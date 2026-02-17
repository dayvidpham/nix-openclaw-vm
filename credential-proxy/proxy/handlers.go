package proxy

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/elazarl/goproxy"
	temporalclient "go.temporal.io/sdk/client"

	"github.com/dayvidpham/nix-openclaw-vm/credential-proxy/authz"
	"github.com/dayvidpham/nix-openclaw-vm/credential-proxy/workflows"
)

// requestState is stored in ctx.UserData to pass data from OnRequest to OnResponse.
type requestState struct {
	scrubMap map[string]string // realValue → placeholder
}

// registerHandlers wires up HandleConnect, OnRequest, and OnResponse on the gateway's proxy.
func registerHandlers(gw *Gateway) {
	gw.proxy.OnRequest().HandleConnect(goproxy.FuncHttpsHandler(
		func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
			return gw.handleConnect(host, ctx)
		},
	))

	gw.proxy.OnRequest().DoFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		return gw.handleRequest(req, ctx)
	})

	gw.proxy.OnResponse().DoFunc(func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
		return gw.handleResponse(resp, ctx)
	})
}

// handleConnect validates the CONNECT target domain and extracts the JWT from
// the Proxy-Authorization header. The token is stored in connTokens for
// retrieval by handleRequest (which runs in a separate ProxyCtx).
func (gw *Gateway) handleConnect(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
	domain := stripPort(host)

	// Fail-closed: reject connections to non-allowlisted domains.
	if !gw.cfg.IsAllowedDomain(domain) {
		slog.Warn("CONNECT rejected", "reason", "domain not in allowlist", "domain", domain)
		return goproxy.RejectConnect, host
	}

	// Extract JWT from Proxy-Authorization header.
	rawToken := extractBearerToken(ctx.Req.Header.Get("Proxy-Authorization"))
	if rawToken == "" {
		slog.Warn("CONNECT rejected", "reason", "missing bearer token")
		return goproxy.RejectConnect, host
	}

	// Store token keyed by remote address so handleRequest can retrieve it.
	gw.connTokens.Store(ctx.Req.RemoteAddr, rawToken)

	return goproxy.MitmConnect, host
}

// handleRequest is the OnRequest handler. It verifies the JWT, extracts
// placeholders, evaluates authorization, resolves credentials from vault,
// and replaces placeholders with real values.
func (gw *Gateway) handleRequest(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	bgCtx := req.Context()

	// Retrieve JWT: try connTokens first (CONNECT tunnel), then Proxy-Authorization.
	rawToken := gw.resolveToken(req)
	if rawToken == "" {
		return req, errorResponse(req, http.StatusProxyAuthRequired, "missing authentication token")
	}

	// Strip Proxy-Authorization so it is not forwarded upstream.
	req.Header.Del("Proxy-Authorization")

	// Verify JWT → agent identity.
	identity, err := gw.authn.VerifyToken(bgCtx, rawToken)
	if err != nil {
		slog.Warn("token verification failed", "error", err)
		return req, errorResponse(req, http.StatusForbidden, "token verification failed")
	}

	// Extract placeholders from request.
	placeholders, err := Extract(req)
	if err != nil {
		slog.Error("placeholder extraction failed", "error", err, "subject", identity.Subject)
		return req, errorResponse(req, http.StatusBadRequest, "failed to read request body")
	}

	// No credentials needed — pass through.
	if len(placeholders) == 0 {
		return req, nil
	}

	// Resolve credential bindings from config and build authz input.
	targetDomain := stripPort(req.Host)
	bindings := make([]authz.CredentialBinding, 0, len(placeholders))
	for _, ph := range placeholders {
		cred := gw.cfg.LookupCredential(ph)
		if cred == nil {
			slog.Warn("unknown placeholder", "placeholder", ph, "subject", identity.Subject, "domain", targetDomain)
			return req, errorResponse(req, http.StatusForbidden,
				fmt.Sprintf("unknown credential placeholder: %s", ph))
		}
		bindings = append(bindings, authz.CredentialBinding{
			Placeholder: ph,
			BoundDomain: cred.BoundDomain,
			VaultPath:   cred.VaultPath,
		})
	}

	// Evaluate authorization policy.
	authzResult, err := gw.authz.Evaluate(bgCtx, &authz.AuthzRequest{
		Identity:     identity.RawClaims,
		Placeholders: placeholders,
		TargetDomain: targetDomain,
		Credentials:  bindings,
	})
	if err != nil {
		slog.Error("authz evaluation error", "error", err, "subject", identity.Subject, "domain", targetDomain)
		return req, errorResponse(req, http.StatusInternalServerError, "authorization evaluation failed")
	}
	if !authzResult.Allowed {
		slog.Warn("authz denied", "reason", authzResult.Reason, "subject", identity.Subject,
			"domain", targetDomain, "placeholder_count", len(placeholders))
		return req, errorResponse(req, http.StatusForbidden,
			fmt.Sprintf("access denied: %s", authzResult.Reason))
	}

	// Resolve credentials from vault and build replacement + scrub maps.
	// Reuse bindings from the first loop to avoid duplicate LookupCredential calls.
	replacements := make(map[string]string, len(bindings))
	scrubMap := make(map[string]string, len(bindings))
	for _, b := range bindings {
		credVal, err := gw.vault.FetchCredential(bgCtx, b.VaultPath)
		if err != nil {
			slog.Error("vault fetch failed", "error", err, "subject", identity.Subject, "domain", targetDomain)
			return req, errorResponse(req, http.StatusBadGateway, "credential resolution failed")
		}

		// Compose the full injection value (e.g., "Bearer " + "sk-xxx").
		realValue := credVal.HeaderPrefix + credVal.Key
		replacements[b.Placeholder] = realValue
		scrubMap[realValue] = b.Placeholder
		// Also scrub the raw key if a prefix is used, in case the upstream
		// API echoes back just the key without the prefix.
		if credVal.HeaderPrefix != "" {
			scrubMap[credVal.Key] = b.Placeholder
		}
	}

	// Replace placeholders with real credentials in the request.
	if err := ReplaceInRequest(req, replacements); err != nil {
		slog.Error("credential injection failed", "error", err, "subject", identity.Subject, "domain", targetDomain)
		return req, errorResponse(req, http.StatusInternalServerError, "credential injection failed")
	}

	// Store scrub map for the response handler.
	ctx.UserData = &requestState{scrubMap: scrubMap}

	// Fire async Temporal audit workflow (fire-and-forget).
	// AuditWorkflow only records search attributes — no credential resolution or upstream calls.
	go func() {
		wfID := fmt.Sprintf("credproxy-%s-%d", identity.Subject, time.Now().UnixNano())
		_, err := gw.temporal.ExecuteWorkflow(context.Background(), temporalclient.StartWorkflowOptions{
			ID:        wfID,
			TaskQueue: gw.cfg.Temporal.TaskQueue,
		}, workflows.AuditWorkflow, workflows.ProxyWorkflowInput{
			AgentID:           identity.Subject,
			RequestID:         wfID,
			TargetDomain:      targetDomain,
			Method:            req.Method,
			Path:              req.URL.Path,
			PlaceholderHashes: placeholders,
		})
		if err != nil {
			slog.Error("temporal audit workflow failed", "error", err, "workflow_id", wfID, "agent_id", identity.Subject)
		}
	}()

	slog.Info("request processed", "subject", identity.Subject, "domain", targetDomain,
		"method", req.Method, "path", req.URL.Path, "placeholder_count", len(placeholders))

	return req, nil
}

// handleResponse is the OnResponse handler. It scrubs real credential values
// from the response body, replacing them with placeholders, and cleans up
// the connection token cache to prevent memory leaks.
func (gw *Gateway) handleResponse(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
	// Clean up the JWT token stored during CONNECT to prevent memory leaks.
	if ctx.Req != nil {
		gw.connTokens.Delete(ctx.Req.RemoteAddr)
	}

	if resp == nil {
		return resp
	}

	state, ok := ctx.UserData.(*requestState)
	if !ok || state == nil || len(state.scrubMap) == 0 {
		return resp
	}

	if err := ScrubCredentials(resp, state.scrubMap); err != nil {
		slog.Error("credential scrubbing failed", "error", err)
	}

	return resp
}

// resolveToken retrieves the JWT for a request. It checks the connection token
// cache first (for CONNECT-tunneled requests), then falls back to the
// Proxy-Authorization header on the request itself (for plain HTTP proxying).
func (gw *Gateway) resolveToken(req *http.Request) string {
	if v, ok := gw.connTokens.Load(req.RemoteAddr); ok {
		if token, ok := v.(string); ok && token != "" {
			return token
		}
	}
	return extractBearerToken(req.Header.Get("Proxy-Authorization"))
}

// extractBearerToken extracts the token from a "Bearer <token>" header value.
func extractBearerToken(headerValue string) string {
	const prefix = "Bearer "
	if !strings.HasPrefix(headerValue, prefix) {
		return ""
	}
	return strings.TrimSpace(headerValue[len(prefix):])
}

// stripPort removes the port from a host:port string.
func stripPort(hostport string) string {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		return hostport // already just a hostname
	}
	return host
}

// errorResponse builds an HTTP error response for short-circuiting in OnRequest.
func errorResponse(req *http.Request, code int, msg string) *http.Response {
	return goproxy.NewResponse(req, "text/plain", code, msg)
}
