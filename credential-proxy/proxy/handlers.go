package proxy

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/elazarl/goproxy"
	temporalclient "go.temporal.io/sdk/client"

	"github.com/dayvidpham/nix-openclaw-vm/credential-proxy/workflows"
)

// requestState is stored in ctx.UserData to pass data from OnRequest to OnResponse.
// It is set only on the success path (when credentials were injected).
type requestState struct {
	scrubMap   map[string]string // realValue → placeholder
	workflowID string            // used to signal "response_complete"
	runID      string
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

	// Extract JWT from Proxy-Authorization header and store it for handleRequest.
	// An empty token is allowed here — handleRequest enforces the presence check.
	// storeConnToken also arms a TTL timer that evicts the entry if the client
	// disconnects before any request arrives (preventing connTokens leaks).
	gw.storeConnToken(ctx.Req.RemoteAddr, extractBearerToken(ctx.Req.Header.Get("Proxy-Authorization")))

	return goproxy.MitmConnect, host
}

// handleRequest is the OnRequest handler. It:
//  1. Retrieves the JWT (from connTokens for CONNECT-tunneled requests, or
//     from Proxy-Authorization for plain HTTP proxy requests).
//  2. Validates the JWT inline via the Verifier — unauthenticated requests are
//     rejected immediately without starting a Temporal workflow.
//  3. Extracts placeholder strings from the request.
//  4. If placeholders are found: registers a RequestContext in the registry,
//     starts a ProxyRequestWorkflow, and blocks on the decision channel until
//     FetchAndInject (or SendDecision on error paths) sends the outcome.
//  5. On an "allowed" decision, the request was already modified in-place by
//     FetchAndInject. Stores the scrub map and workflow IDs in ctx.UserData.
//
// Authorization and vault access are performed inside Temporal activities.
// Raw tokens never appear in Temporal event history — only the public-safe
// IdentityClaims extracted from the verified JWT are passed to the workflow.
func (gw *Gateway) handleRequest(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	// Retrieve JWT: check connTokens first (CONNECT tunnel), then Proxy-Authorization.
	rawToken := gw.resolveToken(req)
	if rawToken == "" {
		return req, errorResponse(req, http.StatusProxyAuthRequired, "missing authentication token")
	}

	// Validate the JWT inline before starting any Temporal workflow.
	// Rejecting unauthenticated requests here avoids wasting workflow slots and
	// ensures raw tokens never flow into Temporal event history.
	identity, err := gw.verifier.VerifyToken(req.Context(), rawToken)
	if err != nil {
		slog.Warn("JWT validation failed", "error", err)
		return req, errorResponse(req, http.StatusProxyAuthRequired, "authentication failed: "+err.Error())
	}

	// Strip Proxy-Authorization so it is not forwarded upstream.
	req.Header.Del("Proxy-Authorization")

	// Disable compression on outbound requests so that response scrubbing can
	// match credential strings in plaintext (hm3: handle compressed responses).
	req.Header.Set("Accept-Encoding", "identity")

	// Extract placeholders from request headers and body.
	placeholders, err := Extract(req)
	if err != nil {
		slog.Error("placeholder extraction failed", "error", err)
		return req, errorResponse(req, http.StatusBadRequest, "failed to read request body")
	}

	// No credentials needed — pass through without a Temporal workflow.
	if len(placeholders) == 0 {
		return req, nil
	}

	// Register a RequestContext in the in-process registry so that the
	// FetchAndInject local activity can look up the live *http.Request.
	requestID := generateRequestID()
	decisionCh := make(chan *workflows.WorkflowDecision, 1)
	reqCtx := &workflows.RequestContext{
		Request:  req,
		ScrubMap: make(map[string]string),
		DecisionCh: decisionCh,
		// ReplaceFunc is a closure over ReplaceInRequest (proxy package) to
		// avoid a circular import between the proxy and workflows packages.
		ReplaceFunc: func(replacements map[string]string) error {
			return ReplaceInRequest(req, replacements)
		},
	}
	gw.registry.Store(requestID, reqCtx)
	defer gw.registry.Delete(requestID)

	// Start the ProxyRequestWorkflow. The workflow stays alive past this handler
	// until goproxy signals "response_complete" in OnResponse.
	targetDomain := stripPort(req.Host)
	run, err := gw.temporal.ExecuteWorkflow(context.Background(), temporalclient.StartWorkflowOptions{
		ID:        fmt.Sprintf("proxy-%s-%s", targetDomain, requestID),
		TaskQueue: gw.cfg.Temporal.TaskQueue,
	}, workflows.ProxyRequestWorkflow, workflows.ProxyInput{
		RequestID: requestID,
		Claims: workflows.IdentityClaims{
			Subject:   identity.Subject,
			Roles:     identity.Roles,
			Groups:    identity.Groups,
			RawClaims: identity.RawClaims,
		},
		Placeholders: placeholders,
		TargetDomain: targetDomain,
	})
	if err != nil {
		slog.Error("failed to start Temporal workflow", "error", err, "request_id", requestID)
		return req, errorResponse(req, http.StatusInternalServerError, "failed to start credential workflow")
	}

	// Block until FetchAndInject (or SendDecision on error paths) sends a
	// decision. A 35-second timeout provides belt-and-suspenders safety in case
	// the workflow fails to send (FetchAndInject has a 30-second activity timeout).
	var decision *workflows.WorkflowDecision
	select {
	case decision = <-decisionCh:
	case <-time.After(35 * time.Second):
		slog.Error("timed out waiting for credential decision", "request_id", requestID, "domain", targetDomain)
		return req, errorResponse(req, http.StatusGatewayTimeout, "credential resolution timed out")
	}

	if decision.Status != workflows.DecisionAllowed {
		slog.Warn("credential workflow denied request", "reason", decision.Reason.String(), "domain", targetDomain)
		return req, errorResponse(req, decision.HTTPStatus, decision.Reason.String())
	}

	// Request was modified in-place by FetchAndInject; ScrubMap is populated.
	// Store state for the OnResponse handler.
	slog.Info("request approved, credentials injected", "domain", targetDomain,
		"credential_count", len(placeholders), "request_id", requestID)
	ctx.UserData = &requestState{
		scrubMap:   reqCtx.ScrubMap,
		workflowID: run.GetID(),
		runID:      run.GetRunID(),
	}
	return req, nil
}

// handleResponse is the OnResponse handler. It:
//  1. Cleans up the JWT token stored in connTokens during CONNECT.
//  2. If credentials were injected (requestState is set): scrubs real credential
//     values from the response body, then signals the Temporal workflow with
//     "response_complete" to complete the audit trail.
func (gw *Gateway) handleResponse(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
	// Clean up the JWT token stored during CONNECT. deleteConnToken also stops
	// the TTL timer that was armed by storeConnToken, preventing a double-delete.
	if ctx.Req != nil {
		gw.deleteConnToken(ctx.Req.RemoteAddr)
	}

	if resp == nil {
		return resp
	}

	state, ok := ctx.UserData.(*requestState)
	if !ok || state == nil {
		return resp
	}

	// Scrub real credential values from the response body.
	scrubCount := 0
	if len(state.scrubMap) > 0 {
		if err := ScrubCredentials(resp, state.scrubMap); err != nil {
			slog.Error("credential scrubbing failed", "error", err)
		} else {
			scrubCount = len(state.scrubMap)
		}
	}

	// Signal the workflow that the response is complete. This is best-effort —
	// a failure to signal leaves the workflow to time out on its 60-second timer.
	if state.workflowID != "" {
		meta := workflows.ResponseCompleteMeta{
			StatusCode: resp.StatusCode,
			ScrubCount: scrubCount,
			Bytes:      resp.ContentLength,
		}
		if err := gw.temporal.SignalWorkflow(context.Background(), state.workflowID, state.runID, string(workflows.SignalResponseComplete), meta); err != nil {
			slog.Warn("failed to signal workflow response_complete",
				"workflow_id", state.workflowID, "error", err)
		}
	}

	return resp
}

// resolveToken retrieves the JWT for a request. It checks the connection token
// cache first (for CONNECT-tunneled requests), then falls back to the
// Proxy-Authorization header on the request itself (for plain HTTP proxying).
func (gw *Gateway) resolveToken(req *http.Request) string {
	if token, ok := gw.loadConnToken(req.RemoteAddr); ok {
		return token
	}
	return extractBearerToken(req.Header.Get("Proxy-Authorization"))
}

// generateRequestID returns a unique request ID as a 16-byte hex string.
func generateRequestID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// Fallback to timestamp-based ID if crypto/rand fails.
		return fmt.Sprintf("req-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
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
