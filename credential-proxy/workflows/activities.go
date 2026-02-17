package workflows

import (
	"context"
	"fmt"
	"net/http"

	"github.com/dayvidpham/nix-openclaw-vm/credential-proxy/authz"
	"github.com/dayvidpham/nix-openclaw-vm/credential-proxy/authn"
	"github.com/dayvidpham/nix-openclaw-vm/credential-proxy/config"
	"github.com/dayvidpham/nix-openclaw-vm/credential-proxy/vault"
)

// ---------------------------------------------------------------------------
// DecisionStatus — typed enum for the outcome of a credential workflow.
// ---------------------------------------------------------------------------

// DecisionStatus represents the terminal decision of a proxy access attempt.
type DecisionStatus int

const (
	DecisionAllowed DecisionStatus = iota
	DecisionDenied
	DecisionError
)

// String returns the human-readable form of a DecisionStatus.
func (s DecisionStatus) String() string {
	switch s {
	case DecisionAllowed:
		return "allowed"
	case DecisionDenied:
		return "denied"
	case DecisionError:
		return "error"
	default:
		return "unknown"
	}
}

// ---------------------------------------------------------------------------
// DenialReason — typed enum for why a credential request was denied.
// ---------------------------------------------------------------------------

// DenialReason identifies the specific cause of a credential workflow denial.
type DenialReason int

const (
	ReasonNone                    DenialReason = iota
	ReasonAuthenticationFailed                 // JWT validation failed
	ReasonAuthorizationDenied                  // OPA policy denied access
	ReasonCredentialInjectionFailed            // vault fetch or placeholder injection failed
	ReasonTimeout                              // credential resolution timed out
)

// String returns a human-readable description of the denial reason.
// This value is used directly in HTTP error response bodies.
func (r DenialReason) String() string {
	switch r {
	case ReasonAuthenticationFailed:
		return "authentication failed"
	case ReasonAuthorizationDenied:
		return "authorization denied"
	case ReasonCredentialInjectionFailed:
		return "credential injection failed"
	case ReasonTimeout:
		return "timeout"
	default:
		return "internal error"
	}
}

// HTTPStatusCode returns the appropriate HTTP status code for this denial reason.
// Used by the goproxy handler to return the correct status rather than always 403.
func (r DenialReason) HTTPStatusCode() int {
	switch r {
	case ReasonAuthenticationFailed:
		return http.StatusProxyAuthRequired // 407
	case ReasonAuthorizationDenied:
		return http.StatusForbidden // 403
	case ReasonCredentialInjectionFailed:
		return http.StatusBadGateway // 502
	case ReasonTimeout:
		return http.StatusGatewayTimeout // 504
	default:
		return http.StatusInternalServerError // 500
	}
}

// ---------------------------------------------------------------------------
// SignalName — typed signal name constants for Temporal signal channels.
// ---------------------------------------------------------------------------

// SignalName is the type for Temporal workflow signal names.
type SignalName string

const (
	// SignalResponseComplete is sent by goproxy OnResponse after scrubbing the
	// upstream response, completing the audit trail.
	SignalResponseComplete SignalName = "response_complete"
)

// ---------------------------------------------------------------------------
// WorkflowDecision — in-process channel payload bridging Temporal and goproxy.
// ---------------------------------------------------------------------------

// WorkflowDecision is sent on RequestContext.DecisionCh by FetchAndInject (or
// SendDecision on the error path) to unblock the goproxy handler goroutine.
type WorkflowDecision struct {
	Status     DecisionStatus
	Reason     DenialReason
	HTTPStatus int // Cached from Reason.HTTPStatusCode(); 0 for DecisionAllowed.
}

// RequestContext holds the live *http.Request and the in-process channels that
// bridge goproxy and Temporal local activities. It is stored in the
// RequestRegistry for the lifetime of the OnRequest handler goroutine.
//
// Secret values live here only — they never enter Temporal event history.
type RequestContext struct {
	// Request is the live *http.Request owned by goproxy. FetchAndInject
	// modifies it in-place via ReplaceFunc.
	Request *http.Request

	// ScrubMap maps real credential values → placeholder strings.
	// Populated by FetchAndInject; read by the OnResponse handler for scrubbing.
	ScrubMap map[string]string

	// DecisionCh is buffered (cap=1). FetchAndInject or SendDecision sends
	// exactly one value to unblock the OnRequest handler goroutine.
	DecisionCh chan *WorkflowDecision

	// ReplaceFunc is called by FetchAndInject to substitute placeholder strings
	// in the *http.Request. It is set by the OnRequest handler as a closure
	// over proxy.ReplaceInRequest, avoiding a circular import between workflows
	// and proxy packages.
	ReplaceFunc func(replacements map[string]string) error
}

// ContextRegistry is the interface through which Temporal local activities look
// up a live RequestContext by request ID. The concrete implementation lives in
// the proxy package (proxy.RequestRegistry) to avoid circular imports.
type ContextRegistry interface {
	Load(requestID string) (*RequestContext, bool)
}

// ---------------------------------------------------------------------------
// Activities struct — shared dependencies for all activity methods.
// ---------------------------------------------------------------------------

// Activities holds the shared dependencies injected into Temporal activity methods.
type Activities struct {
	Store     vault.SecretStore
	Config    *config.Config
	Evaluator authz.Evaluator
	Verifier  authn.Verifier
	Registry  ContextRegistry
}

// ---------------------------------------------------------------------------
// ValidateIdentity — regular activity (JWKS fetch needs network + retry)
// ---------------------------------------------------------------------------

// ValidateIdentityInput is the serializable input for ValidateIdentity.
// Only the raw JWT is passed; no secrets appear in Temporal event history.
type ValidateIdentityInput struct {
	RawJWT string `json:"raw_jwt"`
}

// IdentityClaims is the output of ValidateIdentity. It contains only public
// metadata extracted from the JWT — safe to appear in Temporal event history.
type IdentityClaims struct {
	Subject   string                 `json:"subject"`
	Roles     []string               `json:"roles"`
	Groups    []string               `json:"groups"`
	RawClaims map[string]interface{} `json:"raw_claims"`
}

// ValidateIdentity verifies the raw JWT against the Keycloak JWKS endpoint and
// extracts agent identity claims. It is a regular (non-local) Temporal activity
// so that JWKS network calls benefit from Temporal's retry policy.
func (a *Activities) ValidateIdentity(ctx context.Context, input ValidateIdentityInput) (*IdentityClaims, error) {
	identity, err := a.Verifier.VerifyToken(ctx, input.RawJWT)
	if err != nil {
		return nil, fmt.Errorf("token verification failed: %w", err)
	}
	return &IdentityClaims{
		Subject:   identity.Subject,
		Roles:     identity.Roles,
		Groups:    identity.Groups,
		RawClaims: identity.RawClaims,
	}, nil
}

// ---------------------------------------------------------------------------
// EvaluatePolicy — local activity (OPA is in-process, no network needed)
// ---------------------------------------------------------------------------

// EvalPolicyInput is the serializable input for EvaluatePolicy.
type EvalPolicyInput struct {
	Claims       IdentityClaims `json:"claims"`
	Placeholders []string       `json:"placeholders"`
	TargetDomain string         `json:"target_domain"`
}

// AuthzDecision is the output of EvaluatePolicy.
type AuthzDecision struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason"`
}

// EvaluatePolicy resolves credential bindings from config and evaluates the
// OPA authorization policy. It is a local activity — OPA runs in-process with
// no network I/O, so it does not need Temporal's distributed retry machinery.
func (a *Activities) EvaluatePolicy(ctx context.Context, input EvalPolicyInput) (*AuthzDecision, error) {
	bindings := make([]authz.CredentialBinding, 0, len(input.Placeholders))
	for _, ph := range input.Placeholders {
		cred := a.Config.LookupCredential(ph)
		if cred == nil {
			return &AuthzDecision{Allowed: false, Reason: fmt.Sprintf("unknown credential placeholder: %s", ph)}, nil
		}
		bindings = append(bindings, authz.CredentialBinding{
			Placeholder: ph,
			BoundDomain: cred.BoundDomain,
			VaultPath:   cred.VaultPath,
		})
	}

	result, err := a.Evaluator.Evaluate(ctx, &authz.AuthzRequest{
		Identity:     input.Claims.RawClaims,
		Placeholders: input.Placeholders,
		TargetDomain: input.TargetDomain,
		Credentials:  bindings,
	})
	if err != nil {
		return nil, fmt.Errorf("OPA policy evaluation: %w", err)
	}
	return &AuthzDecision{Allowed: result.Allowed, Reason: result.Reason}, nil
}

// ---------------------------------------------------------------------------
// FetchAndInject — local activity (vault fetch + in-place request modification)
// ---------------------------------------------------------------------------

// FetchInjectInput is the serializable input for FetchAndInject.
// Secret values are NEVER included — only the request ID and placeholder tokens
// that identify which credentials to fetch.
type FetchInjectInput struct {
	RequestID    string   `json:"request_id"`
	Placeholders []string `json:"placeholders"`
}

// InjectResult is the safe output of FetchAndInject. Credential values are
// held only in process memory during the activity and are never serialized.
type InjectResult struct {
	CredentialCount int `json:"credential_count"`
}

// deny is a helper that sends a typed denial on the decision channel and
// returns nil, allowing FetchAndInject to return an error with a single statement.
func deny(ch chan *WorkflowDecision, reason DenialReason) {
	ch <- &WorkflowDecision{
		Status:     DecisionDenied,
		Reason:     reason,
		HTTPStatus: reason.HTTPStatusCode(),
	}
}

// FetchAndInject is the core sealed local activity:
//  1. Looks up the live *http.Request via the RequestRegistry.
//  2. Resolves vault paths from config.
//  3. Fetches real credentials from OpenBao (network call, in-process).
//  4. Replaces placeholder strings in the *http.Request in-place.
//  5. Populates RequestContext.ScrubMap for the OnResponse handler.
//  6. Sends an "allowed" decision on RequestContext.DecisionCh to unblock goproxy.
//
// Secrets exist only in this activity's local memory. They never appear in
// Temporal event history, activity inputs, or activity outputs.
//
// IMPORTANT: This activity MUST send on DecisionCh before returning, even on
// error. Otherwise the OnRequest goproxy goroutine will block until timeout.
func (a *Activities) FetchAndInject(ctx context.Context, input FetchInjectInput) (*InjectResult, error) {
	reqCtx, ok := a.Registry.Load(input.RequestID)
	if !ok {
		// Registry entry gone (e.g., goproxy timed out already). Nothing to do.
		return nil, fmt.Errorf("FetchAndInject: request %s not found in registry", input.RequestID)
	}

	// Resolve vault paths from config. Unknown placeholders → deny immediately.
	type credMeta struct {
		vaultPath    string
		headerName   string
		headerPrefix string
	}
	metas := make(map[string]credMeta, len(input.Placeholders))
	for _, ph := range input.Placeholders {
		cred := a.Config.LookupCredential(ph)
		if cred == nil {
			reason := fmt.Sprintf("unknown credential placeholder: %s", ph)
			deny(reqCtx.DecisionCh, ReasonCredentialInjectionFailed)
			return nil, fmt.Errorf("%s", reason)
		}
		metas[ph] = credMeta{
			vaultPath:    cred.VaultPath,
			headerName:   cred.HeaderName,
			headerPrefix: cred.HeaderPrefix,
		}
	}

	// Fetch credentials from vault. Keep secrets in local memory only.
	replacements := make(map[string]string, len(metas))
	for ph, meta := range metas {
		credVal, err := a.Store.FetchCredential(ctx, meta.vaultPath)
		if err != nil {
			deny(reqCtx.DecisionCh, ReasonCredentialInjectionFailed)
			return nil, fmt.Errorf("credential fetch failed for placeholder %s: %v", ph, err)
		}

		realValue := credVal.HeaderPrefix + credVal.Key
		replacements[ph] = realValue

		// Build scrub map: realValue → placeholder (populated for OnResponse handler).
		reqCtx.ScrubMap[realValue] = ph
		// Also scrub the raw key if a prefix is used, in case the upstream
		// API echoes back just the key without the prefix.
		if credVal.HeaderPrefix != "" {
			reqCtx.ScrubMap[credVal.Key] = ph
		}
	}

	// Replace placeholder strings in the *http.Request in-place.
	if err := reqCtx.ReplaceFunc(replacements); err != nil {
		deny(reqCtx.DecisionCh, ReasonCredentialInjectionFailed)
		return nil, fmt.Errorf("credential injection failed: %v", err)
	}

	// Unblock the goproxy OnRequest goroutine — request is ready to forward.
	reqCtx.DecisionCh <- &WorkflowDecision{Status: DecisionAllowed}
	return &InjectResult{CredentialCount: len(metas)}, nil
}

// ---------------------------------------------------------------------------
// SendDecision — local activity (denial signaling on auth/authz failure paths)
// ---------------------------------------------------------------------------

// SendDecisionInput is the serializable input for SendDecision.
type SendDecisionInput struct {
	RequestID string         `json:"request_id"`
	Status    DecisionStatus `json:"status"`
	Reason    DenialReason   `json:"reason"`
}

// SendDecision is a small local activity used exclusively on the error paths of
// ValidateIdentity and EvaluatePolicy to unblock the goproxy handler goroutine
// with a denial decision. It is separate from FetchAndInject so that the deny
// path does not attempt vault access.
//
// If the registry entry is not found (goproxy already timed out), this returns
// nil — the denial is a no-op since goproxy has already moved on.
func (a *Activities) SendDecision(_ context.Context, input SendDecisionInput) error {
	reqCtx, ok := a.Registry.Load(input.RequestID)
	if !ok {
		// Goproxy timed out before we could send the denial. No-op.
		return nil
	}
	reqCtx.DecisionCh <- &WorkflowDecision{
		Status:     input.Status,
		Reason:     input.Reason,
		HTTPStatus: input.Reason.HTTPStatusCode(),
	}
	return nil
}
