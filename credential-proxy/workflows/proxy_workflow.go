package workflows

import (
	"fmt"
	"strings"
	"time"

	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"

	"github.com/dayvidpham/nix-openclaw-vm/credential-proxy/audit"
)

// ProxyStatus represents the terminal state of a proxy workflow execution.
type ProxyStatus int

const (
	StatusInProgress ProxyStatus = iota
	StatusSuccess
	StatusDenied
	StatusError
	StatusTimeout
)

// String returns the human-readable form of a ProxyStatus.
// Used for Temporal search attribute serialization.
func (s ProxyStatus) String() string {
	switch s {
	case StatusInProgress:
		return "in_progress"
	case StatusSuccess:
		return "success"
	case StatusDenied:
		return "denied"
	case StatusError:
		return "error"
	case StatusTimeout:
		return "timeout"
	default:
		return "unknown"
	}
}

// ProxyInput is the serializable input to ProxyRequestWorkflow.
// It intentionally contains only metadata — never real secret values.
// The raw JWT is included because ValidateIdentity needs it for JWKS verification.
type ProxyInput struct {
	RequestID    string   `json:"request_id"`
	RawJWT       string   `json:"raw_jwt"`
	Placeholders []string `json:"placeholders"`
	TargetDomain string   `json:"target_domain"`
}

// ResponseCompleteMeta is the payload of the SignalResponseComplete signal sent
// by the goproxy OnResponse handler after scrubbing the upstream response.
type ResponseCompleteMeta struct {
	StatusCode int   `json:"status_code"`
	ScrubCount int   `json:"scrub_count"`
	Bytes      int64 `json:"bytes"`
}

// ProxyOutput is the workflow result recorded in Temporal history.
type ProxyOutput struct {
	Status     ProxyStatus `json:"status"`
	LatencyMs  int64       `json:"latency_ms"`
	ScrubCount int         `json:"scrub_count"`
	Bytes      int64       `json:"bytes"`
}

// ProxyRequestWorkflow orchestrates a single proxied request as a full lifecycle:
//
//  1. ValidateIdentity — verifies the JWT against Keycloak JWKS (regular activity,
//     benefits from Temporal retry on transient JWKS network errors).
//  2. EvaluatePolicy — runs the OPA authorization policy in-process (local activity,
//     no network needed).
//  3. FetchAndInject — fetches credentials from OpenBao, replaces placeholder strings
//     in the *http.Request in-place via RequestRegistry, and unblocks the goproxy
//     handler (local activity — secrets never enter Temporal event history).
//  4. Waits for a SignalResponseComplete signal from goproxy after the upstream
//     response is scrubbed, completing the audit trail.
//
// Secret values NEVER appear in Temporal event history. FetchAndInject is a local
// activity that accesses *http.Request via the in-process RequestRegistry.
func ProxyRequestWorkflow(ctx workflow.Context, input ProxyInput) (*ProxyOutput, error) {
	start := workflow.Now(ctx)

	// Set initial search attributes for observability.
	credRefs := strings.Join(input.Placeholders, ",")
	sa := audit.NewSearchAttributes("", input.TargetDomain, credRefs, StatusInProgress.String())
	if err := workflow.UpsertTypedSearchAttributes(ctx, sa.ToSearchAttributeUpdates()...); err != nil {
		return nil, err
	}

	// sendDenial unblocks goproxy with a denied decision on the error paths
	// of ValidateIdentity and EvaluatePolicy.
	localDenyCtx := workflow.WithLocalActivityOptions(ctx, workflow.LocalActivityOptions{
		StartToCloseTimeout: 5 * time.Second,
		RetryPolicy:         &temporal.RetryPolicy{MaximumAttempts: 1},
	})
	sendDenial := func(reason DenialReason) {
		_ = workflow.ExecuteLocalActivity(localDenyCtx, (*Activities).SendDecision, SendDecisionInput{
			RequestID: input.RequestID,
			Status:    DecisionDenied,
			Reason:    reason,
		}).Get(ctx, nil)
	}

	// -------------------------------------------------------------------------
	// Step 1: ValidateIdentity (regular activity — JWKS fetch needs network)
	// -------------------------------------------------------------------------
	validateCtx := workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		StartToCloseTimeout: 10 * time.Second,
		RetryPolicy:         &temporal.RetryPolicy{MaximumAttempts: 2},
	})
	var identity IdentityClaims
	if err := workflow.ExecuteActivity(validateCtx, (*Activities).ValidateIdentity, ValidateIdentityInput{
		RawJWT: input.RawJWT,
	}).Get(ctx, &identity); err != nil {
		sendDenial(ReasonAuthenticationFailed)
		return finalize(ctx, start, StatusDenied, ResponseCompleteMeta{}, err)
	}

	// Update search attributes with agent ID now that we have it.
	sa2 := audit.NewSearchAttributes(identity.Subject, "", "", "")
	_ = workflow.UpsertTypedSearchAttributes(ctx, sa2.ToSearchAttributeUpdates()...)

	// -------------------------------------------------------------------------
	// Step 2: EvaluatePolicy (local activity — OPA runs in-process)
	// -------------------------------------------------------------------------
	evalCtx := workflow.WithLocalActivityOptions(ctx, workflow.LocalActivityOptions{
		StartToCloseTimeout: 5 * time.Second,
		RetryPolicy:         &temporal.RetryPolicy{MaximumAttempts: 1},
	})
	var decision AuthzDecision
	if err := workflow.ExecuteLocalActivity(evalCtx, (*Activities).EvaluatePolicy, EvalPolicyInput{
		Claims:       identity,
		Placeholders: input.Placeholders,
		TargetDomain: input.TargetDomain,
	}).Get(ctx, &decision); err != nil {
		sendDenial(ReasonAuthorizationDenied)
		return finalize(ctx, start, StatusDenied, ResponseCompleteMeta{}, err)
	}
	if !decision.Allowed {
		sendDenial(ReasonAuthorizationDenied)
		return finalize(ctx, start, StatusDenied, ResponseCompleteMeta{}, fmt.Errorf("access denied: %s", decision.Reason))
	}

	// -------------------------------------------------------------------------
	// Step 3: FetchAndInject (local activity — vault fetch + in-place injection)
	//
	// FetchAndInject accesses *http.Request via the in-process RequestRegistry.
	// It ALWAYS sends on DecisionCh before returning (even on error), so goproxy
	// will not deadlock. Retries are disabled: if it fails, goproxy has already
	// been notified via the denied decision, and a retry would find the registry
	// entry cleaned up.
	// -------------------------------------------------------------------------
	fetchCtx := workflow.WithLocalActivityOptions(ctx, workflow.LocalActivityOptions{
		StartToCloseTimeout: 30 * time.Second,
		RetryPolicy:         &temporal.RetryPolicy{MaximumAttempts: 1},
	})
	var injectResult InjectResult
	if err := workflow.ExecuteLocalActivity(fetchCtx, (*Activities).FetchAndInject, FetchInjectInput{
		RequestID:    input.RequestID,
		Placeholders: input.Placeholders,
	}).Get(ctx, &injectResult); err != nil {
		// FetchAndInject already sent a denied decision on DecisionCh.
		return finalize(ctx, start, StatusError, ResponseCompleteMeta{}, err)
	}

	// -------------------------------------------------------------------------
	// Step 4: Wait for SignalResponseComplete from goproxy OnResponse.
	//
	// The workflow stays alive while goproxy forwards the modified request and
	// receives the upstream response. goproxy scrubs the response and signals
	// with outcome metadata, completing the audit trail.
	// -------------------------------------------------------------------------
	var responseMeta ResponseCompleteMeta
	signalCh := workflow.GetSignalChannel(ctx, string(SignalResponseComplete))

	timerCtx, cancelTimer := workflow.WithCancel(ctx)
	timer := workflow.NewTimer(timerCtx, 60*time.Second)

	timedOut := false
	selector := workflow.NewSelector(ctx)
	selector.AddReceive(signalCh, func(ch workflow.ReceiveChannel, _ bool) {
		ch.Receive(ctx, &responseMeta)
	})
	selector.AddFuture(timer, func(f workflow.Future) {
		if f.Get(ctx, nil) == nil {
			timedOut = true
		}
	})
	selector.Select(ctx)
	cancelTimer()

	if timedOut {
		return finalize(ctx, start, StatusError, ResponseCompleteMeta{}, fmt.Errorf("timed out waiting for %s signal", SignalResponseComplete))
	}

	return finalize(ctx, start, StatusSuccess, responseMeta, nil)
}

// finalize upserts the terminal search attribute status and returns the output.
func finalize(ctx workflow.Context, start time.Time, status ProxyStatus, meta ResponseCompleteMeta, workflowErr error) (*ProxyOutput, error) {
	latencyMs := workflow.Now(ctx).Sub(start).Milliseconds()

	// Best-effort status upsert — don't mask the original error.
	sa := audit.SearchAttributes{Status: status.String()}
	_ = workflow.UpsertTypedSearchAttributes(ctx, sa.ToSearchAttributeUpdates()...)

	out := &ProxyOutput{
		Status:     status,
		LatencyMs:  latencyMs,
		ScrubCount: meta.ScrubCount,
		Bytes:      meta.Bytes,
	}
	return out, workflowErr
}
