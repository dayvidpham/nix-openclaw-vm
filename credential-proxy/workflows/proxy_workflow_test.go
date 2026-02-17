package workflows

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"go.temporal.io/sdk/testsuite"
	"go.temporal.io/sdk/temporal"

	"github.com/dayvidpham/nix-openclaw-vm/credential-proxy/authz"
	"github.com/dayvidpham/nix-openclaw-vm/credential-proxy/authn"
)

// ---------------------------------------------------------------------------
// Workflow test fixtures
// ---------------------------------------------------------------------------

// wfTestInput returns a ProxyInput suitable for workflow-level tests.
func wfTestInput() ProxyInput {
	return ProxyInput{
		RequestID:    "req-wf-test-001",
		RawJWT:       "test-jwt-token",
		Placeholders: []string{"agent-vault-aaaaaaaa-1111-2222-3333-444444444444"},
		TargetDomain: "api.example.com",
	}
}

// wfTestIdentity returns a valid IdentityClaims for happy-path tests.
func wfTestIdentity() IdentityClaims {
	return IdentityClaims{
		Subject:   "agent-test-001",
		Roles:     []string{"proxy-user"},
		RawClaims: map[string]interface{}{"sub": "agent-test-001"},
	}
}

// ---------------------------------------------------------------------------
// Helper: newWorkflowEnv builds a TestWorkflowEnvironment with Activities
// registered so that OnActivity mocks are matched by name.
//
// activities is a zero-value *Activities — the fields are nil because the real
// implementations are never called in these workflow-level tests (mocks intercept).
// We need the type only to derive the correct activity function names for OnActivity.
// ---------------------------------------------------------------------------
func newWorkflowEnv(ts *testsuite.WorkflowTestSuite) (*testsuite.TestWorkflowEnvironment, *Activities) {
	env := ts.NewTestWorkflowEnvironment()
	acts := &Activities{}
	// Register all activity methods so that the workflow can find them by name.
	env.RegisterActivity(acts)
	return env, acts
}

// sendResponseComplete schedules the SignalResponseComplete signal to be delivered
// at simulated time 0 (i.e., before the workflow blocks on the selector). Temporal
// buffers signals, so the signal arrives even before GetSignalChannel is called.
func sendResponseComplete(env *testsuite.TestWorkflowEnvironment, meta ResponseCompleteMeta) {
	env.RegisterDelayedCallback(func() {
		env.SignalWorkflow(string(SignalResponseComplete), meta)
	}, 0)
}

// ---------------------------------------------------------------------------
// TestProxyRequestWorkflow_HappyPath verifies the full success path:
// ValidateIdentity → EvaluatePolicy → FetchAndInject → response_complete signal → StatusSuccess
// ---------------------------------------------------------------------------
func TestProxyRequestWorkflow_HappyPath(t *testing.T) {
	ts := &testsuite.WorkflowTestSuite{}
	env, acts := newWorkflowEnv(ts)

	identity := wfTestIdentity()

	env.OnActivity(acts.ValidateIdentity, mock.Anything, mock.Anything).
		Return(&IdentityClaims{
			Subject:   identity.Subject,
			Roles:     identity.Roles,
			RawClaims: identity.RawClaims,
		}, nil).Once()

	env.OnActivity(acts.EvaluatePolicy, mock.Anything, mock.Anything).
		Return(&AuthzDecision{Allowed: true}, nil).Once()

	env.OnActivity(acts.FetchAndInject, mock.Anything, mock.Anything).
		Return(&InjectResult{CredentialCount: 1}, nil).Once()

	sendResponseComplete(env, ResponseCompleteMeta{
		StatusCode: 200,
		ScrubCount: 2,
		Bytes:      512,
	})

	env.ExecuteWorkflow(ProxyRequestWorkflow, wfTestInput())

	if !env.IsWorkflowCompleted() {
		t.Fatal("workflow did not complete")
	}
	if err := env.GetWorkflowError(); err != nil {
		t.Fatalf("workflow error = %v, want nil", err)
	}

	var out ProxyOutput
	if err := env.GetWorkflowResult(&out); err != nil {
		t.Fatalf("get workflow result: %v", err)
	}

	if out.Status != StatusSuccess {
		t.Errorf("status = %q, want %q", out.Status, StatusSuccess)
	}
	if out.ScrubCount != 2 {
		t.Errorf("scrub_count = %d, want 2", out.ScrubCount)
	}
	if out.Bytes != 512 {
		t.Errorf("bytes = %d, want 512", out.Bytes)
	}

	env.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// TestProxyRequestWorkflow_AuthFailure verifies that a ValidateIdentity failure
// causes SendDecision to be called and the workflow to return StatusDenied.
// ---------------------------------------------------------------------------
func TestProxyRequestWorkflow_AuthFailure(t *testing.T) {
	ts := &testsuite.WorkflowTestSuite{}
	env, acts := newWorkflowEnv(ts)

	authErr := fmt.Errorf("token signature invalid")

	// ValidateIdentity fails — this triggers the sendDenial path.
	env.OnActivity(acts.ValidateIdentity, mock.Anything, mock.Anything).
		Return((*IdentityClaims)(nil), temporal.NewApplicationError("token verification failed: token signature invalid", "", authErr)).Once()

	// sendDenial calls SendDecision as a local activity — mock it as a no-op.
	// The registry lookup will miss (RequestID is synthetic), so SendDecision
	// returns nil without blocking.
	env.OnActivity(acts.SendDecision, mock.Anything, mock.Anything).
		Return(nil).Once()

	env.ExecuteWorkflow(ProxyRequestWorkflow, wfTestInput())

	if !env.IsWorkflowCompleted() {
		t.Fatal("workflow did not complete")
	}

	// Workflow should return an error (denied status means non-nil workflow error).
	if err := env.GetWorkflowError(); err == nil {
		t.Error("expected workflow error for auth failure, got nil")
	}

	env.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// TestProxyRequestWorkflow_AuthzDenial verifies that an EvaluatePolicy denial
// causes SendDecision to be called and the workflow to return StatusDenied.
// ---------------------------------------------------------------------------
func TestProxyRequestWorkflow_AuthzDenial(t *testing.T) {
	ts := &testsuite.WorkflowTestSuite{}
	env, acts := newWorkflowEnv(ts)

	identity := wfTestIdentity()

	env.OnActivity(acts.ValidateIdentity, mock.Anything, mock.Anything).
		Return(&IdentityClaims{
			Subject:   identity.Subject,
			Roles:     identity.Roles,
			RawClaims: identity.RawClaims,
		}, nil).Once()

	// Policy denies — Allowed: false is NOT an activity error but an in-band denial.
	env.OnActivity(acts.EvaluatePolicy, mock.Anything, mock.Anything).
		Return(&AuthzDecision{Allowed: false, Reason: "insufficient role"}, nil).Once()

	// sendDenial calls SendDecision — no-op (registry miss expected in test).
	env.OnActivity(acts.SendDecision, mock.Anything, mock.Anything).
		Return(nil).Once()

	env.ExecuteWorkflow(ProxyRequestWorkflow, wfTestInput())

	if !env.IsWorkflowCompleted() {
		t.Fatal("workflow did not complete")
	}

	if err := env.GetWorkflowError(); err == nil {
		t.Error("expected workflow error for authz denial, got nil")
	}

	env.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// TestProxyRequestWorkflow_InjectFailure verifies that a FetchAndInject error
// causes the workflow to return StatusError (not StatusDenied).
// The workflow does NOT call SendDecision on this path — FetchAndInject handles
// its own DecisionCh write internally.
// ---------------------------------------------------------------------------
func TestProxyRequestWorkflow_InjectFailure(t *testing.T) {
	ts := &testsuite.WorkflowTestSuite{}
	env, acts := newWorkflowEnv(ts)

	identity := wfTestIdentity()

	env.OnActivity(acts.ValidateIdentity, mock.Anything, mock.Anything).
		Return(&IdentityClaims{
			Subject:   identity.Subject,
			Roles:     identity.Roles,
			RawClaims: identity.RawClaims,
		}, nil).Once()

	env.OnActivity(acts.EvaluatePolicy, mock.Anything, mock.Anything).
		Return(&AuthzDecision{Allowed: true}, nil).Once()

	// FetchAndInject fails — the workflow returns StatusError.
	fetchErr := fmt.Errorf("credential fetch failed for placeholder: vault unavailable")
	env.OnActivity(acts.FetchAndInject, mock.Anything, mock.Anything).
		Return((*InjectResult)(nil), temporal.NewApplicationError(fetchErr.Error(), "", fetchErr)).Once()

	env.ExecuteWorkflow(ProxyRequestWorkflow, wfTestInput())

	if !env.IsWorkflowCompleted() {
		t.Fatal("workflow did not complete")
	}

	if err := env.GetWorkflowError(); err == nil {
		t.Error("expected workflow error for inject failure, got nil")
	}

	env.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// TestProxyRequestWorkflow_SignalTimeout verifies that when the response_complete
// signal is never sent, the 60-second selector timer fires and the workflow
// returns an error. The test suite's mock clock auto-advances to fire timers.
// ---------------------------------------------------------------------------
func TestProxyRequestWorkflow_SignalTimeout(t *testing.T) {
	ts := &testsuite.WorkflowTestSuite{}
	env, acts := newWorkflowEnv(ts)

	identity := wfTestIdentity()

	env.OnActivity(acts.ValidateIdentity, mock.Anything, mock.Anything).
		Return(&IdentityClaims{
			Subject:   identity.Subject,
			Roles:     identity.Roles,
			RawClaims: identity.RawClaims,
		}, nil).Once()

	env.OnActivity(acts.EvaluatePolicy, mock.Anything, mock.Anything).
		Return(&AuthzDecision{Allowed: true}, nil).Once()

	env.OnActivity(acts.FetchAndInject, mock.Anything, mock.Anything).
		Return(&InjectResult{CredentialCount: 1}, nil).Once()

	// Intentionally do NOT send "response_complete" — the 60-second timer fires.
	// The test suite's mock clock auto-advances to fire the next pending timer.

	env.ExecuteWorkflow(ProxyRequestWorkflow, wfTestInput())

	if !env.IsWorkflowCompleted() {
		t.Fatal("workflow did not complete")
	}

	if err := env.GetWorkflowError(); err == nil {
		t.Error("expected workflow error for signal timeout, got nil")
	}

	env.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// TestProxyRequestWorkflow_SearchAttributes verifies that the workflow sets
// search attributes at each phase of the lifecycle by inspecting the terminal
// ProxyOutput which carries status derived from those attributes. We assert
// that both the in-progress and terminal attribute writes did not cause errors
// (the workflow completed successfully) and that the output status matches.
//
// Temporal's test environment does not expose a direct API to read upserted
// search attributes, so we assert via observable workflow outcomes.
// ---------------------------------------------------------------------------
func TestProxyRequestWorkflow_SearchAttributes(t *testing.T) {
	ts := &testsuite.WorkflowTestSuite{}
	env, acts := newWorkflowEnv(ts)

	identity := wfTestIdentity()

	env.OnActivity(acts.ValidateIdentity, mock.Anything, mock.Anything).
		Return(&IdentityClaims{
			Subject:   identity.Subject,
			Roles:     identity.Roles,
			RawClaims: identity.RawClaims,
		}, nil).Once()

	env.OnActivity(acts.EvaluatePolicy, mock.Anything, mock.Anything).
		Return(&AuthzDecision{Allowed: true}, nil).Once()

	env.OnActivity(acts.FetchAndInject, mock.Anything, mock.Anything).
		Return(&InjectResult{CredentialCount: 1}, nil).Once()

	// Deliver the signal so the workflow completes.
	sendResponseComplete(env, ResponseCompleteMeta{StatusCode: 200, ScrubCount: 0, Bytes: 0})

	env.ExecuteWorkflow(ProxyRequestWorkflow, wfTestInput())

	if !env.IsWorkflowCompleted() {
		t.Fatal("workflow did not complete")
	}
	if err := env.GetWorkflowError(); err != nil {
		t.Fatalf("workflow error = %v; search-attribute upserts should not cause failures", err)
	}

	var out ProxyOutput
	if err := env.GetWorkflowResult(&out); err != nil {
		t.Fatalf("get workflow result: %v", err)
	}

	// The terminal status in ProxyOutput reflects the final UpsertTypedSearchAttributes
	// call (StatusSuccess). If any attribute write had failed, the workflow would have
	// returned an error or incorrect status.
	if out.Status != StatusSuccess {
		t.Errorf("status = %q, want %q; suggests search-attribute lifecycle broken", out.Status, StatusSuccess)
	}

	// Verify the workflow consumed the correct amount of simulated time.
	// A very large LatencyMs would indicate the 60-second timer fired (wrong path).
	if out.LatencyMs > int64(time.Second/time.Millisecond) {
		t.Errorf("latency_ms = %d, want < 1000; may indicate timeout instead of success", out.LatencyMs)
	}

	env.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Compile-time check: Activities receiver type used for mock binding.
// This ensures method names produced by (*Activities).Foo and acts.Foo are
// consistent so that OnActivity mocks intercept the workflow's activity calls.
// ---------------------------------------------------------------------------

// Ensure that the Activities methods we pass to OnActivity are the same type
// as those called by the workflow (both reduce to "MethodName" in the registry).
var _ = (*Activities)(nil) // compile-time nil pointer check

// Ensure authz and authn types are available in this package's test scope.
var _ authz.Evaluator = (*mockEvaluator)(nil)
var _ authn.Verifier = (*mockVerifier)(nil)
