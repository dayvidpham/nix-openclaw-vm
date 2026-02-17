package workflows

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"go.temporal.io/sdk/testsuite"

	"github.com/dayvidpham/nix-openclaw-vm/credential-proxy/authz"
	"github.com/dayvidpham/nix-openclaw-vm/credential-proxy/config"
	"github.com/dayvidpham/nix-openclaw-vm/credential-proxy/internal/testutil"
	"github.com/dayvidpham/nix-openclaw-vm/credential-proxy/vault"
)

// ---------------------------------------------------------------------------
// Mock types whose interfaces live in this package (cannot be in testutil
// without creating a circular import).
// ---------------------------------------------------------------------------

// mockEvaluator implements authz.Evaluator for testing.
type mockEvaluator struct {
	result *authz.AuthzResult
	err    error
}

var _ authz.Evaluator = (*mockEvaluator)(nil)

func (m *mockEvaluator) Evaluate(_ context.Context, _ *authz.AuthzRequest) (*authz.AuthzResult, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.result, nil
}

// mockRegistry implements ContextRegistry for testing.
// Cannot be in testutil because ContextRegistry is defined in this package.
type mockRegistry struct {
	entries map[string]*RequestContext
}

var _ ContextRegistry = (*mockRegistry)(nil)

func (r *mockRegistry) Load(id string) (*RequestContext, bool) {
	ctx, ok := r.entries[id]
	return ctx, ok
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

// testConfig returns a parsed config with two credential entries for testing.
func testConfig(t *testing.T) *config.Config {
	t.Helper()
	yaml := `
oidc:
  issuer_url: "http://localhost:8080/realms/test"
  audience: "test"
vault:
  address: "http://localhost:8200"
credentials:
  - placeholder: "agent-vault-aaaaaaaa-1111-2222-3333-444444444444"
    type: "bearer"
    vault_path: "secret/data/cred-a"
    bound_domain: "api.example.com"
    header_name: "Authorization"
    header_prefix: "Bearer "
  - placeholder: "agent-vault-bbbbbbbb-1111-2222-3333-444444444444"
    type: "api_key"
    vault_path: "secret/data/cred-b"
    bound_domain: "api.example.com"
    header_name: "x-api-key"
`
	cfg, err := config.Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("parse test config: %v", err)
	}
	return cfg
}

// defaultStore returns a MockStore pre-loaded with the two test credentials.
func defaultStore() *testutil.MockStore {
	return &testutil.MockStore{
		Credentials: map[string]*vault.CredentialValue{
			"secret/data/cred-a": {
				Key:          "token-a",
				HeaderName:   "Authorization",
				HeaderPrefix: "Bearer ",
			},
			"secret/data/cred-b": {
				Key:        "key-b",
				HeaderName: "x-api-key",
			},
		},
	}
}

// ---------------------------------------------------------------------------
// EvaluatePolicy tests
// ---------------------------------------------------------------------------

func TestEvaluatePolicy_Allowed(t *testing.T) {
	cfg := testConfig(t)
	acts := &Activities{
		Config:    cfg,
		Evaluator: &mockEvaluator{result: &authz.AuthzResult{Allowed: true}},
	}

	ts := &testsuite.WorkflowTestSuite{}
	env := ts.NewTestActivityEnvironment()
	env.RegisterActivity(acts.EvaluatePolicy)

	result, err := env.ExecuteActivity(acts.EvaluatePolicy, EvalPolicyInput{
		Claims: IdentityClaims{
			Subject:   "agent-001",
			RawClaims: map[string]interface{}{"sub": "agent-001"},
		},
		Placeholders: []string{"agent-vault-aaaaaaaa-1111-2222-3333-444444444444"},
		TargetDomain: "api.example.com",
	})
	if err != nil {
		t.Fatalf("EvaluatePolicy error: %v", err)
	}

	var decision AuthzDecision
	if err := result.Get(&decision); err != nil {
		t.Fatalf("decode decision: %v", err)
	}

	if !decision.Allowed {
		t.Errorf("expected allowed=true, got false (reason: %s)", decision.Reason)
	}
}

func TestEvaluatePolicy_Denied(t *testing.T) {
	cfg := testConfig(t)
	acts := &Activities{
		Config:    cfg,
		Evaluator: &mockEvaluator{result: &authz.AuthzResult{Allowed: false, Reason: "insufficient role"}},
	}

	ts := &testsuite.WorkflowTestSuite{}
	env := ts.NewTestActivityEnvironment()
	env.RegisterActivity(acts.EvaluatePolicy)

	result, err := env.ExecuteActivity(acts.EvaluatePolicy, EvalPolicyInput{
		Claims:       IdentityClaims{RawClaims: map[string]interface{}{}},
		Placeholders: []string{"agent-vault-aaaaaaaa-1111-2222-3333-444444444444"},
		TargetDomain: "api.example.com",
	})
	if err != nil {
		t.Fatalf("EvaluatePolicy error: %v", err)
	}

	var decision AuthzDecision
	if err := result.Get(&decision); err != nil {
		t.Fatalf("decode decision: %v", err)
	}

	if decision.Allowed {
		t.Error("expected allowed=false, got true")
	}
	if decision.Reason != "insufficient role" {
		t.Errorf("reason = %q, want %q", decision.Reason, "insufficient role")
	}
}

func TestEvaluatePolicy_UnknownPlaceholder(t *testing.T) {
	cfg := testConfig(t)
	acts := &Activities{
		Config:    cfg,
		Evaluator: &mockEvaluator{result: &authz.AuthzResult{Allowed: true}},
	}

	ts := &testsuite.WorkflowTestSuite{}
	env := ts.NewTestActivityEnvironment()
	env.RegisterActivity(acts.EvaluatePolicy)

	result, err := env.ExecuteActivity(acts.EvaluatePolicy, EvalPolicyInput{
		Claims:       IdentityClaims{},
		Placeholders: []string{"agent-vault-zzzzzzzz-0000-0000-0000-000000000000"},
		TargetDomain: "api.example.com",
	})
	if err != nil {
		t.Fatalf("EvaluatePolicy error: %v", err)
	}

	var decision AuthzDecision
	if err := result.Get(&decision); err != nil {
		t.Fatalf("decode decision: %v", err)
	}

	// Unknown placeholders are treated as denied.
	if decision.Allowed {
		t.Error("expected allowed=false for unknown placeholder, got true")
	}
	if !strings.Contains(decision.Reason, "unknown credential placeholder") {
		t.Errorf("reason = %q, want to contain 'unknown credential placeholder'", decision.Reason)
	}
}

// ---------------------------------------------------------------------------
// FetchAndInject tests
// ---------------------------------------------------------------------------

func TestFetchAndInject_Success(t *testing.T) {
	cfg := testConfig(t)
	store := defaultStore()

	// Build a real *http.Request to test in-place modification.
	req, err := http.NewRequest("GET", "https://api.example.com/v1/resource", nil)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	req.Header.Set("Authorization", "agent-vault-aaaaaaaa-1111-2222-3333-444444444444")

	decisionCh := make(chan *WorkflowDecision, 1)
	reqCtx := &RequestContext{
		Request:  req,
		ScrubMap: make(map[string]string),
		DecisionCh: decisionCh,
		ReplaceFunc: func(replacements map[string]string) error {
			for _, v := range req.Header {
				for i, h := range v {
					if rep, ok := replacements[h]; ok {
						v[i] = rep
					}
				}
			}
			return nil
		},
	}

	reg := &mockRegistry{entries: map[string]*RequestContext{"req-001": reqCtx}}
	acts := &Activities{
		Store:    store,
		Config:   cfg,
		Registry: reg,
	}

	ts := &testsuite.WorkflowTestSuite{}
	env := ts.NewTestActivityEnvironment()
	env.RegisterActivity(acts.FetchAndInject)

	result, err := env.ExecuteActivity(acts.FetchAndInject, FetchInjectInput{
		RequestID:    "req-001",
		Placeholders: []string{"agent-vault-aaaaaaaa-1111-2222-3333-444444444444"},
	})
	if err != nil {
		t.Fatalf("FetchAndInject error: %v", err)
	}

	var injectResult InjectResult
	if err := result.Get(&injectResult); err != nil {
		t.Fatalf("decode result: %v", err)
	}

	if injectResult.CredentialCount != 1 {
		t.Errorf("credential_count = %d, want 1", injectResult.CredentialCount)
	}

	// Decision channel should have received "allowed".
	select {
	case decision := <-decisionCh:
		if decision.Status != DecisionAllowed {
			t.Errorf("decision.Status = %q, want %q", decision.Status, DecisionAllowed)
		}
	default:
		t.Error("expected decision on DecisionCh, got none")
	}

	// ScrubMap should contain realValue → placeholder.
	expectedReal := "Bearer token-a"
	if ph, ok := reqCtx.ScrubMap[expectedReal]; !ok || ph != "agent-vault-aaaaaaaa-1111-2222-3333-444444444444" {
		t.Errorf("ScrubMap[%q] = %q; want placeholder", expectedReal, ph)
	}
}

func TestFetchAndInject_VaultError(t *testing.T) {
	cfg := testConfig(t)
	store := &testutil.MockStore{Err: fmt.Errorf("vault unavailable")}

	req, _ := http.NewRequest("GET", "https://api.example.com/", nil)
	decisionCh := make(chan *WorkflowDecision, 1)
	reqCtx := &RequestContext{
		Request:     req,
		ScrubMap:    make(map[string]string),
		DecisionCh:  decisionCh,
		ReplaceFunc: func(_ map[string]string) error { return nil },
	}

	reg := &mockRegistry{entries: map[string]*RequestContext{"req-002": reqCtx}}
	acts := &Activities{
		Store:    store,
		Config:   cfg,
		Registry: reg,
	}

	ts := &testsuite.WorkflowTestSuite{}
	env := ts.NewTestActivityEnvironment()
	env.RegisterActivity(acts.FetchAndInject)

	_, err := env.ExecuteActivity(acts.FetchAndInject, FetchInjectInput{
		RequestID:    "req-002",
		Placeholders: []string{"agent-vault-aaaaaaaa-1111-2222-3333-444444444444"},
	})
	if err == nil {
		t.Fatal("expected error from vault failure, got nil")
	}

	// Even on error, DecisionCh should have a denied decision (so goproxy unblocks).
	select {
	case decision := <-decisionCh:
		if decision.Status != DecisionDenied {
			t.Errorf("decision.Status = %q, want %q", decision.Status, DecisionDenied)
		}
	default:
		t.Error("expected denied decision on DecisionCh after vault error, got none")
	}
}

func TestFetchAndInject_RegistryMiss(t *testing.T) {
	cfg := testConfig(t)
	reg := &mockRegistry{entries: map[string]*RequestContext{}} // empty
	acts := &Activities{Config: cfg, Registry: reg}

	ts := &testsuite.WorkflowTestSuite{}
	env := ts.NewTestActivityEnvironment()
	env.RegisterActivity(acts.FetchAndInject)

	_, err := env.ExecuteActivity(acts.FetchAndInject, FetchInjectInput{
		RequestID:    "gone-already",
		Placeholders: []string{"agent-vault-aaaaaaaa-1111-2222-3333-444444444444"},
	})
	if err == nil {
		t.Fatal("expected error for missing registry entry, got nil")
	}
	if !strings.Contains(err.Error(), "not found in registry") {
		t.Errorf("error = %v, want to contain 'not found in registry'", err)
	}
}

// ---------------------------------------------------------------------------
// SendDecision tests
// ---------------------------------------------------------------------------

func TestSendDecision_Denied(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://api.example.com/", nil)
	decisionCh := make(chan *WorkflowDecision, 1)
	reqCtx := &RequestContext{
		Request:     req,
		ScrubMap:    make(map[string]string),
		DecisionCh:  decisionCh,
		ReplaceFunc: func(_ map[string]string) error { return nil },
	}

	reg := &mockRegistry{entries: map[string]*RequestContext{"req-deny": reqCtx}}
	acts := &Activities{Registry: reg}

	ts := &testsuite.WorkflowTestSuite{}
	env := ts.NewTestActivityEnvironment()
	env.RegisterActivity(acts.SendDecision)

	_, err := env.ExecuteActivity(acts.SendDecision, SendDecisionInput{
		RequestID: "req-deny",
		Status:    DecisionDenied,
		Reason:    ReasonAuthorizationDenied,
	})
	if err != nil {
		t.Fatalf("SendDecision error: %v", err)
	}

	select {
	case decision := <-decisionCh:
		if decision.Status != DecisionDenied {
			t.Errorf("decision.Status = %v, want %v", decision.Status, DecisionDenied)
		}
		if decision.Reason != ReasonAuthorizationDenied {
			t.Errorf("decision.Reason = %v, want %v", decision.Reason, ReasonAuthorizationDenied)
		}
		if decision.HTTPStatus != ReasonAuthorizationDenied.HTTPStatusCode() {
			t.Errorf("decision.HTTPStatus = %d, want %d", decision.HTTPStatus, ReasonAuthorizationDenied.HTTPStatusCode())
		}
	default:
		t.Error("expected decision on DecisionCh, got none")
	}
}

func TestSendDecision_RegistryMiss(t *testing.T) {
	reg := &mockRegistry{entries: map[string]*RequestContext{}}
	acts := &Activities{Registry: reg}

	ts := &testsuite.WorkflowTestSuite{}
	env := ts.NewTestActivityEnvironment()
	env.RegisterActivity(acts.SendDecision)

	// Should return nil (no-op) when registry entry is gone.
	_, err := env.ExecuteActivity(acts.SendDecision, SendDecisionInput{
		RequestID: "already-gone",
		Status:    DecisionDenied,
		Reason:    ReasonAuthorizationDenied,
	})
	if err != nil {
		t.Errorf("SendDecision with missing registry entry should return nil, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// FetchAndInject — unknown placeholder branch (cred == nil)
// ---------------------------------------------------------------------------

// testConfigNoCredentials returns a parsed config with no credential entries.
// Used to exercise the "unknown credential placeholder" denial path in FetchAndInject.
func testConfigNoCredentials(t *testing.T) *config.Config {
	t.Helper()
	yaml := `
oidc:
  issuer_url: "http://localhost:8080/realms/test"
  audience: "test"
vault:
  address: "http://localhost:8200"
`
	cfg, err := config.Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("parse empty-credentials config: %v", err)
	}
	return cfg
}

// TestFetchAndInject_UnknownPlaceholder verifies that when a placeholder is not
// registered in the config, FetchAndInject:
//   - returns an error containing "unknown credential placeholder"
//   - sends a denied decision (ReasonCredentialInjectionFailed) on DecisionCh
//     so that the goproxy handler goroutine is not left blocked.
func TestFetchAndInject_UnknownPlaceholder(t *testing.T) {
	cfg := testConfigNoCredentials(t)

	req, _ := http.NewRequest("GET", "https://api.example.com/", nil)
	decisionCh := make(chan *WorkflowDecision, 1)
	reqCtx := &RequestContext{
		Request:     req,
		ScrubMap:    make(map[string]string),
		DecisionCh:  decisionCh,
		ReplaceFunc: func(_ map[string]string) error { return nil },
	}

	unknownPlaceholder := "agent-vault-zzzzzzzz-0000-0000-0000-000000000000"
	reg := &mockRegistry{entries: map[string]*RequestContext{"req-unknown-ph": reqCtx}}
	acts := &Activities{
		Config:   cfg,
		Registry: reg,
	}

	ts := &testsuite.WorkflowTestSuite{}
	env := ts.NewTestActivityEnvironment()
	env.RegisterActivity(acts.FetchAndInject)

	_, err := env.ExecuteActivity(acts.FetchAndInject, FetchInjectInput{
		RequestID:    "req-unknown-ph",
		Placeholders: []string{unknownPlaceholder},
	})
	if err == nil {
		t.Fatal("expected error for unknown placeholder, got nil")
	}
	if !strings.Contains(err.Error(), "unknown credential placeholder") {
		t.Errorf("error = %v, want to contain 'unknown credential placeholder'", err)
	}

	// DecisionCh must have received a denied decision so goproxy is unblocked.
	select {
	case decision := <-decisionCh:
		if decision.Status != DecisionDenied {
			t.Errorf("decision.Status = %v, want %v", decision.Status, DecisionDenied)
		}
		if decision.Reason != ReasonCredentialInjectionFailed {
			t.Errorf("decision.Reason = %v, want %v", decision.Reason, ReasonCredentialInjectionFailed)
		}
		if decision.HTTPStatus != ReasonCredentialInjectionFailed.HTTPStatusCode() {
			t.Errorf("decision.HTTPStatus = %d, want %d", decision.HTTPStatus, ReasonCredentialInjectionFailed.HTTPStatusCode())
		}
	default:
		t.Error("expected denied decision on DecisionCh after unknown placeholder, got none")
	}
}
