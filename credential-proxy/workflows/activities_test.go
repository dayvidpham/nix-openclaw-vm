package workflows

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.temporal.io/sdk/testsuite"

	"github.com/dayvidpham/nix-openclaw-vm/credential-proxy/authz"
	"github.com/dayvidpham/nix-openclaw-vm/credential-proxy/config"
	"github.com/dayvidpham/nix-openclaw-vm/credential-proxy/vault"
)

// mockSecretStore implements vault.SecretStore for testing.
type mockSecretStore struct {
	credentials map[string]*vault.CredentialValue
	err         error
}

var _ vault.SecretStore = (*mockSecretStore)(nil)

func (m *mockSecretStore) FetchCredential(_ context.Context, vaultPath string) (*vault.CredentialValue, error) {
	if m.err != nil {
		return nil, m.err
	}
	cred, ok := m.credentials[vaultPath]
	if !ok {
		return nil, fmt.Errorf("%w: %s", vault.ErrSecretNotFound, vaultPath)
	}
	return cred, nil
}

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

func TestFetchAndForward_Success(t *testing.T) {
	// Target server that echoes back the received Authorization header.
	var receivedAuth string
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Length", "2")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer target.Close()

	// Extract host:port from the test server URL (e.g., "127.0.0.1:PORT").
	targetDomain := strings.TrimPrefix(target.URL, "https://")

	store := &mockSecretStore{
		credentials: map[string]*vault.CredentialValue{
			"secret/data/anthropic": {
				Key:          "sk-ant-test-key",
				HeaderName:   "Authorization",
				HeaderPrefix: "Bearer ",
			},
		},
	}

	acts := &Activities{
		Store:      store,
		HTTPClient: target.Client(),
	}

	env := &testsuite.TestActivityEnvironment{}
	testSuite := &testsuite.WorkflowTestSuite{}
	env = testSuite.NewTestActivityEnvironment()
	env.RegisterActivity(acts.FetchAndForward)

	result, err := env.ExecuteActivity(acts.FetchAndForward, FetchAndForwardInput{
		RequestID:    "req-001",
		TargetDomain: targetDomain,
		Method:       "GET",
		Path:         "/v1/messages",
		CredentialPaths: map[string]string{
			"hash-abc": "secret/data/anthropic",
		},
	})
	if err != nil {
		t.Fatalf("FetchAndForward error: %v", err)
	}

	var output FetchAndForwardOutput
	if err := result.Get(&output); err != nil {
		t.Fatalf("decode output: %v", err)
	}

	if output.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", output.StatusCode)
	}
	if output.BytesTransferred != 2 {
		t.Errorf("expected 2 bytes transferred, got %d", output.BytesTransferred)
	}
	if receivedAuth != "Bearer sk-ant-test-key" {
		t.Errorf("expected Authorization header 'Bearer sk-ant-test-key', got %q", receivedAuth)
	}
}

func TestFetchAndForward_VaultError(t *testing.T) {
	store := &mockSecretStore{
		err: fmt.Errorf("vault unavailable"),
	}

	acts := &Activities{
		Store:      store,
		HTTPClient: http.DefaultClient,
	}

	testSuite := &testsuite.WorkflowTestSuite{}
	env := testSuite.NewTestActivityEnvironment()
	env.RegisterActivity(acts.FetchAndForward)

	_, err := env.ExecuteActivity(acts.FetchAndForward, FetchAndForwardInput{
		RequestID:    "req-002",
		TargetDomain: "api.anthropic.com",
		Method:       "POST",
		Path:         "/v1/messages",
		CredentialPaths: map[string]string{
			"hash-xyz": "secret/data/anthropic",
		},
	})
	if err == nil {
		t.Fatal("expected error from vault failure, got nil")
	}
	if !strings.Contains(err.Error(), "vault unavailable") {
		t.Errorf("expected error to mention 'vault unavailable', got: %v", err)
	}
}

func TestValidateAndResolve_Success(t *testing.T) {
	cfg := testConfig(t)
	eval := &mockEvaluator{
		result: &authz.AuthzResult{Allowed: true},
	}

	acts := &Activities{
		Config:    cfg,
		Evaluator: eval,
	}

	testSuite := &testsuite.WorkflowTestSuite{}
	env := testSuite.NewTestActivityEnvironment()
	env.RegisterActivity(acts.ValidateAndResolve)

	result, err := env.ExecuteActivity(acts.ValidateAndResolve, ValidateAndResolveInput{
		AgentID:           "agent-1",
		TargetDomain:      "api.example.com",
		PlaceholderHashes: []string{"agent-vault-aaaaaaaa-1111-2222-3333-444444444444", "agent-vault-bbbbbbbb-1111-2222-3333-444444444444"},
	})
	if err != nil {
		t.Fatalf("ValidateAndResolve error: %v", err)
	}

	var output ValidateAndResolveOutput
	if err := result.Get(&output); err != nil {
		t.Fatalf("decode output: %v", err)
	}

	if len(output.CredentialPaths) != 2 {
		t.Fatalf("expected 2 credential paths, got %d", len(output.CredentialPaths))
	}
	if output.CredentialPaths["agent-vault-aaaaaaaa-1111-2222-3333-444444444444"] != "secret/data/cred-a" {
		t.Errorf("expected agent-vault-aaaaaaaa-1111-2222-3333-444444444444 → secret/data/cred-a, got %q", output.CredentialPaths["agent-vault-aaaaaaaa-1111-2222-3333-444444444444"])
	}
	if output.CredentialPaths["agent-vault-bbbbbbbb-1111-2222-3333-444444444444"] != "secret/data/cred-b" {
		t.Errorf("expected agent-vault-bbbbbbbb-1111-2222-3333-444444444444 → secret/data/cred-b, got %q", output.CredentialPaths["agent-vault-bbbbbbbb-1111-2222-3333-444444444444"])
	}
}

func TestValidateAndResolve_EmptyInput(t *testing.T) {
	acts := &Activities{}

	testSuite := &testsuite.WorkflowTestSuite{}
	env := testSuite.NewTestActivityEnvironment()
	env.RegisterActivity(acts.ValidateAndResolve)

	result, err := env.ExecuteActivity(acts.ValidateAndResolve, ValidateAndResolveInput{
		AgentID:           "agent-1",
		TargetDomain:      "example.com",
		PlaceholderHashes: []string{},
	})
	if err != nil {
		t.Fatalf("ValidateAndResolve error: %v", err)
	}

	var output ValidateAndResolveOutput
	if err := result.Get(&output); err != nil {
		t.Fatalf("decode output: %v", err)
	}

	if len(output.CredentialPaths) != 0 {
		t.Errorf("expected 0 credential paths for empty input, got %d", len(output.CredentialPaths))
	}
}

func TestValidateAndResolve_PolicyDenied(t *testing.T) {
	cfg := testConfig(t)
	eval := &mockEvaluator{
		result: &authz.AuthzResult{Allowed: false, Reason: "agent not authorized for this domain"},
	}

	acts := &Activities{
		Config:    cfg,
		Evaluator: eval,
	}

	testSuite := &testsuite.WorkflowTestSuite{}
	env := testSuite.NewTestActivityEnvironment()
	env.RegisterActivity(acts.ValidateAndResolve)

	_, err := env.ExecuteActivity(acts.ValidateAndResolve, ValidateAndResolveInput{
		AgentID:           "agent-1",
		TargetDomain:      "api.example.com",
		PlaceholderHashes: []string{"agent-vault-aaaaaaaa-1111-2222-3333-444444444444"},
	})
	if err == nil {
		t.Fatal("expected error from policy denial, got nil")
	}
	if !strings.Contains(err.Error(), "access denied") {
		t.Errorf("expected error to mention 'access denied', got: %v", err)
	}
	if !strings.Contains(err.Error(), "agent not authorized") {
		t.Errorf("expected error to mention deny reason, got: %v", err)
	}
}

func TestValidateAndResolve_UnknownPlaceholder(t *testing.T) {
	cfg := testConfig(t)
	eval := &mockEvaluator{
		result: &authz.AuthzResult{Allowed: true},
	}

	acts := &Activities{
		Config:    cfg,
		Evaluator: eval,
	}

	testSuite := &testsuite.WorkflowTestSuite{}
	env := testSuite.NewTestActivityEnvironment()
	env.RegisterActivity(acts.ValidateAndResolve)

	_, err := env.ExecuteActivity(acts.ValidateAndResolve, ValidateAndResolveInput{
		AgentID:           "agent-1",
		TargetDomain:      "api.example.com",
		PlaceholderHashes: []string{"hash-nonexistent"},
	})
	if err == nil {
		t.Fatal("expected error for unknown placeholder, got nil")
	}
	if !strings.Contains(err.Error(), "unknown placeholder") {
		t.Errorf("expected error to mention 'unknown placeholder', got: %v", err)
	}
}
