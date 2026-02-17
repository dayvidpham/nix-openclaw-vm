package workflows

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.temporal.io/sdk/testsuite"

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
	acts := &Activities{}

	testSuite := &testsuite.WorkflowTestSuite{}
	env := testSuite.NewTestActivityEnvironment()
	env.RegisterActivity(acts.ValidateAndResolve)

	result, err := env.ExecuteActivity(acts.ValidateAndResolve, ValidateAndResolveInput{
		AgentID:           "agent-1",
		TargetDomain:      "api.anthropic.com",
		PlaceholderHashes: []string{"hash-aaa", "hash-bbb"},
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
	// Current stub maps hash→hash; verify both exist.
	for _, hash := range []string{"hash-aaa", "hash-bbb"} {
		if _, ok := output.CredentialPaths[hash]; !ok {
			t.Errorf("expected credential path for %s", hash)
		}
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
