// Package testutil provides shared mock types and fixtures for unit and
// integration tests across the credential-proxy packages.
//
// Only interfaces from packages that do not import proxy or workflows are
// placed here to avoid circular imports. The mockRegistry type (which
// implements workflows.ContextRegistry) lives in workflows/activities_test.go.
package testutil

import (
	"context"
	"fmt"

	"github.com/dayvidpham/nix-openclaw-vm/credential-proxy/authz"
	"github.com/dayvidpham/nix-openclaw-vm/credential-proxy/authn"
	"github.com/dayvidpham/nix-openclaw-vm/credential-proxy/vault"
)

// ---------------------------------------------------------------------------
// Shared test constants
// ---------------------------------------------------------------------------

const (
	// TestJWT is the bearer token used in proxy-level gateway tests.
	TestJWT = "test-jwt-token"

	// TestSubject is the agent identity subject used in workflow-level tests.
	TestSubject = "agent-test-001"

	// TestPlaceholder is a placeholder token present in the test config.
	TestPlaceholder = "agent-vault-deadbeef-1234-5678-9abc-def012345678"

	// TestVaultPath is the vault path associated with TestPlaceholder.
	TestVaultPath = "secret/data/openclaw/credentials/anthropic"

	// TestRealSecret is the credential value returned for TestVaultPath.
	TestRealSecret = "sk-ant-real-secret-key-12345"
)

// ---------------------------------------------------------------------------
// MockVerifier — implements authn.Verifier
// ---------------------------------------------------------------------------

// MockVerifier is a configurable stub for authn.Verifier. Set Identity to
// return a successful result; set Err to return an error.
type MockVerifier struct {
	Identity *authn.AgentIdentity
	Err      error
}

var _ authn.Verifier = (*MockVerifier)(nil)

func (m *MockVerifier) VerifyToken(_ context.Context, _ string) (*authn.AgentIdentity, error) {
	if m.Err != nil {
		return nil, m.Err
	}
	return m.Identity, nil
}

// DefaultVerifier returns a MockVerifier that succeeds with a basic agent identity.
func DefaultVerifier() *MockVerifier {
	return &MockVerifier{
		Identity: &authn.AgentIdentity{
			Subject:   TestSubject,
			Roles:     []string{"proxy-user"},
			RawClaims: map[string]interface{}{"sub": TestSubject},
		},
	}
}

// ---------------------------------------------------------------------------
// MockEvaluator — implements authz.Evaluator
// ---------------------------------------------------------------------------

// MockEvaluator is a configurable stub for authz.Evaluator. Set Result to
// return a successful evaluation; set Err to simulate an OPA error.
type MockEvaluator struct {
	Result *authz.AuthzResult
	Err    error
}

var _ authz.Evaluator = (*MockEvaluator)(nil)

func (m *MockEvaluator) Evaluate(_ context.Context, _ *authz.AuthzRequest) (*authz.AuthzResult, error) {
	if m.Err != nil {
		return nil, m.Err
	}
	return m.Result, nil
}

// AllowEvaluator returns a MockEvaluator that always grants access.
func AllowEvaluator() *MockEvaluator {
	return &MockEvaluator{Result: &authz.AuthzResult{Allowed: true}}
}

// DenyEvaluator returns a MockEvaluator that always denies with the given reason.
func DenyEvaluator(reason string) *MockEvaluator {
	return &MockEvaluator{Result: &authz.AuthzResult{Allowed: false, Reason: reason}}
}

// ---------------------------------------------------------------------------
// MockStore — implements vault.SecretStore
// ---------------------------------------------------------------------------

// MockStore is a configurable stub for vault.SecretStore backed by a simple
// map from vault path → CredentialValue.
type MockStore struct {
	Credentials map[string]*vault.CredentialValue
	Err         error
}

var _ vault.SecretStore = (*MockStore)(nil)

func (m *MockStore) FetchCredential(_ context.Context, vaultPath string) (*vault.CredentialValue, error) {
	if m.Err != nil {
		return nil, m.Err
	}
	cred, ok := m.Credentials[vaultPath]
	if !ok {
		return nil, fmt.Errorf("%w: %s", vault.ErrSecretNotFound, vaultPath)
	}
	return cred, nil
}

// DefaultStore returns a MockStore pre-loaded with the TestVaultPath credential.
func DefaultStore() *MockStore {
	return &MockStore{
		Credentials: map[string]*vault.CredentialValue{
			TestVaultPath: {
				Key:          TestRealSecret,
				HeaderName:   "x-api-key",
				HeaderPrefix: "",
			},
		},
	}
}
