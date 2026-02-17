package authz

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// policyDir resolves the path to the real rego policies shipped with the package.
func policyDir(t *testing.T) string {
	t.Helper()
	// The test binary runs from the package directory, so policies/ is a sibling.
	dir := filepath.Join("policies")
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("policy dir %s not found: %v", dir, err)
	}
	return dir
}

func newEvaluator(t *testing.T) *OPAEvaluator {
	t.Helper()
	eval, err := NewOPAEvaluator(context.Background(), policyDir(t))
	if err != nil {
		t.Fatalf("NewOPAEvaluator: %v", err)
	}
	return eval
}

// identityWithRoles builds a Keycloak-shaped JWT claims map with roles nested
// under realm_access.roles, matching the actual token structure at runtime.
func identityWithRoles(roles ...string) map[string]interface{} {
	ifaces := make([]interface{}, len(roles))
	for i, r := range roles {
		ifaces[i] = r
	}
	return map[string]interface{}{
		"realm_access": map[string]interface{}{
			"roles": ifaces,
		},
		"sub": "test-agent",
	}
}

func identityNoRoles() map[string]interface{} {
	return map[string]interface{}{
		"realm_access": map[string]interface{}{
			"roles": []interface{}{},
		},
		"sub": "test-agent",
	}
}

func TestAllow_SingleCredentialCorrectDomain(t *testing.T) {
	eval := newEvaluator(t)
	result, err := eval.Evaluate(context.Background(), &AuthzRequest{
		Identity:     identityWithRoles("agent"),
		Placeholders: []string{"agent-vault-00000000-0000-0000-0000-000000000001"},
		TargetDomain: "api.anthropic.com",
		Credentials: []CredentialBinding{
			{Placeholder: "agent-vault-00000000-0000-0000-0000-000000000001", BoundDomain: "api.anthropic.com", VaultPath: "secret/data/anthropic"},
		},
	})
	if err != nil {
		t.Fatalf("Evaluate error: %v", err)
	}
	if !result.Allowed {
		t.Errorf("expected Allowed=true, got false; reason: %s", result.Reason)
	}
}

func TestAllow_NoCredentialsPassthrough(t *testing.T) {
	eval := newEvaluator(t)
	result, err := eval.Evaluate(context.Background(), &AuthzRequest{
		Identity:     identityWithRoles("agent"),
		Placeholders: []string{},
		TargetDomain: "example.com",
		Credentials:  []CredentialBinding{},
	})
	if err != nil {
		t.Fatalf("Evaluate error: %v", err)
	}
	if !result.Allowed {
		t.Errorf("expected Allowed=true for pass-through (no credentials), got false; reason: %s", result.Reason)
	}
}

func TestDeny_NoRoles(t *testing.T) {
	eval := newEvaluator(t)
	result, err := eval.Evaluate(context.Background(), &AuthzRequest{
		Identity:     identityNoRoles(),
		Placeholders: []string{"agent-vault-00000000-0000-0000-0000-000000000001"},
		TargetDomain: "api.anthropic.com",
		Credentials: []CredentialBinding{
			{Placeholder: "agent-vault-00000000-0000-0000-0000-000000000001", BoundDomain: "api.anthropic.com", VaultPath: "secret/data/anthropic"},
		},
	})
	if err != nil {
		t.Fatalf("Evaluate error: %v", err)
	}
	if result.Allowed {
		t.Fatal("expected Allowed=false for identity with no roles")
	}
	if !strings.Contains(result.Reason, "no roles") {
		t.Errorf("expected reason to mention 'no roles', got: %s", result.Reason)
	}
}

func TestDeny_DomainMismatch(t *testing.T) {
	eval := newEvaluator(t)
	result, err := eval.Evaluate(context.Background(), &AuthzRequest{
		Identity:     identityWithRoles("agent"),
		Placeholders: []string{"agent-vault-00000000-0000-0000-0000-000000000001"},
		TargetDomain: "evil.com",
		Credentials: []CredentialBinding{
			{Placeholder: "agent-vault-00000000-0000-0000-0000-000000000001", BoundDomain: "api.anthropic.com", VaultPath: "secret/data/anthropic"},
		},
	})
	if err != nil {
		t.Fatalf("Evaluate error: %v", err)
	}
	if result.Allowed {
		t.Fatal("expected Allowed=false for domain mismatch")
	}
	if !strings.Contains(result.Reason, "agent-vault-00000000-0000-0000-0000-000000000001") {
		t.Errorf("expected reason to mention the credential placeholder, got: %s", result.Reason)
	}
	if !strings.Contains(result.Reason, "evil.com") {
		t.Errorf("expected reason to mention the target domain, got: %s", result.Reason)
	}
}

func TestDeny_MixedCredentials(t *testing.T) {
	eval := newEvaluator(t)
	result, err := eval.Evaluate(context.Background(), &AuthzRequest{
		Identity:     identityWithRoles("agent"),
		Placeholders: []string{"agent-vault-00000000-0000-0000-0000-000000000002", "agent-vault-00000000-0000-0000-0000-000000000003"},
		TargetDomain: "api.anthropic.com",
		Credentials: []CredentialBinding{
			{Placeholder: "agent-vault-00000000-0000-0000-0000-000000000002", BoundDomain: "api.anthropic.com", VaultPath: "secret/data/anthropic"},
			{Placeholder: "agent-vault-00000000-0000-0000-0000-000000000003", BoundDomain: "api.openai.com", VaultPath: "secret/data/openai"},
		},
	})
	if err != nil {
		t.Fatalf("Evaluate error: %v", err)
	}
	if result.Allowed {
		t.Fatal("expected Allowed=false when one credential is mismatched")
	}
	if !strings.Contains(result.Reason, "agent-vault-00000000-0000-0000-0000-000000000003") {
		t.Errorf("expected reason to mention the mismatched credential, got: %s", result.Reason)
	}
}

func TestAllow_MultipleCredentialsAllMatching(t *testing.T) {
	eval := newEvaluator(t)
	result, err := eval.Evaluate(context.Background(), &AuthzRequest{
		Identity:     identityWithRoles("agent", "admin"),
		Placeholders: []string{"agent-vault-00000000-0000-0000-0000-00000000000a", "agent-vault-00000000-0000-0000-0000-00000000000b", "agent-vault-00000000-0000-0000-0000-00000000000c"},
		TargetDomain: "api.anthropic.com",
		Credentials: []CredentialBinding{
			{Placeholder: "agent-vault-00000000-0000-0000-0000-00000000000a", BoundDomain: "api.anthropic.com", VaultPath: "secret/data/a"},
			{Placeholder: "agent-vault-00000000-0000-0000-0000-00000000000b", BoundDomain: "api.anthropic.com", VaultPath: "secret/data/b"},
			{Placeholder: "agent-vault-00000000-0000-0000-0000-00000000000c", BoundDomain: "api.anthropic.com", VaultPath: "secret/data/c"},
		},
	})
	if err != nil {
		t.Fatalf("Evaluate error: %v", err)
	}
	if !result.Allowed {
		t.Errorf("expected Allowed=true for multiple matching credentials, got false; reason: %s", result.Reason)
	}
}

func TestNewOPAEvaluator_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	_, err := NewOPAEvaluator(context.Background(), dir)
	if err == nil {
		t.Fatal("expected error for empty policy dir, got nil")
	}
	if !strings.Contains(err.Error(), "no .rego files") {
		t.Errorf("expected 'no .rego files' error, got: %v", err)
	}
}

func TestNewOPAEvaluator_NonexistentDir(t *testing.T) {
	_, err := NewOPAEvaluator(context.Background(), "/nonexistent/path")
	if err == nil {
		t.Fatal("expected error for nonexistent dir, got nil")
	}
}
