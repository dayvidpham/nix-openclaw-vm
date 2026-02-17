package authn

import (
	"errors"
	"fmt"
	"testing"
)

// Compile-time check: OIDCVerifier satisfies Verifier.
var _ Verifier = (*OIDCVerifier)(nil)

func TestClassifyVerifyError_TokenExpired(t *testing.T) {
	original := fmt.Errorf("oidc: token is expired (Token Expiry: ...)")
	err := classifyVerifyError(original)
	if !errors.Is(err, ErrTokenExpired) {
		t.Errorf("expected ErrTokenExpired, got: %v", err)
	}
}

func TestClassifyVerifyError_InvalidIssuer(t *testing.T) {
	original := fmt.Errorf("oidc: id token issuer does not match")
	err := classifyVerifyError(original)
	if !errors.Is(err, ErrInvalidIssuer) {
		t.Errorf("expected ErrInvalidIssuer, got: %v", err)
	}
}

func TestClassifyVerifyError_InvalidAudience(t *testing.T) {
	original := fmt.Errorf("oidc: expected audience \"credproxy\" got [\"other\"]")
	err := classifyVerifyError(original)
	if !errors.Is(err, ErrInvalidAudience) {
		t.Errorf("expected ErrInvalidAudience, got: %v", err)
	}
}

func TestClassifyVerifyError_Unknown(t *testing.T) {
	original := fmt.Errorf("some unknown error")
	err := classifyVerifyError(original)
	if errors.Is(err, ErrTokenExpired) || errors.Is(err, ErrInvalidIssuer) || errors.Is(err, ErrInvalidAudience) {
		t.Errorf("expected generic error, got sentinel: %v", err)
	}
	if err == nil {
		t.Fatal("expected non-nil error")
	}
}

func TestExtractRealmRoles(t *testing.T) {
	tests := []struct {
		name   string
		claims map[string]interface{}
		want   []string
	}{
		{
			name: "keycloak roles present",
			claims: map[string]interface{}{
				"realm_access": map[string]interface{}{
					"roles": []interface{}{"credential-consumer", "audit-reader"},
				},
			},
			want: []string{"credential-consumer", "audit-reader"},
		},
		{
			name:   "missing realm_access",
			claims: map[string]interface{}{},
			want:   nil,
		},
		{
			name: "realm_access wrong type",
			claims: map[string]interface{}{
				"realm_access": "not-a-map",
			},
			want: nil,
		},
		{
			name: "realm_access missing roles key",
			claims: map[string]interface{}{
				"realm_access": map[string]interface{}{
					"other": "value",
				},
			},
			want: nil,
		},
		{
			name: "roles contains non-string values",
			claims: map[string]interface{}{
				"realm_access": map[string]interface{}{
					"roles": []interface{}{"valid-role", 42, "another-role"},
				},
			},
			want: []string{"valid-role", "another-role"},
		},
		{
			name: "empty roles array",
			claims: map[string]interface{}{
				"realm_access": map[string]interface{}{
					"roles": []interface{}{},
				},
			},
			want: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractRealmRoles(tt.claims)
			if tt.want == nil {
				if got != nil {
					t.Errorf("got %v, want nil", got)
				}
				return
			}
			if len(got) != len(tt.want) {
				t.Fatalf("len = %d, want %d; got %v", len(got), len(tt.want), got)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestExtractStringSlice(t *testing.T) {
	tests := []struct {
		name   string
		claims map[string]interface{}
		key    string
		want   []string
	}{
		{
			name: "groups present",
			claims: map[string]interface{}{
				"groups": []interface{}{"/agents/trusted", "/agents/all"},
			},
			key:  "groups",
			want: []string{"/agents/trusted", "/agents/all"},
		},
		{
			name:   "key missing",
			claims: map[string]interface{}{},
			key:    "groups",
			want:   nil,
		},
		{
			name: "wrong value type",
			claims: map[string]interface{}{
				"groups": "not-a-slice",
			},
			key:  "groups",
			want: nil,
		},
		{
			name: "mixed types filtered",
			claims: map[string]interface{}{
				"items": []interface{}{"a", 123, true, "b"},
			},
			key:  "items",
			want: []string{"a", "b"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractStringSlice(tt.claims, tt.key)
			if tt.want == nil {
				if got != nil {
					t.Errorf("got %v, want nil", got)
				}
				return
			}
			if len(got) != len(tt.want) {
				t.Fatalf("len = %d, want %d; got %v", len(got), len(tt.want), got)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}
