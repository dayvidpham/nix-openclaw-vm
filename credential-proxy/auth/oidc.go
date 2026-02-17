package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"

	gooidc "github.com/coreos/go-oidc/v3/oidc"

	"github.com/dayvidpham/nix-openclaw-vm/credential-proxy/config"
)

// Sentinel errors for token verification failures.
var (
	ErrTokenExpired   = errors.New("token expired")
	ErrInvalidIssuer  = errors.New("invalid issuer")
	ErrInvalidAudience = errors.New("invalid audience")
)

// AgentIdentity represents the authenticated identity extracted from a verified JWT.
type AgentIdentity struct {
	// Subject is the JWT "sub" claim — uniquely identifies the agent.
	Subject string

	// Roles extracted from Keycloak realm_access.roles.
	Roles []string

	// Groups extracted from the JWT "groups" claim.
	Groups []string

	// RawClaims holds the full decoded token claims for downstream use.
	RawClaims map[string]interface{}
}

// Verifier validates a raw JWT string and returns the agent identity on success.
type Verifier interface {
	VerifyToken(ctx context.Context, rawToken string) (*AgentIdentity, error)
}

// OIDCVerifier validates JWTs against a Keycloak OIDC provider using JWKS.
type OIDCVerifier struct {
	verifier *gooidc.IDTokenVerifier
}

// NewOIDCVerifier creates a Verifier that validates tokens against the given OIDC issuer.
// It fetches the provider's JWKS endpoint during construction.
func NewOIDCVerifier(ctx context.Context, cfg config.OIDCConfig) (*OIDCVerifier, error) {
	provider, err := gooidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("discover OIDC provider %s: %w", cfg.IssuerURL, err)
	}

	verifier := provider.Verifier(&gooidc.Config{
		ClientID: cfg.Audience,
	})

	return &OIDCVerifier{verifier: verifier}, nil
}

// VerifyToken validates a raw JWT string, returning the extracted AgentIdentity.
// The rawToken should be the bare JWT (no "Bearer " prefix).
func (v *OIDCVerifier) VerifyToken(ctx context.Context, rawToken string) (*AgentIdentity, error) {
	rawToken = strings.TrimSpace(rawToken)

	idToken, err := v.verifier.Verify(ctx, rawToken)
	if err != nil {
		return nil, classifyVerifyError(err)
	}

	var claims map[string]interface{}
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("decode token claims: %w", err)
	}

	identity := &AgentIdentity{
		Subject:   idToken.Subject,
		Roles:     extractRealmRoles(claims),
		Groups:    extractStringSlice(claims, "groups"),
		RawClaims: claims,
	}

	return identity, nil
}

// classifyVerifyError maps go-oidc verification errors to sentinel errors.
func classifyVerifyError(err error) error {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "token is expired"):
		return fmt.Errorf("%w: %v", ErrTokenExpired, err)
	case strings.Contains(msg, "issuer"):
		return fmt.Errorf("%w: %v", ErrInvalidIssuer, err)
	case strings.Contains(msg, "audience"):
		return fmt.Errorf("%w: %v", ErrInvalidAudience, err)
	default:
		return fmt.Errorf("verify token: %w", err)
	}
}

// extractRealmRoles extracts roles from the Keycloak realm_access.roles claim.
func extractRealmRoles(claims map[string]interface{}) []string {
	realmAccess, ok := claims["realm_access"].(map[string]interface{})
	if !ok {
		return nil
	}
	return extractStringSlice(realmAccess, "roles")
}

// extractStringSlice extracts a []string from a claims map by key.
func extractStringSlice(claims map[string]interface{}, key string) []string {
	raw, ok := claims[key].([]interface{})
	if !ok {
		return nil
	}
	result := make([]string, 0, len(raw))
	for _, v := range raw {
		if s, ok := v.(string); ok {
			result = append(result, s)
		}
	}
	return result
}
