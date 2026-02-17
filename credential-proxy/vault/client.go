package vault

import (
	"context"
	"errors"
	"fmt"

	baoapi "github.com/openbao/openbao/api/v2"

	"github.com/dayvidpham/nix-openclaw-vm/credential-proxy/config"
)

// ErrSecretNotFound indicates the requested secret path does not exist in the vault.
var ErrSecretNotFound = errors.New("secret not found")

// CredentialValue holds the resolved secret data fetched from OpenBao.
type CredentialValue struct {
	// Key is the actual secret value (e.g., "sk-ant-xxx").
	Key string

	// HeaderName is the HTTP header to inject the credential into.
	HeaderName string

	// HeaderPrefix is prepended to the key when injecting (e.g., "Bearer ").
	HeaderPrefix string
}

// SecretStore abstracts credential retrieval for dependency injection.
type SecretStore interface {
	FetchCredential(ctx context.Context, vaultPath string) (*CredentialValue, error)
}

// OpenBaoClient implements SecretStore using the OpenBao KV v2 API.
type OpenBaoClient struct {
	client *baoapi.Client
}

// Compile-time check: OpenBaoClient satisfies SecretStore.
var _ SecretStore = (*OpenBaoClient)(nil)

// NewOpenBaoClient creates a SecretStore backed by an OpenBao server.
func NewOpenBaoClient(cfg config.VaultConfig) (*OpenBaoClient, error) {
	baoCfg := baoapi.DefaultConfig()
	baoCfg.Address = cfg.Address

	client, err := baoapi.NewClient(baoCfg)
	if err != nil {
		return nil, fmt.Errorf("create OpenBao client: %w", err)
	}

	if cfg.Token != "" {
		client.SetToken(cfg.Token)
	}

	return &OpenBaoClient{client: client}, nil
}

// HealthCheck verifies that the OpenBao server is reachable, initialized, and
// unsealed. It is called once at startup to fail fast rather than on the first
// proxied request (r42).
func (c *OpenBaoClient) HealthCheck(ctx context.Context) error {
	health, err := c.client.Sys().HealthWithContext(ctx)
	if err != nil {
		return fmt.Errorf("vault health check: %w", err)
	}
	if !health.Initialized {
		return fmt.Errorf("vault is not initialized")
	}
	if health.Sealed {
		return fmt.Errorf("vault is sealed")
	}
	return nil
}

// FetchCredential reads a KV v2 secret from the given vaultPath and extracts
// the key, header_name, and header_prefix fields.
//
// The vaultPath should be the full KV v2 data path, e.g.
// "secret/data/openclaw/credentials/anthropic".
func (c *OpenBaoClient) FetchCredential(ctx context.Context, vaultPath string) (*CredentialValue, error) {
	secret, err := c.client.Logical().ReadWithContext(ctx, vaultPath)
	if err != nil {
		return nil, fmt.Errorf("read secret %s: %w", vaultPath, err)
	}
	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("%w: %s", ErrSecretNotFound, vaultPath)
	}

	// KV v2 wraps actual data under a "data" key.
	data, ok := secret.Data["data"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("%w: %s (missing data envelope)", ErrSecretNotFound, vaultPath)
	}

	key, _ := data["key"].(string)
	if key == "" {
		return nil, fmt.Errorf("secret %s: missing or empty 'key' field", vaultPath)
	}

	headerName, _ := data["header_name"].(string)
	if headerName == "" {
		return nil, fmt.Errorf("secret %s: missing or empty 'header_name' field", vaultPath)
	}

	headerPrefix, _ := data["header_prefix"].(string)

	return &CredentialValue{
		Key:          key,
		HeaderName:   headerName,
		HeaderPrefix: headerPrefix,
	}, nil
}
