package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// CredentialType enumerates the supported credential injection methods.
type CredentialType string

const (
	CredentialTypeAPIKey    CredentialType = "api_key"
	CredentialTypeBearer    CredentialType = "bearer"
	CredentialTypeBasicAuth CredentialType = "basic_auth"
	CredentialTypeHeader    CredentialType = "header"
)

// Credential defines a single credential entry with domain binding.
type Credential struct {
	// Placeholder is the opaque token the agent uses (e.g., "agent-vault-<uuid>").
	Placeholder string `yaml:"placeholder"`

	// Type determines how the credential is injected into the request.
	Type CredentialType `yaml:"type"`

	// VaultPath is the OpenBao secret path (e.g., "secret/data/openclaw/credentials/anthropic").
	VaultPath string `yaml:"vault_path"`

	// BoundDomain restricts this credential to a specific target domain.
	// Requests to other domains using this placeholder are rejected (fail-closed).
	BoundDomain string `yaml:"bound_domain"`

	// HeaderName is the HTTP header to inject (e.g., "x-api-key", "Authorization").
	HeaderName string `yaml:"header_name"`

	// HeaderPrefix is prepended to the credential value (e.g., "Bearer " for Authorization header).
	HeaderPrefix string `yaml:"header_prefix"`
}

// OIDCConfig holds Keycloak OIDC JWT validation settings.
type OIDCConfig struct {
	// IssuerURL is the Keycloak realm URL (e.g., "http://127.0.0.1:8080/realms/openclaw").
	IssuerURL string `yaml:"issuer_url"`

	// Audience is the expected JWT audience claim.
	Audience string `yaml:"audience"`
}

// OPAConfig holds embedded OPA policy engine settings.
type OPAConfig struct {
	// PolicyDir is the directory containing .rego policy files.
	PolicyDir string `yaml:"policy_dir"`
}

// VaultConfig holds OpenBao client settings.
type VaultConfig struct {
	// Address is the OpenBao server URL (e.g., "http://127.0.0.1:8200").
	Address string `yaml:"address"`

	// Token is the authentication token (for dev/testing; production uses AppRole or OIDC).
	Token string `yaml:"token,omitempty"`
}

// TemporalConfig holds Temporal client settings.
type TemporalConfig struct {
	// HostPort is the Temporal frontend address (e.g., "localhost:7233").
	HostPort string `yaml:"host_port"`

	// Namespace is the Temporal namespace for proxy workflows.
	Namespace string `yaml:"namespace"`

	// TaskQueue is the task queue name for proxy workers.
	TaskQueue string `yaml:"task_queue"`
}

// ListenerConfig holds VSOCK listener settings.
type ListenerConfig struct {
	// CID is the VSOCK context ID (2 = host).
	CID uint32 `yaml:"cid"`

	// Port is the VSOCK port to listen on.
	Port uint32 `yaml:"port"`
}

// Config is the top-level configuration for the credential proxy.
type Config struct {
	Listener    ListenerConfig `yaml:"listener"`
	OIDC        OIDCConfig     `yaml:"oidc"`
	OPA         OPAConfig      `yaml:"opa"`
	Vault       VaultConfig    `yaml:"vault"`
	Temporal    TemporalConfig `yaml:"temporal"`
	Credentials []Credential   `yaml:"credentials"`

	// AllowedDomains is the fail-closed domain allowlist.
	// Only domains in this list can be proxied via CONNECT.
	AllowedDomains []string `yaml:"allowed_domains"`

	// CAKeyPath and CACertPath are paths to the MITM CA certificate and key.
	CAKeyPath  string `yaml:"ca_key_path"`
	CACertPath string `yaml:"ca_cert_path"`

	// MaxBodySize is the maximum number of bytes read from request/response bodies.
	// Prevents OOM on large or malicious payloads. Defaults to 10 MiB when zero.
	MaxBodySize int64 `yaml:"max_body_size"`

	// RegistryTTLSecs is the maximum lifetime (in seconds) of a RequestRegistry
	// entry before the background sweeper evicts it.
	// Defaults to 120 when zero (2× the 60-second workflow signal timeout).
	RegistryTTLSecs int `yaml:"registry_ttl_secs"`

	// ConnTokenTTLSecs is the maximum lifetime (in seconds) of a JWT stored in
	// connTokens after a CONNECT handshake. Defaults to 120 when zero.
	ConnTokenTTLSecs int `yaml:"conn_token_ttl_secs"`

	// Index built at load time: placeholder string → Credential
	credentialIndex map[string]*Credential
	// Index built at load time: domain → allowed
	domainIndex map[string]bool
}

// LoadFromFile reads and parses a YAML config file.
func LoadFromFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	return Parse(data)
}

// Parse parses YAML config bytes, validates, and builds internal indexes.
func Parse(data []byte) (*Config, error) {
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if err := cfg.buildIndexes(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// validCredentialTypes is the set of recognized credential injection methods.
var validCredentialTypes = map[CredentialType]bool{
	CredentialTypeAPIKey:    true,
	CredentialTypeBearer:    true,
	CredentialTypeBasicAuth: true,
	CredentialTypeHeader:    true,
}

// defaultMaxBodySize is the fallback body read limit when not set in config (10 MiB).
const defaultMaxBodySize int64 = 10 * 1024 * 1024

// Validate checks that required configuration fields are present and valid.
func (c *Config) Validate() error {
	if c.MaxBodySize == 0 {
		c.MaxBodySize = defaultMaxBodySize
	}
	if c.RegistryTTLSecs == 0 {
		c.RegistryTTLSecs = 120
	}
	if c.ConnTokenTTLSecs == 0 {
		c.ConnTokenTTLSecs = 120
	}
	if c.OIDC.IssuerURL == "" {
		return fmt.Errorf("config: oidc.issuer_url is required")
	}
	if c.Vault.Address == "" {
		return fmt.Errorf("config: vault.address is required")
	}
	for i, cred := range c.Credentials {
		if cred.Placeholder == "" {
			return fmt.Errorf("config: credentials[%d].placeholder is required", i)
		}
		if cred.VaultPath == "" {
			return fmt.Errorf("config: credentials[%d].vault_path is required (placeholder %q)", i, cred.Placeholder)
		}
		if !validCredentialTypes[cred.Type] {
			return fmt.Errorf("config: credentials[%d].type %q is invalid (placeholder %q)", i, cred.Type, cred.Placeholder)
		}
		if cred.BoundDomain == "" {
			return fmt.Errorf("config: credentials[%d].bound_domain is required (placeholder %q)", i, cred.Placeholder)
		}
	}
	return nil
}

func (c *Config) buildIndexes() error {
	c.credentialIndex = make(map[string]*Credential, len(c.Credentials))
	for i := range c.Credentials {
		cred := &c.Credentials[i]
		if _, exists := c.credentialIndex[cred.Placeholder]; exists {
			return fmt.Errorf("duplicate placeholder: %s", cred.Placeholder)
		}
		c.credentialIndex[cred.Placeholder] = cred
	}

	c.domainIndex = make(map[string]bool, len(c.AllowedDomains))
	for _, d := range c.AllowedDomains {
		c.domainIndex[strings.ToLower(d)] = true
	}
	return nil
}

// LookupCredential returns the Credential for a placeholder string, or nil if not found.
func (c *Config) LookupCredential(placeholder string) *Credential {
	return c.credentialIndex[placeholder]
}

// IsAllowedDomain checks if a domain is in the allowlist (case-insensitive, fail-closed).
func (c *Config) IsAllowedDomain(domain string) bool {
	return c.domainIndex[strings.ToLower(domain)]
}

// RegistryTTL returns the maximum lifetime of a RequestRegistry entry as a Duration.
func (c *Config) RegistryTTL() time.Duration {
	return time.Duration(c.RegistryTTLSecs) * time.Second
}

// ConnTokenTTL returns the maximum lifetime of a connTokens JWT entry as a Duration.
func (c *Config) ConnTokenTTL() time.Duration {
	return time.Duration(c.ConnTokenTTLSecs) * time.Second
}
