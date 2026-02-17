package proxy

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	temporalclient "go.temporal.io/sdk/client"

	"github.com/dayvidpham/nix-openclaw-vm/credential-proxy/authn"
	"github.com/dayvidpham/nix-openclaw-vm/credential-proxy/authz"
	"github.com/dayvidpham/nix-openclaw-vm/credential-proxy/config"
	"github.com/dayvidpham/nix-openclaw-vm/credential-proxy/vault"
)

// ---------------------------------------------------------------------------
// Mock implementations
// ---------------------------------------------------------------------------

type mockVerifier struct {
	identity *authn.AgentIdentity
	err      error
}

func (m *mockVerifier) VerifyToken(_ context.Context, _ string) (*authn.AgentIdentity, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.identity, nil
}

type mockEvaluator struct {
	result *authz.AuthzResult
	err    error
}

func (m *mockEvaluator) Evaluate(_ context.Context, _ *authz.AuthzRequest) (*authz.AuthzResult, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.result, nil
}

type mockStore struct {
	credentials map[string]*vault.CredentialValue
	err         error
}

func (m *mockStore) FetchCredential(_ context.Context, vaultPath string) (*vault.CredentialValue, error) {
	if m.err != nil {
		return nil, m.err
	}
	cred, ok := m.credentials[vaultPath]
	if !ok {
		return nil, vault.ErrSecretNotFound
	}
	return cred, nil
}

// mockTemporalClient implements temporalclient.Client by embedding the
// interface. Only ExecuteWorkflow is overridden (fire-and-forget in handlers).
type mockTemporalClient struct {
	temporalclient.Client
}

func (m *mockTemporalClient) ExecuteWorkflow(_ context.Context, _ temporalclient.StartWorkflowOptions, _ interface{}, _ ...interface{}) (temporalclient.WorkflowRun, error) {
	return nil, nil
}

// Compile-time interface satisfaction checks.
var (
	_ authn.Verifier          = (*mockVerifier)(nil)
	_ authz.Evaluator        = (*mockEvaluator)(nil)
	_ vault.SecretStore      = (*mockStore)(nil)
	_ temporalclient.Client  = (*mockTemporalClient)(nil)
)

// ---------------------------------------------------------------------------
// Test constants
// ---------------------------------------------------------------------------

const (
	gwTestToken   = "test-jwt-token"
	gwPlaceholder = "agent-vault-deadbeef-1234-5678-9abc-def012345678"
	gwRealSecret  = "sk-ant-real-secret-key-12345"
	gwVaultPath   = "secret/data/openclaw/credentials/anthropic"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// generateTestCA creates an ephemeral ECDSA CA certificate and key, returning
// file paths suitable for config.Config.CACertPath / CAKeyPath.
func generateTestCA(t *testing.T) (certPath, keyPath string) {
	t.Helper()
	dir := t.TempDir()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test MITM CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}

	certPath = filepath.Join(dir, "ca.pem")
	keyPath = filepath.Join(dir, "ca-key.pem")

	certFile, err := os.Create(certPath)
	if err != nil {
		t.Fatalf("create cert file: %v", err)
	}
	if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		t.Fatalf("encode cert PEM: %v", err)
	}
	certFile.Close()

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal CA key: %v", err)
	}
	keyFile, err := os.Create(keyPath)
	if err != nil {
		t.Fatalf("create key file: %v", err)
	}
	if err := pem.Encode(keyFile, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}); err != nil {
		t.Fatalf("encode key PEM: %v", err)
	}
	keyFile.Close()

	return certPath, keyPath
}

// testConfig builds a *config.Config with test credentials and domain allowlist.
func testConfig(t *testing.T, certPath, keyPath string) *config.Config {
	t.Helper()
	raw := fmt.Sprintf(`
oidc:
  issuer_url: "http://localhost:8080/realms/test"
  audience: "test-client"
vault:
  address: "http://localhost:8200"
allowed_domains:
  - "api.allowed.com"
  - "127.0.0.1"
ca_cert_path: %q
ca_key_path: %q
credentials:
  - placeholder: %q
    type: api_key
    vault_path: %q
    bound_domain: "api.allowed.com"
    header_name: "x-api-key"
`, certPath, keyPath, gwPlaceholder, gwVaultPath)

	cfg, err := config.Parse([]byte(raw))
	if err != nil {
		t.Fatalf("parse test config: %v", err)
	}
	return cfg
}

// startGateway creates a Gateway, starts serving on a random port, and returns
// the listener address. The listener is closed via t.Cleanup.
func startGateway(t *testing.T, cfg *config.Config, v authn.Verifier, e authz.Evaluator, s vault.SecretStore) string {
	t.Helper()

	gw, err := NewGateway(cfg, v, e, s, &mockTemporalClient{})
	if err != nil {
		t.Fatalf("NewGateway: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go http.Serve(ln, gw)
	t.Cleanup(func() { ln.Close() })

	return ln.Addr().String()
}

// proxyClient returns an *http.Client configured to proxy through proxyAddr.
func gwProxyClient(t *testing.T, proxyAddr string) *http.Client {
	t.Helper()
	proxyURL, err := url.Parse("http://" + proxyAddr)
	if err != nil {
		t.Fatalf("parse proxy URL: %v", err)
	}
	return &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout:   5 * time.Second,
	}
}

func defaultMockVerifier() *mockVerifier {
	return &mockVerifier{
		identity: &authn.AgentIdentity{
			Subject:   "agent-001",
			RawClaims: map[string]interface{}{"sub": "agent-001"},
		},
	}
}

func defaultMockEvaluator() *mockEvaluator {
	return &mockEvaluator{
		result: &authz.AuthzResult{Allowed: true},
	}
}

func defaultMockStore() *mockStore {
	return &mockStore{
		credentials: map[string]*vault.CredentialValue{
			gwVaultPath: {
				Key:          gwRealSecret,
				HeaderName:   "x-api-key",
				HeaderPrefix: "",
			},
		},
	}
}

// ---------------------------------------------------------------------------
// Integration tests
// ---------------------------------------------------------------------------

// TestGateway_PlaceholderSubstitution verifies the full round-trip: a request
// with an agent-vault placeholder is resolved via the mock vault, and the
// upstream receives the real credential instead of the placeholder.
func TestGateway_PlaceholderSubstitution(t *testing.T) {
	certPath, keyPath := generateTestCA(t)
	cfg := testConfig(t, certPath, keyPath)

	receivedKey := make(chan string, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedKey <- r.Header.Get("X-Api-Key")
		fmt.Fprint(w, "ok")
	}))
	defer upstream.Close()

	addr := startGateway(t, cfg, defaultMockVerifier(), defaultMockEvaluator(), defaultMockStore())
	client := gwProxyClient(t, addr)

	req, err := http.NewRequest("GET", upstream.URL+"/v1/chat", nil)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	req.Header.Set("X-Api-Key", gwPlaceholder)
	req.Header.Set("Proxy-Authorization", "Bearer "+gwTestToken)

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 200; body = %q", resp.StatusCode, body)
	}

	got := <-receivedKey
	if got != gwRealSecret {
		t.Errorf("upstream received key = %q, want %q", got, gwRealSecret)
	}
}

// TestGateway_DomainReject verifies that a CONNECT to a non-allowlisted domain
// is rejected (fail-closed domain allowlist). goproxy may either return a 502
// response or simply close the connection — both indicate rejection.
func TestGateway_DomainReject(t *testing.T) {
	certPath, keyPath := generateTestCA(t)
	cfg := testConfig(t, certPath, keyPath)

	addr := startGateway(t, cfg, defaultMockVerifier(), defaultMockEvaluator(), defaultMockStore())

	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	// CONNECT to a domain NOT in the allowlist.
	fmt.Fprintf(conn,
		"CONNECT disallowed.example.com:443 HTTP/1.1\r\nHost: disallowed.example.com:443\r\nProxy-Authorization: Bearer %s\r\n\r\n",
		gwTestToken,
	)

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		// Connection closed without response is an acceptable rejection.
		return
	}
	defer resp.Body.Close()

	// If goproxy sends a response, it should indicate failure (typically 502).
	if resp.StatusCode == http.StatusOK {
		t.Errorf("CONNECT to disallowed domain should not succeed; got status %d", resp.StatusCode)
	}
}

// TestGateway_AuthReject verifies that a request without Proxy-Authorization
// receives a 407 Proxy Authentication Required response.
func TestGateway_AuthReject(t *testing.T) {
	certPath, keyPath := generateTestCA(t)
	cfg := testConfig(t, certPath, keyPath)

	addr := startGateway(t, cfg, defaultMockVerifier(), defaultMockEvaluator(), defaultMockStore())
	client := gwProxyClient(t, addr)

	req, err := http.NewRequest("GET", "http://127.0.0.1/api", nil)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	// Intentionally no Proxy-Authorization.

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusProxyAuthRequired {
		body, _ := io.ReadAll(resp.Body)
		t.Errorf("status = %d, want %d (407); body = %q", resp.StatusCode, http.StatusProxyAuthRequired, body)
	}
}

// TestGateway_AuthzDeny verifies that when the authorization evaluator denies
// a request, the gateway returns 403 with the denial reason.
func TestGateway_AuthzDeny(t *testing.T) {
	certPath, keyPath := generateTestCA(t)
	cfg := testConfig(t, certPath, keyPath)

	denyEval := &mockEvaluator{
		result: &authz.AuthzResult{
			Allowed: false,
			Reason:  "insufficient permissions",
		},
	}

	addr := startGateway(t, cfg, defaultMockVerifier(), denyEval, defaultMockStore())
	client := gwProxyClient(t, addr)

	req, err := http.NewRequest("GET", "http://127.0.0.1/api", nil)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	req.Header.Set("X-Api-Key", gwPlaceholder)
	req.Header.Set("Proxy-Authorization", "Bearer "+gwTestToken)

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want %d (403)", resp.StatusCode, http.StatusForbidden)
	}

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "insufficient permissions") {
		t.Errorf("body = %q, want to contain 'insufficient permissions'", body)
	}
}

// TestGateway_ResponseScrubbing verifies that when the upstream response body
// contains a real credential value, the gateway replaces it with the
// placeholder before returning to the client.
func TestGateway_ResponseScrubbing(t *testing.T) {
	certPath, keyPath := generateTestCA(t)
	cfg := testConfig(t, certPath, keyPath)

	// Upstream echoes the X-Api-Key value it received back in the response body.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiKey := r.Header.Get("X-Api-Key")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"echoed_key":"%s"}`, apiKey)
	}))
	defer upstream.Close()

	addr := startGateway(t, cfg, defaultMockVerifier(), defaultMockEvaluator(), defaultMockStore())
	client := gwProxyClient(t, addr)

	req, err := http.NewRequest("GET", upstream.URL+"/api", nil)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	req.Header.Set("X-Api-Key", gwPlaceholder)
	req.Header.Set("Proxy-Authorization", "Bearer "+gwTestToken)

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 200; body = %q", resp.StatusCode, body)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	if strings.Contains(string(body), gwRealSecret) {
		t.Errorf("response body contains real secret %q: %s", gwRealSecret, body)
	}
	if !strings.Contains(string(body), gwPlaceholder) {
		t.Errorf("response body should contain placeholder %q, got: %s", gwPlaceholder, body)
	}
}

// TestGateway_NoPlaceholderPassthrough verifies that requests without any
// placeholders pass through the gateway unmodified.
func TestGateway_NoPlaceholderPassthrough(t *testing.T) {
	certPath, keyPath := generateTestCA(t)
	cfg := testConfig(t, certPath, keyPath)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "passthrough-ok")
	}))
	defer upstream.Close()

	addr := startGateway(t, cfg, defaultMockVerifier(), defaultMockEvaluator(), defaultMockStore())
	client := gwProxyClient(t, addr)

	req, err := http.NewRequest("GET", upstream.URL+"/health", nil)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	req.Header.Set("Proxy-Authorization", "Bearer "+gwTestToken)

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 200; body = %q", resp.StatusCode, body)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(body) != "passthrough-ok" {
		t.Errorf("body = %q, want %q", body, "passthrough-ok")
	}
}

// TestGateway_UnknownPlaceholder verifies that a request containing a
// placeholder not registered in the config is rejected with 403.
func TestGateway_UnknownPlaceholder(t *testing.T) {
	certPath, keyPath := generateTestCA(t)
	cfg := testConfig(t, certPath, keyPath)

	addr := startGateway(t, cfg, defaultMockVerifier(), defaultMockEvaluator(), defaultMockStore())
	client := gwProxyClient(t, addr)

	unknownPH := "agent-vault-99999999-0000-1111-2222-333333333333"

	req, err := http.NewRequest("GET", "http://127.0.0.1/api", nil)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	req.Header.Set("X-Api-Key", unknownPH)
	req.Header.Set("Proxy-Authorization", "Bearer "+gwTestToken)

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want %d (403)", resp.StatusCode, http.StatusForbidden)
	}

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "unknown credential placeholder") {
		t.Errorf("body = %q, want to contain 'unknown credential placeholder'", body)
	}
}
