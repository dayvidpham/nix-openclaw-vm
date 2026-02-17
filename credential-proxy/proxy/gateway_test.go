package proxy

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
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
	"github.com/dayvidpham/nix-openclaw-vm/credential-proxy/config"
	"github.com/dayvidpham/nix-openclaw-vm/credential-proxy/internal/testutil"
	"github.com/dayvidpham/nix-openclaw-vm/credential-proxy/vault"
	"github.com/dayvidpham/nix-openclaw-vm/credential-proxy/workflows"
)

// ---------------------------------------------------------------------------
// simulatedWorker — replaces the real Temporal worker for gateway integration tests.
//
// It implements temporalclient.Client by embedding the interface (nil for unused
// methods) and overriding ExecuteWorkflow and SignalWorkflow. When ExecuteWorkflow
// is called it runs the credential injection logic synchronously in a goroutine,
// simulating the FetchAndInject local activity, so that the gateway handler
// goroutine unblocks on DecisionCh as it would with a real worker.
// ---------------------------------------------------------------------------

type simulatedWorker struct {
	temporalclient.Client // nil — only ExecuteWorkflow / SignalWorkflow are called
	registry *RequestRegistry
	cfg      *config.Config
	store    vault.SecretStore
	// decisionOverride, if non-nil, is sent as the decision for every request.
	// Used to test denial paths without involving the vault / config.
	decisionOverride *workflows.WorkflowDecision
}

var _ temporalclient.Client = (*simulatedWorker)(nil)

func (sw *simulatedWorker) ExecuteWorkflow(
	ctx context.Context,
	opts temporalclient.StartWorkflowOptions,
	_ interface{},
	args ...interface{},
) (temporalclient.WorkflowRun, error) {
	run := &fakeWorkflowRun{id: opts.ID}

	if len(args) == 0 {
		return run, nil
	}
	input, ok := args[0].(workflows.ProxyInput)
	if !ok {
		return run, nil
	}

	go func() {
		reqCtx, ok := sw.registry.Load(input.RequestID)
		if !ok {
			return
		}

		// Honor override decision (for deny-path tests).
		if sw.decisionOverride != nil {
			reqCtx.DecisionCh <- sw.decisionOverride
			return
		}

		// Simulate FetchAndInject: resolve credentials and inject them.
		replacements := make(map[string]string, len(input.Placeholders))
		for _, ph := range input.Placeholders {
			cred := sw.cfg.LookupCredential(ph)
			if cred == nil {
				reqCtx.DecisionCh <- &workflows.WorkflowDecision{
					Status:     workflows.DecisionDenied,
					Reason:     workflows.ReasonCredentialInjectionFailed,
					HTTPStatus: workflows.ReasonCredentialInjectionFailed.HTTPStatusCode(),
				}
				return
			}
			cv, err := sw.store.FetchCredential(ctx, cred.VaultPath)
			if err != nil {
				reqCtx.DecisionCh <- &workflows.WorkflowDecision{
					Status:     workflows.DecisionDenied,
					Reason:     workflows.ReasonCredentialInjectionFailed,
					HTTPStatus: workflows.ReasonCredentialInjectionFailed.HTTPStatusCode(),
				}
				return
			}
			realValue := cv.HeaderPrefix + cv.Key
			replacements[ph] = realValue
			reqCtx.ScrubMap[realValue] = ph
			if cv.HeaderPrefix != "" {
				reqCtx.ScrubMap[cv.Key] = ph
			}
		}

		if err := reqCtx.ReplaceFunc(replacements); err != nil {
			reqCtx.DecisionCh <- &workflows.WorkflowDecision{
				Status:     workflows.DecisionDenied,
				Reason:     workflows.ReasonCredentialInjectionFailed,
				HTTPStatus: workflows.ReasonCredentialInjectionFailed.HTTPStatusCode(),
			}
			return
		}

		reqCtx.DecisionCh <- &workflows.WorkflowDecision{Status: workflows.DecisionAllowed}
	}()

	return run, nil
}

func (sw *simulatedWorker) SignalWorkflow(_ context.Context, _, _, _ string, _ interface{}) error {
	return nil // no-op in tests
}

// fakeWorkflowRun is the minimal WorkflowRun returned by simulatedWorker.
type fakeWorkflowRun struct {
	id string
}

func (f *fakeWorkflowRun) GetID() string                                          { return f.id }
func (f *fakeWorkflowRun) GetRunID() string                                       { return "test-run-id" }
func (f *fakeWorkflowRun) Get(_ context.Context, _ interface{}) error             { return nil }
func (f *fakeWorkflowRun) GetWithOptions(_ context.Context, _ interface{}, _ temporalclient.WorkflowRunGetOptions) error {
	return nil
}

// Compile-time interface satisfaction checks.
var _ temporalclient.Client = (*simulatedWorker)(nil)

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

// defaultMockVerifier returns a verifier that always succeeds with a basic agent identity.
// Use this for tests that only care about the credential injection path, not auth.
func defaultMockVerifier() *testutil.MockVerifier {
	return testutil.DefaultVerifier()
}

// Compile-time check: testutil.MockVerifier implements authn.Verifier.
var _ authn.Verifier = (*testutil.MockVerifier)(nil)

// mockStore implements vault.SecretStore.
type mockStore struct {
	credentials map[string]*vault.CredentialValue
	err         error
}

var _ vault.SecretStore = (*mockStore)(nil)

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

// newSimulatedWorker builds a simulatedWorker with the shared registry, config,
// and vault mock. Use decisionOverride to force a specific decision for deny tests.
func newSimulatedWorker(cfg *config.Config, store vault.SecretStore, override *workflows.WorkflowDecision) (*simulatedWorker, *RequestRegistry) {
	reg := &RequestRegistry{}
	return &simulatedWorker{
		registry:         reg,
		cfg:              cfg,
		store:            store,
		decisionOverride: override,
	}, reg
}

// startGateway creates a Gateway backed by the given simulatedWorker, starts
// serving on a random port, and returns the listener address. The listener is
// closed via t.Cleanup.
func startGateway(t *testing.T, cfg *config.Config, worker *simulatedWorker, reg *RequestRegistry, verifier authn.Verifier) string {
	t.Helper()

	gw, err := NewGateway(cfg, worker, reg, verifier)
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

// gwProxyClient returns an *http.Client configured to proxy through proxyAddr.
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

	worker, reg := newSimulatedWorker(cfg, defaultMockStore(), nil)
	addr := startGateway(t, cfg, worker, reg, defaultMockVerifier())
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

	worker, reg := newSimulatedWorker(cfg, defaultMockStore(), nil)
	addr := startGateway(t, cfg, worker, reg, defaultMockVerifier())

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

	worker, reg := newSimulatedWorker(cfg, defaultMockStore(), nil)
	addr := startGateway(t, cfg, worker, reg, defaultMockVerifier())
	client := gwProxyClient(t, addr)

	req, err := http.NewRequest("GET", "http://127.0.0.1/api", nil)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	// Intentionally no Proxy-Authorization.
	req.Header.Set("X-Api-Key", gwPlaceholder)

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

// TestGateway_WorkflowDeny verifies that when the Temporal workflow denies a
// request (e.g. authz failure), the gateway returns 403 with the denial reason.
func TestGateway_WorkflowDeny(t *testing.T) {
	certPath, keyPath := generateTestCA(t)
	cfg := testConfig(t, certPath, keyPath)

	// Override: workflow always denies due to authorization failure.
	denyDecision := &workflows.WorkflowDecision{
		Status:     workflows.DecisionDenied,
		Reason:     workflows.ReasonAuthorizationDenied,
		HTTPStatus: workflows.ReasonAuthorizationDenied.HTTPStatusCode(),
	}

	worker, reg := newSimulatedWorker(cfg, defaultMockStore(), denyDecision)
	addr := startGateway(t, cfg, worker, reg, defaultMockVerifier())
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
	if !strings.Contains(string(body), workflows.ReasonAuthorizationDenied.String()) {
		t.Errorf("body = %q, want to contain %q", body, workflows.ReasonAuthorizationDenied.String())
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

	worker, reg := newSimulatedWorker(cfg, defaultMockStore(), nil)
	addr := startGateway(t, cfg, worker, reg, defaultMockVerifier())
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
// placeholders pass through the gateway unmodified (no Temporal workflow started).
func TestGateway_NoPlaceholderPassthrough(t *testing.T) {
	certPath, keyPath := generateTestCA(t)
	cfg := testConfig(t, certPath, keyPath)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "passthrough-ok")
	}))
	defer upstream.Close()

	worker, reg := newSimulatedWorker(cfg, defaultMockStore(), nil)
	addr := startGateway(t, cfg, worker, reg, defaultMockVerifier())
	client := gwProxyClient(t, addr)

	req, err := http.NewRequest("GET", upstream.URL+"/health", nil)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	req.Header.Set("Proxy-Authorization", "Bearer "+gwTestToken)
	// No placeholder headers.

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

	unknownPH := "agent-vault-99999999-0000-1111-2222-333333333333"

	worker, reg := newSimulatedWorker(cfg, defaultMockStore(), nil)
	addr := startGateway(t, cfg, worker, reg, defaultMockVerifier())
	client := gwProxyClient(t, addr)

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

	if resp.StatusCode != workflows.ReasonCredentialInjectionFailed.HTTPStatusCode() {
		t.Errorf("status = %d, want %d (502)", resp.StatusCode, workflows.ReasonCredentialInjectionFailed.HTTPStatusCode())
	}

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), workflows.ReasonCredentialInjectionFailed.String()) {
		t.Errorf("body = %q, want to contain %q", body, workflows.ReasonCredentialInjectionFailed.String())
	}
}

// ---------------------------------------------------------------------------
// gwProxyClientTLS and TestGateway_ConnectHTTPS — HTTPS CONNECT MITM path
// ---------------------------------------------------------------------------

// gwProxyClientTLS returns an *http.Client that tunnels HTTPS requests through
// proxyAddr via the HTTP CONNECT method. It trusts the MITM CA at caCertPath
// (so the gateway's dynamically-issued certificates are accepted) and injects
// the test JWT into the CONNECT request via Proxy-Authorization.
func gwProxyClientTLS(t *testing.T, proxyAddr, caCertPath string) *http.Client {
	t.Helper()
	caCert, err := os.ReadFile(caCertPath)
	if err != nil {
		t.Fatalf("read MITM CA cert: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caCert) {
		t.Fatal("failed to append MITM CA cert to pool")
	}
	proxyURL, err := url.Parse("http://" + proxyAddr)
	if err != nil {
		t.Fatalf("parse proxy URL: %v", err)
	}
	return &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			ProxyConnectHeader: http.Header{
				"Proxy-Authorization": []string{"Bearer " + gwTestToken},
			},
			TLSClientConfig: &tls.Config{RootCAs: pool},
		},
		Timeout: 5 * time.Second,
	}
}

// TestGateway_ConnectHTTPS exercises the full HTTPS CONNECT → TLS MITM →
// credential injection path. The client dials through the proxy via CONNECT,
// negotiates TLS with the gateway's MITM certificate (signed by the test CA),
// sends a request with an agent-vault placeholder, and verifies the TLS
// upstream receives the real credential instead of the placeholder.
func TestGateway_ConnectHTTPS(t *testing.T) {
	certPath, keyPath := generateTestCA(t)
	cfg := testConfig(t, certPath, keyPath)

	receivedKey := make(chan string, 1)
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedKey <- r.Header.Get("X-Api-Key")
		fmt.Fprint(w, "tls-ok")
	}))
	defer upstream.Close()

	worker, reg := newSimulatedWorker(cfg, defaultMockStore(), nil)
	addr := startGateway(t, cfg, worker, reg, defaultMockVerifier())
	client := gwProxyClientTLS(t, addr, certPath)

	req, err := http.NewRequest("GET", upstream.URL+"/v1/chat", nil)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	req.Header.Set("X-Api-Key", gwPlaceholder)
	// Proxy-Authorization is sent in the CONNECT headers via ProxyConnectHeader,
	// not in the tunnelled request itself — handleConnect stores it in connTokens.

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

// TestGateway_InvalidToken verifies that a request carrying a present but
// invalid JWT receives a 407 Proxy Authentication Required response.
// This is the zyg path: the proxy validates the JWT inline before any workflow.
func TestGateway_InvalidToken(t *testing.T) {
	certPath, keyPath := generateTestCA(t)
	cfg := testConfig(t, certPath, keyPath)

	// Verifier that always rejects tokens.
	failVerifier := &testutil.MockVerifier{
		Err: fmt.Errorf("token signature invalid"),
	}

	worker, reg := newSimulatedWorker(cfg, defaultMockStore(), nil)
	addr := startGateway(t, cfg, worker, reg, failVerifier)
	client := gwProxyClient(t, addr)

	req, err := http.NewRequest("GET", "http://127.0.0.1/api", nil)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	req.Header.Set("X-Api-Key", gwPlaceholder)
	req.Header.Set("Proxy-Authorization", "Bearer invalid-jwt-token")

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
