package proxy

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	temporalclient "go.temporal.io/sdk/client"

	"github.com/dayvidpham/nix-openclaw-vm/credential-proxy/internal/testutil"
	"github.com/dayvidpham/nix-openclaw-vm/credential-proxy/workflows"
)

// ---------------------------------------------------------------------------
// realActivitiesWorker — exercises the full goproxy ↔ Registry ↔ Activities loop.
//
// Unlike simulatedWorker (which reimplements the injection logic in the test),
// realActivitiesWorker calls the actual Activities.EvaluatePolicy and
// Activities.FetchAndInject methods. This proves the real coordination path
// works end-to-end: goproxy stores a RequestContext in the registry,
// FetchAndInject loads it by requestID, injects real credentials in-place,
// populates ScrubMap, and sends on DecisionCh to unblock the handler goroutine.
// ---------------------------------------------------------------------------

type realActivitiesWorker struct {
	temporalclient.Client // nil — only ExecuteWorkflow / SignalWorkflow are called
	acts                  *workflows.Activities
}

var _ temporalclient.Client = (*realActivitiesWorker)(nil)

func (w *realActivitiesWorker) ExecuteWorkflow(
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
		// Step 1: EvaluatePolicy (real activity — runs OPA evaluator in-process).
		decision, err := w.acts.EvaluatePolicy(ctx, workflows.EvalPolicyInput{
			Claims:       input.Claims,
			Placeholders: input.Placeholders,
			TargetDomain: input.TargetDomain,
		})
		if err != nil || !decision.Allowed {
			_ = w.acts.SendDecision(ctx, workflows.SendDecisionInput{
				RequestID: input.RequestID,
				Status:    workflows.DecisionDenied,
				Reason:    workflows.ReasonAuthorizationDenied,
			})
			return
		}

		// Step 2: FetchAndInject (real activity — loads RequestContext from registry,
		// fetches credentials from vault, injects them in-place into *http.Request,
		// populates ScrubMap, and sends DecisionAllowed on DecisionCh).
		_, _ = w.acts.FetchAndInject(ctx, workflows.FetchInjectInput{
			RequestID:    input.RequestID,
			Placeholders: input.Placeholders,
		})
	}()

	return run, nil
}

func (w *realActivitiesWorker) SignalWorkflow(_ context.Context, _, _, _ string, _ interface{}) error {
	return nil // best-effort in tests
}

// startGatewayWithActivities creates a Gateway wired to real Activities against
// the given registry, starts serving, and returns the listener address.
// It calls NewGateway directly (not startGateway) because the worker type is
// realActivitiesWorker rather than the simulatedWorker used in gateway_test.go.
func startGatewayWithActivities(t *testing.T, acts *workflows.Activities, reg *RequestRegistry) string {
	t.Helper()

	certPath, keyPath := generateTestCA(t)
	cfg := testConfig(t, certPath, keyPath)
	acts.Config = cfg

	worker := &realActivitiesWorker{acts: acts}
	verifier := testutil.DefaultVerifier()

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

// ---------------------------------------------------------------------------
// TestGateway_Integration_RealActivities verifies the full synchronization loop
// using real Activities. Key differences from the simulatedWorker-based tests:
//
//  1. EvaluatePolicy calls the real mockEvaluator via Activities.EvaluatePolicy.
//  2. FetchAndInject loads the RequestContext from the real RequestRegistry and
//     calls the real mockStore via Activities.FetchAndInject.
//  3. Credential injection and ScrubMap population happen via the real code path.
//
// This proves that goproxy, RequestRegistry, and the Activities package are
// correctly wired together: the handler goroutine stores the context, the
// activity goroutine finds and modifies it, and the decision channel handshake
// unblocks goproxy at the right moment.
// ---------------------------------------------------------------------------
func TestGateway_Integration_RealActivities(t *testing.T) {
	receivedKey := make(chan string, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedKey <- r.Header.Get("X-Api-Key")
		fmt.Fprint(w, "ok")
	}))
	defer upstream.Close()

	reg := &RequestRegistry{}
	acts := &workflows.Activities{
		Store:     testutil.DefaultStore(),
		Evaluator: testutil.AllowEvaluator(),
		Registry:  reg,
		// Config and Verifier are set by startGatewayWithActivities.
	}

	addr := startGatewayWithActivities(t, acts, reg)
	client := gwProxyClient(t, addr)

	req, err := http.NewRequest("GET", upstream.URL+"/v1/chat", nil)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	req.Header.Set("X-Api-Key", testutil.TestPlaceholder)
	req.Header.Set("Proxy-Authorization", "Bearer "+testutil.TestJWT)

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
	if got != testutil.TestRealSecret {
		t.Errorf("upstream received key = %q, want %q", got, testutil.TestRealSecret)
	}
}

// TestGateway_Integration_ResponseScrubbing verifies the full roundtrip including
// response scrubbing: the upstream echoes the injected credential back in its
// response body, and the gateway replaces it with the placeholder before the
// client receives the response.
func TestGateway_Integration_ResponseScrubbing(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Echo the injected credential value back in the response body.
		apiKey := r.Header.Get("X-Api-Key")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"echoed_key":"%s"}`, apiKey)
	}))
	defer upstream.Close()

	reg := &RequestRegistry{}
	acts := &workflows.Activities{
		Store:     testutil.DefaultStore(),
		Evaluator: testutil.AllowEvaluator(),
		Registry:  reg,
	}

	addr := startGatewayWithActivities(t, acts, reg)
	client := gwProxyClient(t, addr)

	req, err := http.NewRequest("GET", upstream.URL+"/api", nil)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	req.Header.Set("X-Api-Key", testutil.TestPlaceholder)
	req.Header.Set("Proxy-Authorization", "Bearer "+testutil.TestJWT)

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

	// Real credential must not appear in the response body.
	if strings.Contains(string(body), testutil.TestRealSecret) {
		t.Errorf("response body contains real secret %q: %s", testutil.TestRealSecret, body)
	}
	// Placeholder should replace it.
	if !strings.Contains(string(body), testutil.TestPlaceholder) {
		t.Errorf("response body should contain placeholder %q after scrubbing, got: %s", testutil.TestPlaceholder, body)
	}
}

// TestGateway_Integration_AuthzDenied verifies that when EvaluatePolicy denies
// the request, the real Activities.SendDecision path fires and the gateway
// returns the correct 403 status.
func TestGateway_Integration_AuthzDenied(t *testing.T) {
	reg := &RequestRegistry{}
	acts := &workflows.Activities{
		Store:     testutil.DefaultStore(),
		Evaluator: testutil.DenyEvaluator("insufficient role"),
		Registry:  reg,
	}

	addr := startGatewayWithActivities(t, acts, reg)
	client := gwProxyClient(t, addr)

	req, err := http.NewRequest("GET", "http://127.0.0.1/api", nil)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	req.Header.Set("X-Api-Key", testutil.TestPlaceholder)
	req.Header.Set("Proxy-Authorization", "Bearer "+testutil.TestJWT)

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(resp.Body)
		t.Errorf("status = %d, want %d (403); body = %q", resp.StatusCode, http.StatusForbidden, body)
	}
}
