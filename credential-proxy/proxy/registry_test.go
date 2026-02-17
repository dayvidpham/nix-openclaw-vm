package proxy

import (
	"context"
	"testing"
	"time"

	"github.com/dayvidpham/nix-openclaw-vm/credential-proxy/config"
	"github.com/dayvidpham/nix-openclaw-vm/credential-proxy/workflows"
)

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

// makeTestReqCtx returns a minimal RequestContext sufficient for registry tests.
// The DecisionCh is buffered (cap 1) matching the production pattern.
func makeTestReqCtx() *workflows.RequestContext {
	return &workflows.RequestContext{
		ScrubMap:   make(map[string]string),
		DecisionCh: make(chan *workflows.WorkflowDecision, 1),
	}
}

// testGatewayWithTTL builds a bare Gateway whose cfg.ConnTokenTTLSecs is set
// to the given number of seconds. No proxy or temporal client is needed for
// connToken helper tests.
func testGatewayWithTTL(connTokenTTL time.Duration) *Gateway {
	secs := int(connTokenTTL.Seconds())
	if secs < 1 {
		secs = 1
	}
	return &Gateway{
		cfg: &config.Config{
			ConnTokenTTLSecs: secs,
		},
	}
}

// ---------------------------------------------------------------------------
// RequestRegistry TTL tests
// ---------------------------------------------------------------------------

// TestRegistry_EntryEvictedAfterTTL verifies that the sweeper removes an entry
// once its age exceeds the configured TTL.
func TestRegistry_EntryEvictedAfterTTL(t *testing.T) {
	reg := &RequestRegistry{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const ttl = 60 * time.Millisecond
	const interval = 20 * time.Millisecond
	reg.Start(ctx, ttl, interval)

	reg.Store("evict-me", makeTestReqCtx())

	// Immediately after Store the entry must be visible.
	if _, ok := reg.Load("evict-me"); !ok {
		t.Fatal("entry should be present immediately after Store")
	}

	// Wait for TTL plus two sweep intervals so the sweeper has time to run.
	time.Sleep(ttl + 2*interval)

	if _, ok := reg.Load("evict-me"); ok {
		t.Error("entry should have been evicted after TTL expired")
	}
}

// TestRegistry_ActiveEntryNotEvicted verifies that entries younger than the TTL
// are preserved across sweep cycles.
func TestRegistry_ActiveEntryNotEvicted(t *testing.T) {
	reg := &RequestRegistry{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const ttl = 300 * time.Millisecond
	const interval = 20 * time.Millisecond
	reg.Start(ctx, ttl, interval)

	reg.Store("keep-me", makeTestReqCtx())

	// After 2 sweep intervals (well before TTL), entry must still exist.
	time.Sleep(2 * interval)

	if _, ok := reg.Load("keep-me"); !ok {
		t.Error("entry should not be evicted before TTL expires")
	}
}

// TestRegistry_SweeperExitsOnCancel verifies that the sweeper goroutine
// terminates cleanly when its context is cancelled (no goroutine leak).
func TestRegistry_SweeperExitsOnCancel(t *testing.T) {
	reg := &RequestRegistry{}
	ctx, cancel := context.WithCancel(context.Background())

	reg.Start(ctx, 10*time.Second, 10*time.Millisecond)

	// Cancel and give the goroutine time to exit the select loop.
	cancel()
	time.Sleep(50 * time.Millisecond)

	// The registry itself must remain usable after the sweeper stops.
	reg.Store("post-cancel", makeTestReqCtx())
	if _, ok := reg.Load("post-cancel"); !ok {
		t.Error("registry should be functional after sweeper stops")
	}
	reg.Delete("post-cancel")
}

// TestRegistry_ExplicitDeleteBeforeTTL verifies that a manual Delete removes
// the entry immediately, before any sweeper cycle.
func TestRegistry_ExplicitDeleteBeforeTTL(t *testing.T) {
	reg := &RequestRegistry{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	reg.Start(ctx, 500*time.Millisecond, 100*time.Millisecond)

	reg.Store("delete-early", makeTestReqCtx())
	reg.Delete("delete-early")

	if _, ok := reg.Load("delete-early"); ok {
		t.Error("entry should be absent immediately after Delete")
	}
}

// TestRegistry_MultipleEntries verifies that the sweeper evicts only stale
// entries and leaves fresh ones intact.
func TestRegistry_MultipleEntries(t *testing.T) {
	reg := &RequestRegistry{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const ttl = 80 * time.Millisecond
	const interval = 20 * time.Millisecond
	reg.Start(ctx, ttl, interval)

	// Store first entry — will be stale by the time we check.
	reg.Store("stale", makeTestReqCtx())

	// Wait past the TTL before adding the fresh entry.
	time.Sleep(ttl + interval)

	// Store second entry — should be fresh relative to the next sweep.
	reg.Store("fresh", makeTestReqCtx())

	// Wait one more sweep interval so the sweeper runs at least once more.
	time.Sleep(2 * interval)

	if _, ok := reg.Load("stale"); ok {
		t.Error("stale entry should have been evicted")
	}
	if _, ok := reg.Load("fresh"); !ok {
		t.Error("fresh entry should still be present")
	}
}

// ---------------------------------------------------------------------------
// connTokens TTL tests
// ---------------------------------------------------------------------------

// TestConnToken_EntryEvictedAfterTTL verifies that a connToken is automatically
// removed from Gateway.connTokens when its TTL timer fires (simulating a client
// that disconnects after CONNECT without sending any request).
func TestConnToken_EntryEvictedAfterTTL(t *testing.T) {
	gw := &Gateway{}
	key := "192.0.2.1:54321"
	token := "eyJhbGciOiJSUzI1NiJ9.stale"

	const ttl = 60 * time.Millisecond

	// Construct the connToken directly to control the TTL precisely.
	ct := &connToken{
		token: token,
		timer: time.AfterFunc(ttl, func() {
			gw.connTokens.Delete(key)
		}),
	}
	gw.connTokens.Store(key, ct)

	// Entry must be visible immediately after storage.
	if got, ok := gw.loadConnToken(key); !ok || got != token {
		t.Fatalf("expected token %q before TTL, got %q (ok=%v)", token, got, ok)
	}

	// After the TTL fires the entry should be gone.
	time.Sleep(ttl + 20*time.Millisecond)

	if _, ok := gw.loadConnToken(key); ok {
		t.Error("connToken should be evicted after TTL expires")
	}
}

// TestConnToken_TimerCancelledOnDelete verifies that deleteConnToken stops the
// TTL timer so it does not fire after the entry has been consumed normally
// (i.e., the handleResponse cleanup path cancels the pending eviction).
func TestConnToken_TimerCancelledOnDelete(t *testing.T) {
	gw := &Gateway{}
	key := "192.0.2.2:12345"

	fired := make(chan struct{}, 1)
	ct := &connToken{
		token: "eyJhbGciOiJSUzI1NiJ9.consumed",
		timer: time.AfterFunc(80*time.Millisecond, func() {
			fired <- struct{}{}
		}),
	}
	gw.connTokens.Store(key, ct)

	// Simulate the handleResponse cleanup path.
	gw.deleteConnToken(key)

	// Entry must be gone immediately.
	if _, ok := gw.loadConnToken(key); ok {
		t.Error("entry should be absent after deleteConnToken")
	}

	// The timer must NOT fire within its original deadline.
	select {
	case <-fired:
		t.Error("TTL timer fired after deleteConnToken stopped it")
	case <-time.After(150 * time.Millisecond):
		// Correct: timer was cancelled.
	}
}

// TestConnToken_StoreAndLoad exercises the storeConnToken → loadConnToken
// round-trip (mirrors handleConnect → resolveToken flow) using a long TTL so
// the timer does not interfere with the test.
func TestConnToken_StoreAndLoad(t *testing.T) {
	gw := testGatewayWithTTL(5 * time.Minute)
	key := "10.0.0.1:8080"
	token := "eyJhbGciOiJSUzI1NiJ9.valid"

	gw.storeConnToken(key, token)
	defer gw.deleteConnToken(key) // cancel timer on test exit

	got, ok := gw.loadConnToken(key)
	if !ok {
		t.Fatal("loadConnToken: entry absent after storeConnToken")
	}
	if got != token {
		t.Errorf("loadConnToken: got %q, want %q", got, token)
	}
}

// TestConnToken_LoadAbsentKey verifies that loadConnToken returns ("", false)
// when no entry exists for the given remote address.
func TestConnToken_LoadAbsentKey(t *testing.T) {
	gw := &Gateway{}
	if _, ok := gw.loadConnToken("192.0.2.99:9999"); ok {
		t.Error("loadConnToken should return false for absent key")
	}
}

// TestConnToken_DeleteIdempotent verifies that deleteConnToken is safe to call
// on an absent key (no panic, no data race).
func TestConnToken_DeleteIdempotent(t *testing.T) {
	gw := &Gateway{}
	// Should not panic.
	gw.deleteConnToken("192.0.2.100:1234")
}
