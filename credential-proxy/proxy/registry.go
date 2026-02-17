package proxy

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/dayvidpham/nix-openclaw-vm/credential-proxy/workflows"
)

// registryEntry wraps a RequestContext with a creation timestamp used by the
// background sweeper to enforce TTL-based eviction.
type registryEntry struct {
	ctx       *workflows.RequestContext
	createdAt time.Time
}

// RequestRegistry is an in-process sync.Map that bridges the goproxy OnRequest
// handler goroutine and the Temporal local activity worker goroutine.
//
// Lifecycle:
//  1. OnRequest stores a *workflows.RequestContext keyed by requestID.
//  2. FetchAndInject (local activity) loads the entry, modifies *http.Request
//     in-place, populates ScrubMap, and sends a decision on DecisionCh.
//  3. OnRequest unblocks, defers Delete, and returns.
//
// Registry entries exist only for the duration of the OnRequest handler call.
// Secrets (real credential values) live only in the RequestContext's ScrubMap
// and are never serialized to Temporal event history.
//
// The Start method runs a background sweeper that evicts entries older than a
// configured TTL, providing defence-in-depth against leaked entries when the
// handler goroutine exits abnormally without calling Delete.
type RequestRegistry struct {
	m sync.Map
}

// Store registers a RequestContext under the given requestID, recording the
// current time as the entry's creation timestamp for TTL tracking.
func (r *RequestRegistry) Store(id string, ctx *workflows.RequestContext) {
	r.m.Store(id, &registryEntry{ctx: ctx, createdAt: time.Now()})
}

// Load retrieves a RequestContext by requestID. Returns (nil, false) if not found.
// Implements workflows.ContextRegistry.
func (r *RequestRegistry) Load(id string) (*workflows.RequestContext, bool) {
	v, ok := r.m.Load(id)
	if !ok {
		return nil, false
	}
	return v.(*registryEntry).ctx, true
}

// Delete removes a RequestContext from the registry.
func (r *RequestRegistry) Delete(id string) {
	r.m.Delete(id)
}

// Start runs a background sweeper goroutine that evicts entries older than ttl,
// ticking every sweepInterval. The goroutine exits cleanly when ctx is cancelled.
// Callers should pass a context derived from the server's shutdown context so
// the sweeper stops alongside the rest of the process.
func (r *RequestRegistry) Start(ctx context.Context, ttl, sweepInterval time.Duration) {
	go func() {
		ticker := time.NewTicker(sweepInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				r.sweep(ttl)
			}
		}
	}()
}

// sweep evicts all registry entries whose age exceeds ttl.
func (r *RequestRegistry) sweep(ttl time.Duration) {
	now := time.Now()
	r.m.Range(func(k, v any) bool {
		entry := v.(*registryEntry)
		age := now.Sub(entry.createdAt)
		if age > ttl {
			r.m.Delete(k)
			slog.Warn("evicted stale RequestRegistry entry",
				"id", k,
				"age", age.Truncate(time.Millisecond).String(),
			)
		}
		return true
	})
}

// Compile-time check: RequestRegistry implements workflows.ContextRegistry.
var _ workflows.ContextRegistry = (*RequestRegistry)(nil)
