package proxy

import (
	"sync"

	"github.com/dayvidpham/nix-openclaw-vm/credential-proxy/workflows"
)

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
type RequestRegistry struct {
	m sync.Map
}

// Store registers a RequestContext under the given requestID.
func (r *RequestRegistry) Store(id string, ctx *workflows.RequestContext) {
	r.m.Store(id, ctx)
}

// Load retrieves a RequestContext by requestID. Returns (nil, false) if not found.
// Implements workflows.ContextRegistry.
func (r *RequestRegistry) Load(id string) (*workflows.RequestContext, bool) {
	v, ok := r.m.Load(id)
	if !ok {
		return nil, false
	}
	return v.(*workflows.RequestContext), true
}

// Delete removes a RequestContext from the registry.
func (r *RequestRegistry) Delete(id string) {
	r.m.Delete(id)
}

// Compile-time check: RequestRegistry implements workflows.ContextRegistry.
var _ workflows.ContextRegistry = (*RequestRegistry)(nil)
