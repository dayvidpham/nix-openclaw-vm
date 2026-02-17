package proxy

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/elazarl/goproxy"
	temporalclient "go.temporal.io/sdk/client"

	"github.com/dayvidpham/nix-openclaw-vm/credential-proxy/authn"
	"github.com/dayvidpham/nix-openclaw-vm/credential-proxy/config"
)

// connToken stores a JWT token alongside its TTL cleanup timer. Entries are
// stored in Gateway.connTokens keyed by the client's remoteAddr string.
// The timer fires if the connection is abandoned after CONNECT (i.e., the
// client disconnects before sending any request), preventing token leaks.
type connToken struct {
	token string
	timer *time.Timer
}

// Gateway is the credential-proxy HTTP handler. It composes domain allowlist
// enforcement, JWT validation, Temporal workflow orchestration, credential
// injection (via local activities), and response scrubbing around a goproxy
// MITM proxy.
//
// JWT validation is performed inline in OnRequest (via the Verifier) before any
// Temporal workflow is started. This keeps raw tokens out of Temporal event
// history and avoids workflow overhead for unauthenticated requests.
// Authorization and credential fetching are handled inside Temporal activities
// for retry semantics and a complete audit trail.
type Gateway struct {
	cfg      *config.Config
	proxy    *goproxy.ProxyHttpServer
	temporal temporalclient.Client
	registry *RequestRegistry
	verifier authn.Verifier

	// connTokens maps remote addresses to *connToken entries created during
	// CONNECT handshakes. Each entry carries its own TTL timer so that tokens
	// are evicted automatically when a client disconnects before sending a request.
	connTokens sync.Map // remoteAddr → *connToken
}

// Compile-time check: Gateway implements http.Handler.
var _ http.Handler = (*Gateway)(nil)

// NewGateway constructs a fully-wired Gateway and registers goproxy handlers.
// The registry must be the same instance passed to workflows.Activities so that
// local activities can find RequestContext entries created by the OnRequest handler.
// The verifier is called inline in OnRequest to validate JWTs before starting any
// Temporal workflow, keeping raw tokens out of Temporal event history.
func NewGateway(cfg *config.Config, tc temporalclient.Client, reg *RequestRegistry, verifier authn.Verifier) (*Gateway, error) {
	// Load MITM CA certificate if configured.
	if cfg.CACertPath != "" && cfg.CAKeyPath != "" {
		ca, err := tls.LoadX509KeyPair(cfg.CACertPath, cfg.CAKeyPath)
		if err != nil {
			return nil, fmt.Errorf("load MITM CA certificate: %w", err)
		}
		goproxy.GoproxyCa = ca
	}

	gw := &Gateway{
		cfg:      cfg,
		proxy:    goproxy.NewProxyHttpServer(),
		temporal: tc,
		registry: reg,
		verifier: verifier,
	}

	registerHandlers(gw)

	return gw, nil
}

// ServeHTTP delegates to the internal goproxy handler, implementing http.Handler.
func (gw *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	gw.proxy.ServeHTTP(w, r)
}

// storeConnToken stores a JWT for a remote address and schedules TTL eviction.
// If the client disconnects after CONNECT without sending a request, the timer
// fires and removes the entry so connTokens does not grow without bound.
func (gw *Gateway) storeConnToken(remoteAddr, token string) {
	ttl := gw.cfg.ConnTokenTTL()
	ct := &connToken{
		token: token,
		timer: time.AfterFunc(ttl, func() {
			gw.connTokens.Delete(remoteAddr)
		}),
	}
	gw.connTokens.Store(remoteAddr, ct)
}

// loadConnToken retrieves the JWT for a remote address.
// Returns ("", false) if the entry is absent or the token is empty.
func (gw *Gateway) loadConnToken(remoteAddr string) (string, bool) {
	v, ok := gw.connTokens.Load(remoteAddr)
	if !ok {
		return "", false
	}
	ct, ok := v.(*connToken)
	if !ok || ct.token == "" {
		return "", false
	}
	return ct.token, true
}

// deleteConnToken removes the JWT for a remote address and stops its TTL timer.
// Called by handleResponse on the normal response path to cancel the timer
// before it fires.
func (gw *Gateway) deleteConnToken(remoteAddr string) {
	if v, ok := gw.connTokens.LoadAndDelete(remoteAddr); ok {
		if ct, ok := v.(*connToken); ok {
			ct.timer.Stop()
		}
	}
}
