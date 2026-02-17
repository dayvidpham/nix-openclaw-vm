package proxy

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"sync"

	"github.com/elazarl/goproxy"
	temporalclient "go.temporal.io/sdk/client"

	"github.com/dayvidpham/nix-openclaw-vm/credential-proxy/config"
)

// Gateway is the credential-proxy HTTP handler. It composes domain allowlist
// enforcement, JWT extraction, Temporal workflow orchestration, credential
// injection (via local activities), and response scrubbing around a goproxy
// MITM proxy.
//
// Authentication, authorization, and credential fetching are all performed
// inside Temporal activities — not inline in the proxy handlers. This keeps
// secret values out of Temporal event history and provides a full audit trail.
type Gateway struct {
	cfg      *config.Config
	proxy    *goproxy.ProxyHttpServer
	temporal temporalclient.Client
	registry *RequestRegistry

	// connTokens maps remote addresses to JWT tokens extracted during CONNECT
	// handshakes. This bridges HandleConnect and OnRequest, which run in
	// separate goproxy ProxyCtx instances.
	connTokens sync.Map // remoteAddr → string (raw JWT)
}

// Compile-time check: Gateway implements http.Handler.
var _ http.Handler = (*Gateway)(nil)

// NewGateway constructs a fully-wired Gateway and registers goproxy handlers.
// The registry must be the same instance passed to workflows.Activities so that
// local activities can find RequestContext entries created by the OnRequest handler.
func NewGateway(cfg *config.Config, tc temporalclient.Client, reg *RequestRegistry) (*Gateway, error) {
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
	}

	registerHandlers(gw)

	return gw, nil
}

// ServeHTTP delegates to the internal goproxy handler, implementing http.Handler.
func (gw *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	gw.proxy.ServeHTTP(w, r)
}
