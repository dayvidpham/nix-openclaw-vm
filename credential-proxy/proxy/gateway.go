package proxy

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"sync"

	"github.com/elazarl/goproxy"
	temporalclient "go.temporal.io/sdk/client"

	"github.com/dayvidpham/nix-openclaw-vm/credential-proxy/auth"
	"github.com/dayvidpham/nix-openclaw-vm/credential-proxy/authz"
	"github.com/dayvidpham/nix-openclaw-vm/credential-proxy/config"
	"github.com/dayvidpham/nix-openclaw-vm/credential-proxy/vault"
)

// Gateway is the credential-proxy HTTP handler. It composes authentication,
// authorization, vault secret resolution, and credential substitution around
// a goproxy MITM proxy.
type Gateway struct {
	cfg      *config.Config
	auth     auth.Verifier
	authz    authz.Evaluator
	vault    vault.SecretStore
	proxy    *goproxy.ProxyHttpServer
	temporal temporalclient.Client

	// connTokens maps remote addresses to JWT tokens extracted during CONNECT
	// handshakes. This bridges HandleConnect and OnRequest, which use separate
	// goproxy ProxyCtx instances.
	connTokens sync.Map // remoteAddr → string (raw JWT)
}

// Compile-time check: Gateway implements http.Handler.
var _ http.Handler = (*Gateway)(nil)

// NewGateway constructs a fully-wired Gateway and registers goproxy handlers.
func NewGateway(cfg *config.Config, authV auth.Verifier, authzE authz.Evaluator, vaultS vault.SecretStore, tc temporalclient.Client) (*Gateway, error) {
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
		auth:     authV,
		authz:    authzE,
		vault:    vaultS,
		proxy:    goproxy.NewProxyHttpServer(),
		temporal: tc,
	}

	registerHandlers(gw)

	return gw, nil
}

// ServeHTTP delegates to the internal goproxy handler, implementing http.Handler.
func (gw *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	gw.proxy.ServeHTTP(w, r)
}
