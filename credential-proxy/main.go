package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/mdlayher/vsock"
	temporalclient "go.temporal.io/sdk/client"
	"go.temporal.io/sdk/worker"

	"github.com/dayvidpham/nix-openclaw-vm/credential-proxy/authn"
	"github.com/dayvidpham/nix-openclaw-vm/credential-proxy/authz"
	"github.com/dayvidpham/nix-openclaw-vm/credential-proxy/config"
	"github.com/dayvidpham/nix-openclaw-vm/credential-proxy/proxy"
	"github.com/dayvidpham/nix-openclaw-vm/credential-proxy/vault"
	"github.com/dayvidpham/nix-openclaw-vm/credential-proxy/workflows"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "credproxy: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("credproxy", flag.ExitOnError)
	configPath := fs.String("config", "/etc/credproxy/config.yaml", "path to config file")
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("parse flags: %w", err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	slog.SetDefault(logger)

	// Load configuration.
	cfg, err := config.LoadFromFile(*configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	slog.Info("config loaded", "path", *configPath)

	// Initialize OIDC verifier.
	verifier, err := authn.NewOIDCVerifier(ctx, cfg.OIDC)
	if err != nil {
		return fmt.Errorf("init OIDC verifier: %w", err)
	}
	slog.Info("OIDC verifier initialized", "issuer", cfg.OIDC.IssuerURL)

	// Initialize OPA evaluator.
	evaluator, err := authz.NewOPAEvaluator(ctx, cfg.OPA.PolicyDir)
	if err != nil {
		return fmt.Errorf("init OPA evaluator: %w", err)
	}
	slog.Info("OPA evaluator initialized", "policy_dir", cfg.OPA.PolicyDir)

	// Initialize OpenBao vault client.
	vaultClient, err := vault.NewOpenBaoClient(cfg.Vault)
	if err != nil {
		return fmt.Errorf("init vault client: %w", err)
	}
	slog.Info("vault client initialized", "address", cfg.Vault.Address)

	// Connect to Temporal.
	tc, err := temporalclient.Dial(temporalclient.Options{
		HostPort:  cfg.Temporal.HostPort,
		Namespace: cfg.Temporal.Namespace,
	})
	if err != nil {
		return fmt.Errorf("connect to Temporal at %s: %w", cfg.Temporal.HostPort, err)
	}
	defer tc.Close()
	slog.Info("Temporal client connected", "host_port", cfg.Temporal.HostPort, "namespace", cfg.Temporal.Namespace)

	// Initialize the proxy gateway (needs Temporal client for audit workflows).
	gateway, err := proxy.NewGateway(cfg, verifier, evaluator, vaultClient, tc)
	if err != nil {
		return fmt.Errorf("init gateway: %w", err)
	}
	slog.Info("proxy gateway initialized")

	// Start Temporal worker.
	w := worker.New(tc, cfg.Temporal.TaskQueue, worker.Options{})
	w.RegisterWorkflow(workflows.ProxyRequestWorkflow)
	w.RegisterWorkflow(workflows.AuditWorkflow)
	activities := &workflows.Activities{
		Store: vaultClient,
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
			// Disable redirect-following to prevent credential exfiltration
			// via malicious redirects to attacker-controlled domains.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		Config:    cfg,
		Evaluator: evaluator,
	}
	w.RegisterActivity(activities)

	if err := w.Start(); err != nil {
		return fmt.Errorf("start Temporal worker: %w", err)
	}
	defer w.Stop()
	slog.Info("Temporal worker started", "task_queue", cfg.Temporal.TaskQueue)

	// Create VSOCK listener.
	listener, err := vsock.Listen(cfg.Listener.Port, nil)
	if err != nil {
		return fmt.Errorf("listen on vsock port %d: %w", cfg.Listener.Port, err)
	}
	defer listener.Close()
	slog.Info("VSOCK listener started", "port", cfg.Listener.Port)

	// Serve HTTP on the VSOCK listener.
	server := &http.Server{Handler: gateway}

	// Graceful shutdown goroutine.
	go func() {
		<-ctx.Done()
		slog.Info("shutting down")
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer shutdownCancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			slog.Error("HTTP server shutdown error", "error", err)
		}
	}()

	slog.Info("credproxy ready")
	if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("serve: %w", err)
	}

	return nil
}
