# OpenClaw NixOS Module
# Secure personal AI assistant running in isolated Podman containers
#
# This module provides:
# - Rootless Podman containers for OpenClaw instances
# - Dual-mode secrets management:
#   - v1: sops-nix encrypted secrets (fallback)
#   - v2: Zero-trust with Keycloak + OpenBao (recommended)
# - Strict network allowlist (Anthropic API only)
# - Inter-instance communication with authenticated RPC
# - Shared context store with gatekeeper
#
# Security Features:
# - Read-only root filesystem
# - No capabilities (CAP_DROP ALL)
# - Seccomp profile enforcement
# - Isolated workspaces per instance
# - No external network access except allowlisted hosts
# - All secrets on tmpfs (never touch disk)
#
# Zero-Trust Mode (v2):
# - Containers have NO credentials
# - External injector authenticates via Keycloak OIDC
# - Secrets fetched from OpenBao, injected to tmpfs
# - Cryptographic isolation (not just permission-based)
{ config
, pkgs
, lib ? pkgs.lib
, ...
}:
let
  cfg = config.CUSTOM.virtualisation.openclaw;

  inherit (lib)
    mkIf
    mkOption
    mkEnableOption
    ;

in
{
  imports = [
    ./secrets.nix
    ./container.nix
    ./network.nix
    ./instance.nix
    ./bridge.nix
    # Zero-trust infrastructure (optional)
    ./keycloak.nix
    ./openbao.nix
    ./injector.nix
  ];

  options.CUSTOM.virtualisation.openclaw = {
    enable = mkEnableOption "OpenClaw secure AI assistant containers";

    warnIfSecretsDisabled = mkOption {
      type = lib.types.bool;
      default = true;
      description = "Warn if secrets management is not enabled. Set to false for development.";
    };

    # Zero-trust secrets architecture
    zeroTrust = {
      enable = mkEnableOption ''
        Zero-trust secrets architecture using Keycloak + OpenBao.
        When enabled, containers have NO credentials. Secrets are injected
        by an external sidecar that authenticates via OIDC.
      '';
    };
  };

  config = mkIf cfg.enable {
    # Ensure podman is enabled
    virtualisation.podman.enable = true;
    virtualisation.podman.dockerCompat = true;

    # Enable rootless containers
    virtualisation.podman.defaultNetwork.settings = {
      dns_enabled = true;
    };

    # Required for user linger (rootless podman)
    security.polkit.enable = true;

    # Assertions for configuration validation
    assertions = [
      {
        assertion = cfg.instances != { };
        message = "At least one OpenClaw instance must be configured when openclaw is enabled";
      }
      {
        assertion = cfg.secrets.enable -> (config ? sops && config.sops ? secrets);
        message = "sops-nix must be imported when openclaw.secrets.enable is true";
      }
      {
        assertion = cfg.container.registry == "" -> cfg.container.gatewayPackage != null;
        message = "openclaw.container.gatewayPackage must be set when container.registry is empty (using local build)";
      }
      # Zero-trust mode requires all three components
      {
        assertion = cfg.zeroTrust.enable -> (cfg.zeroTrust.keycloak.enable && cfg.zeroTrust.openbao.enable && cfg.zeroTrust.injector.enable);
        message = ''
          Zero-trust mode requires all three components enabled:
          - CUSTOM.virtualisation.openclaw.zeroTrust.keycloak.enable
          - CUSTOM.virtualisation.openclaw.zeroTrust.openbao.enable
          - CUSTOM.virtualisation.openclaw.zeroTrust.injector.enable
        '';
      }
      # Zero-trust requires sops for fallback and trust anchor
      {
        assertion = cfg.zeroTrust.enable -> cfg.secrets.enable;
        message = ''
          Zero-trust mode requires sops-nix as trust anchor for Keycloak client credentials.
          Enable CUSTOM.virtualisation.openclaw.secrets.enable and configure sops-nix.
        '';
      }
      # Zero-trust mode requires all three components
      {
        assertion = cfg.zeroTrust.enable -> (cfg.zeroTrust.keycloak.enable && cfg.zeroTrust.openbao.enable && cfg.zeroTrust.injector.enable);
        message = ''
          Zero-trust mode requires all three components enabled:
          - CUSTOM.virtualisation.openclaw.zeroTrust.keycloak.enable
          - CUSTOM.virtualisation.openclaw.zeroTrust.openbao.enable
          - CUSTOM.virtualisation.openclaw.zeroTrust.injector.enable
        '';
      }
      # Zero-trust requires sops for fallback and trust anchor
      {
        assertion = cfg.zeroTrust.enable -> cfg.secrets.enable;
        message = ''
          Zero-trust mode requires sops-nix as trust anchor for Keycloak client credentials.
          Enable CUSTOM.virtualisation.openclaw.secrets.enable and configure sops-nix.
        '';
      }
    ];

    # Warning about secrets (can be suppressed for development)
    warnings = lib.optional (cfg.warnIfSecretsDisabled && !cfg.secrets.enable && !cfg.zeroTrust.enable) ''
      OpenClaw is running without secrets management.
      This is insecure for production use. Either:
      - Enable CUSTOM.virtualisation.openclaw.secrets.enable (sops-nix mode)
      - Enable CUSTOM.virtualisation.openclaw.zeroTrust.enable (zero-trust mode)
      To suppress this warning during development, set CUSTOM.virtualisation.openclaw.warnIfSecretsDisabled = false.
    '';
  };
}
