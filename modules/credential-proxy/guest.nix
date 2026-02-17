# Credential Proxy Guest Module
# Configures the guest VM to route HTTP(S) traffic through the host's
# credential proxy via a VSOCK bridge.
#
# Architecture:
# - socat bridges VSOCK to a local TCP port the agent can reach
# - HTTP_PROXY / HTTPS_PROXY point all agent traffic through the proxy
# - The MITM CA cert is installed in the system trust store
# - Placeholder env vars expose opaque tokens to the agent
# - credproxy-auth / credproxy-request scripts are on PATH for agent use
{ config
, pkgs
, lib ? pkgs.lib
, ...
}:
let
  cfg = config.CUSTOM.virtualisation.openclaw-vm.guest.credentialProxy;

  inherit (lib)
    mkIf
    mkOption
    mkEnableOption
    types
    ;

  # Guest-side client scripts for credential proxy interaction.
  # writeShellApplication provides bash shebang, set -euo pipefail,
  # and injects runtimeInputs into PATH.
  credproxy-auth = pkgs.writeShellApplication {
    name = "credproxy-auth";
    runtimeInputs = [ pkgs.curl pkgs.jq ];
    text = builtins.readFile ../../credential-proxy/scripts/credproxy-auth.sh;
  };
  credproxy-request = pkgs.writeShellApplication {
    name = "credproxy-request";
    runtimeInputs = [ pkgs.curl ];
    text = builtins.readFile ../../credential-proxy/scripts/credproxy-request.sh;
  };
in
{
  options.CUSTOM.virtualisation.openclaw-vm.guest.credentialProxy = {
    enable = mkEnableOption "Credential proxy client in guest VM";

    localPort = mkOption {
      type = types.port;
      default = 18790;
      description = "Local TCP port for the VSOCK bridge (matches host vsockPort)";
    };

    vsockPort = mkOption {
      type = types.port;
      default = 18790;
      description = "VSOCK port on the host to connect to";
    };

    caCertFile = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "Path to the credential proxy MITM CA certificate for trust store installation";
    };

    keycloakURL = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "Keycloak token endpoint URL for OIDC authentication";
    };

    clientId = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "OIDC client ID for credential proxy authentication";
    };

    clientSecretFile = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "Path to file containing the OIDC client secret (read at runtime by credproxy-auth)";
    };

    placeholderEnvVars = mkOption {
      type = types.attrsOf types.str;
      default = { };
      description = "Environment variables mapping names to placeholder tokens (e.g., ANTHROPIC_API_KEY = \"agent-vault-...\")";
      example = {
        ANTHROPIC_API_KEY = "agent-vault-00000000-0000-0000-0000-000000000001";
      };
    };
  };

  config = mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.caCertFile != null;
        message = "credentialProxy.caCertFile must be set when credentialProxy is enabled. The MITM CA cert is required for TLS trust.";
      }
    ];

    # socat VSOCK bridge: forwards local TCP to host's credential proxy via VSOCK
    # CID 2 = host
    systemd.services.credproxy-vsock-bridge = {
      description = "VSOCK Bridge to Credential Proxy";
      after = [ "network.target" ];
      wantedBy = [ "multi-user.target" ];

      serviceConfig = {
        Type = "simple";
        ExecStart = "${pkgs.socat}/bin/socat TCP-LISTEN:${toString cfg.localPort},fork,reuseaddr VSOCK-CONNECT:2:${toString cfg.vsockPort}";
        Restart = "always";
        RestartSec = "1s";

        # Hardening — network proxy only
        DynamicUser = true;
        NoNewPrivileges = true;
        PrivateTmp = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        RestrictNamespaces = true;
        RestrictSUIDSGID = true;
        CapabilityBoundingSet = "";
        SystemCallFilter = [ "@system-service" "~@privileged" ];
      };
    };

    # Install MITM CA cert in system trust store so TLS verification passes
    # through the credential proxy's MITM interception.
    # (assertion above guarantees caCertFile is non-null when enabled)
    security.pki.certificateFiles = [ cfg.caCertFile ];

    # Client scripts for credential proxy interaction (auth + request wrapper)
    environment.systemPackages = [
      credproxy-auth
      credproxy-request
    ];

    # Proxy env vars: use environment.variables so systemd services also get them
    environment.variables = {
      HTTP_PROXY = "http://localhost:${toString cfg.localPort}";
      HTTPS_PROXY = "http://localhost:${toString cfg.localPort}";
      NO_PROXY = "localhost,127.0.0.1";
    } // cfg.placeholderEnvVars;

    # CREDPROXY_TOKEN_FILE uses XDG_RUNTIME_DIR which must be evaluated at
    # login time, not build time — set via a profile.d snippet.
    environment.etc."profile.d/credproxy-token.sh" = {
      text = ''
        export CREDPROXY_TOKEN_FILE="''${XDG_RUNTIME_DIR:-/tmp}/credproxy-jwt"
      '';
    };

    # Generate /etc/credproxy/client.env for credproxy-auth when Keycloak is configured
    environment.etc."credproxy/client.env" = mkIf (cfg.keycloakURL != null) {
      text = lib.concatStringsSep "\n" (
        [ "CREDPROXY_KEYCLOAK_URL=${lib.escapeShellArg cfg.keycloakURL}" ]
        ++ lib.optional (cfg.clientId != null)
          "CREDPROXY_CLIENT_ID=${lib.escapeShellArg cfg.clientId}"
        ++ lib.optional (cfg.clientSecretFile != null)
          "CREDPROXY_CLIENT_SECRET_FILE=${lib.escapeShellArg (toString cfg.clientSecretFile)}"
        ++ [ "" ]
      );
      mode = "0644";
    };
  };
}
