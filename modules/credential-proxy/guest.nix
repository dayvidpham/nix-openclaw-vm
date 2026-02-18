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
    mkMerge
    mkOption
    mkEnableOption
    types
    ;

  # When devMode is enabled, auto-derive the OIDC token endpoint URL
  # from the guest-side VSOCK bridge to OpenBao at localhost:8200.
  effectiveTokenURL = if cfg.devMode.enable
    then "http://localhost:8200/v1/identity/oidc/provider/credproxy/token"
    else cfg.tokenURL;

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

    devMode = {
      enable = mkEnableOption "Dev mode guest configuration (OpenBao VSOCK bridge, auto-config)";
    };

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

    tokenURL = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "OIDC token endpoint URL for authentication (IdP-agnostic, replaces keycloakURL)";
    };

    keycloakURL = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "Legacy: Keycloak token endpoint URL (use tokenURL instead)";
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

    fwCfg = {
      enable = mkEnableOption ''
        Populate placeholder env vars from the fw_cfg JSON credential at boot.

        When enabled, a oneshot systemd service reads the credproxy-placeholder-env
        credential (passed by the host via fw_cfg / microvm.credentialFiles) and writes
        /run/credproxy/placeholder.env. A profile.d snippet sources this file at login,
        making fw_cfg the single source of truth for placeholder env var assignments.

        This is set automatically by the host credential-proxy module when microvm is
        available. There is normally no need to set this manually.
      '';
    };
  };

  config = mkIf cfg.enable (mkMerge [
    {
      assertions = [
        {
          # In devMode the CA cert is delivered at runtime via virtiofs,
          # so caCertFile (a build-time path) is not required.
          assertion = cfg.devMode.enable || cfg.caCertFile != null;
          message = "credentialProxy.caCertFile must be set when credentialProxy is enabled (unless devMode is active). The MITM CA cert is required for TLS trust.";
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
      # In devMode the cert is delivered at runtime via virtiofs instead (see below).
      security.pki.certificateFiles = mkIf
        (!cfg.devMode.enable && cfg.caCertFile != null)
        [ cfg.caCertFile ];

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

      # Generate /etc/credproxy/client.env for credproxy-auth
      # Supports both tokenURL (preferred) and keycloakURL (legacy fallback)
      environment.etc."credproxy/client.env" = mkIf (effectiveTokenURL != null || cfg.keycloakURL != null) {
        text = lib.concatStringsSep "\n" (
          lib.optional (effectiveTokenURL != null)
            "CREDPROXY_TOKEN_URL=${lib.escapeShellArg effectiveTokenURL}"
          ++ lib.optional (cfg.keycloakURL != null && effectiveTokenURL == null)
            "CREDPROXY_KEYCLOAK_URL=${lib.escapeShellArg cfg.keycloakURL}"
          ++ lib.optional (cfg.clientId != null)
            "CREDPROXY_CLIENT_ID=${lib.escapeShellArg cfg.clientId}"
          ++ lib.optional (cfg.clientSecretFile != null)
            "CREDPROXY_CLIENT_SECRET_FILE=${lib.escapeShellArg (toString cfg.clientSecretFile)}"
          ++ [ "" ]
        );
        mode = "0644";
      };
    }

    # fw_cfg → env var boot service.
    # Reads the credproxy-placeholder-env credential (provided by the host via
    # microvm.credentialFiles / QEMU fw_cfg) and writes each env_var=placeholder pair
    # to /run/credproxy/placeholder.env. A profile.d snippet then sources that file
    # at login time so agents see the placeholder tokens without any static Nix config.
    (mkIf cfg.fwCfg.enable {
      systemd.services.credproxy-placeholder-env = {
        description = "Populate credential placeholder env vars from fw_cfg";
        wantedBy = [ "multi-user.target" ];
        before = [ "multi-user.target" ];

        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
          # Import the fw_cfg credential into $CREDENTIALS_DIRECTORY
          ImportCredential = "credproxy-placeholder-env";
          ExecStart = pkgs.writeShellScript "credproxy-placeholder-env-init" ''
            set -euo pipefail
            mkdir -p /run/credproxy
            ${pkgs.jq}/bin/jq -r \
              '.placeholders[] | "\(.env_var)=\(.placeholder)"' \
              "$CREDENTIALS_DIRECTORY/credproxy-placeholder-env" \
              > /run/credproxy/placeholder.env
            chmod 0644 /run/credproxy/placeholder.env
          '';

          # Minimal hardening for a boot-time oneshot
          NoNewPrivileges = true;
          ProtectSystem = "strict";
          ReadWritePaths = [ "/run/credproxy" ];
        };
      };

      # Source placeholder env vars at login time for interactive shells and agent processes.
      # This is the guest-side companion to fwCfg: agents see the tokens without any
      # static configuration baked into the Nix closure.
      environment.etc."profile.d/credproxy-placeholder-env.sh" = {
        text = ''
          # Credential placeholder env vars — written at boot by credproxy-placeholder-env.service
          if [[ -r /run/credproxy/placeholder.env ]]; then
            set -a
            # shellcheck source=/dev/null
            source /run/credproxy/placeholder.env
            set +a
          fi
        '';
        mode = "0644";
      };
    })

    # --- Dev mode guest services ---
    (mkIf cfg.devMode.enable {
      # Runtime CA trust: the host generates the MITM CA key+cert at activation
      # time (credproxy-ca-init), and the virtiofs share exposes it to the guest
      # at /mnt/credproxy/ca/ca.crt.  We poll for the cert, then build a combined
      # CA bundle so TLS clients trust the proxy without any secret in /nix/store.
      systemd.services.credproxy-ca-trust = {
        description = "Install credproxy MITM CA from virtiofs into runtime trust store";
        after = [ "local-fs.target" ];
        before = [ "multi-user.target" ];
        wantedBy = [ "multi-user.target" ];

        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
          ExecStart = pkgs.writeShellScript "credproxy-ca-trust-init" ''
            set -euo pipefail
            # Wait for host CA cert to appear on virtiofs share
            for i in $(seq 1 60); do
              if [ -f /mnt/credproxy/ca/ca.crt ]; then
                break
              fi
              echo "Waiting for credproxy CA cert on virtiofs... ($i/60)"
              sleep 2
            done
            if [ ! -f /mnt/credproxy/ca/ca.crt ]; then
              echo "error: /mnt/credproxy/ca/ca.crt not found after 2 minutes" >&2
              exit 1
            fi
            mkdir -p /run/credproxy
            # Combine the system CA bundle with the credproxy MITM cert
            cat /etc/ssl/certs/ca-certificates.crt /mnt/credproxy/ca/ca.crt \
              > /run/credproxy/ca-bundle.crt
            chmod 0644 /run/credproxy/ca-bundle.crt
            echo "credproxy CA installed in runtime trust bundle"
          '';
          NoNewPrivileges = true;
          ProtectSystem = "strict";
          ReadWritePaths = [ "/run/credproxy" ];
        };
      };

      # Point all TLS libraries at the runtime CA bundle that includes the
      # credproxy MITM cert.  This covers curl, Python requests, Go net/http,
      # Node.js, and most OpenSSL-based tools.
      environment.variables = {
        SSL_CERT_FILE = "/run/credproxy/ca-bundle.crt";
        CURL_CA_BUNDLE = "/run/credproxy/ca-bundle.crt";
        REQUESTS_CA_BUNDLE = "/run/credproxy/ca-bundle.crt";
        NODE_EXTRA_CA_CERTS = "/run/credproxy/ca-bundle.crt";
      };

      # VSOCK bridge to OpenBao for OIDC auth (devMode only)
      # The host runs OpenBao dev server on port 8200; this bridge makes
      # it accessible to the guest at localhost:8200 via VSOCK CID 2.
      systemd.services.credproxy-openbao-bridge = {
        description = "VSOCK Bridge to OpenBao for OIDC auth";
        after = [ "network.target" ];
        wantedBy = [ "multi-user.target" ];
        serviceConfig = {
          Type = "simple";
          ExecStart = "${pkgs.socat}/bin/socat TCP-LISTEN:8200,fork,reuseaddr VSOCK-CONNECT:2:8200";
          Restart = "always";
          RestartSec = "1s";
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

      # Load OIDC client credentials from host virtiofs share.
      # The host provisioning script writes oidc-client.env to /var/lib/credproxy/
      # which is shared to the guest at /mnt/credproxy via virtiofs.
      # This service polls until the file appears (provisioning may still be running)
      # then copies it to /run/credproxy/client-creds.env for credproxy-auth to source.
      systemd.services.credproxy-oidc-creds = {
        description = "Load OIDC client credentials from host virtiofs share";
        after = [ "local-fs.target" "credproxy-openbao-bridge.service" ];
        wantedBy = [ "multi-user.target" ];
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
          ExecStart = pkgs.writeShellScript "credproxy-oidc-creds-init" ''
            set -euo pipefail
            # Wait for provisioning to complete (file appears on virtiofs share)
            for i in $(seq 1 60); do
              if [ -f /mnt/credproxy/oidc-client.env ]; then
                break
              fi
              echo "Waiting for OIDC client credentials... ($i/60)"
              sleep 2
            done
            if [ ! -f /mnt/credproxy/oidc-client.env ]; then
              echo "error: /mnt/credproxy/oidc-client.env not found after 2 minutes" >&2
              exit 1
            fi
            mkdir -p /run/credproxy
            cp /mnt/credproxy/oidc-client.env /run/credproxy/client-creds.env
            chmod 0600 /run/credproxy/client-creds.env
          '';
          NoNewPrivileges = true;
          ProtectSystem = "strict";
          ReadWritePaths = [ "/run/credproxy" ];
        };
      };
    })
  ]);
}
