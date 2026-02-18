# Credential Proxy Host Module
# Runs the credential proxy and Temporal dev server on the host.
# The proxy listens on VSOCK for requests from the guest VM.
#
# Architecture:
# - Host runs credproxy (Go binary) + Temporal dev server (SQLite-backed)
# - credproxy depends on OpenBao for secret retrieval and Temporal for audit
# - Guest VM connects to credproxy via VSOCK
# - MITM CA key+cert generated at service activation time (never in /nix/store)
{ config
, options
, pkgs
, lib ? pkgs.lib
, credential-proxy
, ...
}:
let
  cfg = config.CUSTOM.virtualisation.openclaw-vm.credentialProxy;

  hasMicrovm = options ? microvm;

  inherit (lib)
    mkIf
    mkMerge
    mkOption
    mkEnableOption
    optionalAttrs
    types
    ;

  credproxy-pkg = credential-proxy.packages.${pkgs.system}.credential-proxy;

  # Credentials that carry an env_var field — these are exposed to the guest
  # via fw_cfg so the guest can populate placeholder env vars at boot.
  credentialsWithEnvVar = builtins.filter (c: c ? env_var) cfg.credentials;

  # JSON credential file passed to the guest VM via fw_cfg.
  # Contains only the fields needed by the guest: env_var, placeholder, alias, bound_domain.
  # The full credential definition (vault_path, header, etc.) stays host-side only.
  credentialPlaceholdersJson = pkgs.writeText "credproxy-placeholder-env.json"
    (builtins.toJSON { placeholders = credentialsWithEnvVar; });

  caDir = "/var/lib/credproxy/ca";
  caKeyPath = "${caDir}/ca.key";
  caCertPath = "${caDir}/ca.crt";

  # When devMode is enabled, override OIDC and vault URLs to point at the
  # local OpenBao dev server instead of external Keycloak / OpenBao instances.
  effectiveOidcIssuerURL = if cfg.devMode.enable
    then "http://127.0.0.1:${toString cfg.devMode.openbaoPort}/v1/identity/oidc/provider/credproxy"
    else cfg.oidcIssuerURL;

  effectiveVaultAddress = if cfg.devMode.enable
    then "http://127.0.0.1:${toString cfg.devMode.openbaoPort}"
    else cfg.vaultAddress;

  # Generate the config file for credproxy.
  # NOTE: builtins.toJSON produces JSON, which is valid YAML 1.2.
  # This is intentional — JSON is a subset of YAML and avoids Nix's
  # lack of a native YAML serializer.
  configFile = pkgs.writeText "credproxy.yaml" (builtins.toJSON {
    listener = {
      cid = 2; # Host CID
      port = cfg.vsockPort;
    };
    oidc = {
      issuer_url = effectiveOidcIssuerURL;
      audience = cfg.oidcAudience;
    };
    opa = {
      policy_dir = cfg.policyDir;
    };
    vault = {
      address = effectiveVaultAddress;
    } // lib.optionalAttrs cfg.devMode.enable {
      token = cfg.devMode.openbaoToken;
    };
    temporal = {
      host_port = "localhost:${toString cfg.temporalPort}";
      namespace = "default";
      task_queue = "credproxy";
    };
    ca_key_path = caKeyPath;
    ca_cert_path = caCertPath;
    allowed_domains = cfg.allowedDomains;
    credentials = cfg.credentials;
  });
in
{
  options.CUSTOM.virtualisation.openclaw-vm.credentialProxy = {
    enable = mkEnableOption "Credential proxy for OpenClaw VM";

    devMode = {
      enable = mkEnableOption "Dev mode with OpenBao dev server for auth + secrets";
      openbaoToken = mkOption {
        type = types.str;
        default = "dev-token";
        description = "Root token for OpenBao dev server";
      };
      openbaoPort = mkOption {
        type = types.port;
        default = 8200;
        description = "Listen port for OpenBao dev server";
      };
    };

    vsockPort = mkOption {
      type = types.port;
      default = 18790;
      description = "VSOCK port for the credential proxy";
    };

    temporalPort = mkOption {
      type = types.port;
      default = 7233;
      description = "Port for the Temporal dev server";
    };

    oidcIssuerURL = mkOption {
      type = types.str;
      default = "http://127.0.0.1:8080/realms/openclaw";
      description = "Keycloak OIDC issuer URL for JWT validation";
    };

    oidcAudience = mkOption {
      type = types.str;
      default = "credproxy";
      description = "Expected JWT audience claim";
    };

    vaultAddress = mkOption {
      type = types.str;
      default = "http://127.0.0.1:8200";
      description = "OpenBao server address";
    };

    policyDir = mkOption {
      type = types.path;
      default = "${credproxy-pkg}/share/policies";
      description = "Directory containing OPA .rego policy files";
    };

    allowedDomains = mkOption {
      type = types.listOf types.str;
      default = [ ];
      description = "Fail-closed domain allowlist. Only these domains can be proxied.";
      example = [ "api.anthropic.com" "api.openai.com" ];
    };

    credentials = mkOption {
      type = types.listOf (types.attrsOf types.anything);
      default = [ ];
      description = "Credential definitions (placeholder, type, vault_path, bound_domain, header_name, header_prefix)";
    };

    caCertPath = mkOption {
      type = types.path;
      default = caCertPath;
      description = "Runtime path to the MITM CA certificate (for guest trust store)";
      readOnly = true;
    };
  };

  config = mkIf cfg.enable (mkMerge [
    # fw_cfg: pass placeholder config to guest VM when microvm is available.
    # The guest reads this credential at boot via credproxy-placeholder-env.service
    # and writes /run/credproxy/placeholder.env, making fw_cfg the single source
    # of truth for which credential placeholders exist and which env var each maps to.
    (optionalAttrs hasMicrovm {
      microvm.vms.openclaw-vm.config = {
        microvm.credentialFiles."credproxy-placeholder-env" = credentialPlaceholdersJson;
        CUSTOM.virtualisation.openclaw-vm.guest.credentialProxy.fwCfg.enable = true;
      };
    })

    {
      # Static system user for credproxy — needs VSOCK device access
      users.users.credproxy = {
        isSystemUser = true;
        group = "credproxy";
        description = "Credential Proxy Service";
      };
      users.groups.credproxy = { };

      # State directory for CA material and Temporal SQLite DB
      systemd.tmpfiles.rules = [
        "d /var/lib/credproxy 0750 credproxy credproxy -"
        "d ${caDir} 0700 credproxy credproxy -"
      ];

      # Oneshot service: generate MITM CA key+cert at activation time.
      # The private key lives in /var/lib/credproxy/ca/ (0700 credproxy:credproxy),
      # never in the world-readable /nix/store.
      systemd.services.credproxy-ca-init = {
        description = "Generate Credential Proxy MITM CA";
        wantedBy = [ "multi-user.target" ];

        # Only run if the CA cert doesn't already exist (idempotent)
        unitConfig.ConditionPathExists = "!${caCertPath}";

        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
          User = "credproxy";
          Group = "credproxy";
          ExecStart = pkgs.writeShellScript "credproxy-ca-init" ''
            set -euo pipefail
            umask 0077
            ${pkgs.openssl}/bin/openssl ecparam -genkey -name prime256v1 -noout -out ${caKeyPath}
            chmod 0400 ${caKeyPath}
            ${pkgs.openssl}/bin/openssl req -new -x509 -key ${caKeyPath} \
              -out ${caCertPath} \
              -days 3650 \
              -subj "/CN=credproxy MITM CA/O=OpenClaw/OU=Credential Proxy"
            chmod 0444 ${caCertPath}
          '';
        };
      };

      # Temporal dev server (SQLite-backed, no external dependencies)
      systemd.services.credproxy-temporal = {
        description = "Temporal Dev Server for Credential Proxy";
        after = [ "network.target" ];
        wantedBy = [ "multi-user.target" ];

        serviceConfig = {
          Type = "simple";
          User = "credproxy";
          Group = "credproxy";
          ExecStart = "${pkgs.temporal-cli}/bin/temporal server start-dev --port ${toString cfg.temporalPort} --db-filename /var/lib/credproxy/temporal.db --log-format json";
          Restart = "always";
          RestartSec = 5;
          StateDirectory = "credproxy";

          # Hardening
          NoNewPrivileges = true;
          PrivateTmp = true;
          ProtectSystem = "strict";
          ProtectHome = true;
          ProtectKernelTunables = true;
          ProtectKernelModules = true;
          ProtectKernelLogs = true;
          ProtectControlGroups = true;
          RestrictNamespaces = true;
          RestrictSUIDSGID = true;
          LockPersonality = true;
          CapabilityBoundingSet = "";
          AmbientCapabilities = "";
          SystemCallFilter = [ "@system-service" "~@privileged" "~@resources" ];
          SystemCallArchitectures = "native";
        };
      };

      # Credential proxy service (base definition — devMode adds extra deps below)
      systemd.services.credproxy = {
        description = "OpenClaw Credential Proxy";
        after = [
          "network.target"
          "credproxy-temporal.service"
          "credproxy-ca-init.service"
        ];
        requires = [
          "credproxy-temporal.service"
          "credproxy-ca-init.service"
        ];
        wantedBy = [ "multi-user.target" ];

        # Crash protection
        startLimitBurst = 5;
        startLimitIntervalSec = 300;

        serviceConfig = {
          Type = "simple";
          User = "credproxy";
          Group = "credproxy";
          ExecStart = "${credproxy-pkg}/bin/credproxy --config ${configFile}";
          Restart = "always";
          RestartSec = 5;
          RestartSteps = 5;
          RestartMaxDelaySec = "60s";

          # VSOCK device access
          DeviceAllow = [ "/dev/vhost-vsock rw" ];

          # Process isolation
          ProtectProc = "invisible";
          ProcSubset = "pid";
          NoNewPrivileges = true;

          # Filesystem isolation
          ProtectSystem = "strict";
          ProtectHome = true;
          PrivateTmp = true;
          PrivateDevices = false; # Needs /dev/vhost-vsock
          ReadOnlyPaths = [ caDir ];

          # Kernel hardening
          ProtectKernelTunables = true;
          ProtectKernelModules = true;
          ProtectKernelLogs = true;
          ProtectControlGroups = true;

          # Namespace restrictions
          RestrictNamespaces = true;
          RestrictSUIDSGID = true;

          # Memory protection
          LockPersonality = true;

          # Capabilities
          CapabilityBoundingSet = "";
          AmbientCapabilities = "";

          # System call filtering
          SystemCallFilter = [ "@system-service" "~@privileged" "~@resources" ];
          SystemCallArchitectures = "native";
        };
      };
    }

    # --- OpenBao dev mode services ---
    (mkIf cfg.devMode.enable {
      # OpenBao dev server (in-memory, unsealed, root token pre-set)
      systemd.services.credproxy-openbao-dev = {
        description = "OpenBao Dev Server for Credential Proxy";
        after = [ "network.target" ];
        wantedBy = [ "multi-user.target" ];
        serviceConfig = {
          Type = "simple";
          User = "credproxy";
          Group = "credproxy";
          ExecStart = "${pkgs.openbao}/bin/bao server -dev -dev-root-token-id=${cfg.devMode.openbaoToken} -dev-listen-address=127.0.0.1:${toString cfg.devMode.openbaoPort}";
          Restart = "always";
          RestartSec = 5;
          StateDirectory = "credproxy";

          # Hardening (matches credproxy-temporal pattern)
          NoNewPrivileges = true;
          PrivateTmp = true;
          ProtectSystem = "strict";
          ProtectHome = true;
          ProtectKernelTunables = true;
          ProtectKernelModules = true;
          ProtectKernelLogs = true;
          ProtectControlGroups = true;
          RestrictNamespaces = true;
          RestrictSUIDSGID = true;
          LockPersonality = true;
          CapabilityBoundingSet = "";
          AmbientCapabilities = "";
          SystemCallFilter = [ "@system-service" "~@privileged" "~@resources" ];
          SystemCallArchitectures = "native";
        };
      };

      # Oneshot: provision OIDC identity provider + KV v2 sample secrets
      systemd.services.credproxy-openbao-provision = {
        description = "Provision OpenBao OIDC + KV v2 for Credential Proxy";
        after = [ "credproxy-openbao-dev.service" ];
        requires = [ "credproxy-openbao-dev.service" ];
        wantedBy = [ "multi-user.target" ];
        path = [ pkgs.openbao pkgs.jq pkgs.curl ];

        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
          User = "credproxy";
          Group = "credproxy";
        };

        script = let
          port = toString cfg.devMode.openbaoPort;
          token = cfg.devMode.openbaoToken;
        in ''
          set -euo pipefail

          export BAO_ADDR="http://127.0.0.1:${port}"
          export BAO_TOKEN="${token}"

          # Wait for OpenBao to be ready
          for i in $(seq 1 30); do
            if bao status >/dev/null 2>&1; then
              break
            fi
            echo "Waiting for OpenBao to be ready... ($i/30)"
            sleep 1
          done

          # --- OIDC Identity Provider ---

          # 1. Configure OIDC issuer
          bao write identity/oidc/config issuer="http://127.0.0.1:${port}"

          # 2. Create signing key
          bao write identity/oidc/key/credproxy-key \
            rotation_period=24h \
            allowed_client_ids="*"

          # 3. Create identity entity for the VM agent
          ENTITY_ID=$(bao write -format=json identity/entity \
            name="credproxy-agent" \
            metadata=role=agent | jq -r '.data.id')

          # 4. Create OIDC assignment (maps entities to clients)
          bao write identity/oidc/assignment/credproxy-assignment \
            entity_ids="$ENTITY_ID"

          # 5. Create OIDC scope with realm_access template (Keycloak-compatible claims)
          bao write identity/oidc/scope/credproxy-scope \
            template='{"realm_access":{"roles":["credproxy-user"]},"groups":["openclaw-agents"]}'

          # 6. Create confidential OIDC client
          CLIENT_OUTPUT=$(bao write -format=json identity/oidc/client/credproxy \
            key=credproxy-key \
            assignments=credproxy-assignment \
            client_type=confidential \
            id_token_ttl=1h \
            access_token_ttl=1h)
          CLIENT_ID=$(echo "$CLIENT_OUTPUT" | jq -r '.data.client_id')
          CLIENT_SECRET=$(echo "$CLIENT_OUTPUT" | jq -r '.data.client_secret')

          # 7. Create OIDC provider
          bao write identity/oidc/provider/credproxy \
            scopes_supported=credproxy-scope \
            allowed_client_ids="$CLIENT_ID"

          # 8. Write client credentials to file for guest provisioning
          echo "CREDPROXY_CLIENT_ID=$CLIENT_ID" > /var/lib/credproxy/oidc-client.env
          echo "CREDPROXY_CLIENT_SECRET=$CLIENT_SECRET" >> /var/lib/credproxy/oidc-client.env
          chmod 600 /var/lib/credproxy/oidc-client.env

          # --- KV v2 Provisioning ---

          # Enable KV v2 at "secret/" (dev mode may already have this)
          bao secrets enable -path=secret -version=2 kv 2>/dev/null || true

          # Write sample credentials
          bao kv put secret/openclaw/credentials/httpbin \
            key="test-api-key-httpbin-12345" \
            header_name="Authorization" \
            header_prefix="Bearer "

          echo "OpenBao provisioning complete: OIDC + KV v2 configured"
        '';
      };

      # Wire credproxy to start after provisioning completes
      systemd.services.credproxy = {
        after = [ "credproxy-openbao-provision.service" ];
        requires = [ "credproxy-openbao-provision.service" ];
      };
    })

    # devMode guest wiring: virtiofs share for runtime OIDC credentials + guest devMode config
    (mkIf cfg.devMode.enable (optionalAttrs hasMicrovm {
      microvm.vms.openclaw-vm.config = {
        # Share /var/lib/credproxy from host to guest so the guest can read
        # oidc-client.env (written at runtime by the provisioning script).
        microvm.shares = [{
          tag = "credproxy-state";
          source = "/var/lib/credproxy";
          mountPoint = "/mnt/credproxy";
          proto = "virtiofs";
        }];
        # Enable devMode on the guest (auto-configures VSOCK bridge + token URL)
        CUSTOM.virtualisation.openclaw-vm.guest.credentialProxy.devMode.enable = true;
      };
    }))
  ]);
}
