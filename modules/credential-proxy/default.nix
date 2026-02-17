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
      issuer_url = cfg.oidcIssuerURL;
      audience = cfg.oidcAudience;
    };
    opa = {
      policy_dir = cfg.policyDir;
    };
    vault = {
      address = cfg.vaultAddress;
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

      # Credential proxy service
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
  ]);
}
