# OpenClaw Inter-Instance Communication Bridge
# Provides authenticated RPC for task delegation and shared context management
{ config
, pkgs
, lib ? pkgs.lib
, ...
}:
let
  cfg = config.CUSTOM.virtualisation.openclaw;
  bridgeCfg = cfg.bridge;

  inherit (lib)
    mkIf
    mkOption
    mkEnableOption
    types
    ;

  # Reference the external JavaScript file
  bridgeScript = ./scripts/bridge.js;

in
{
  options.CUSTOM.virtualisation.openclaw.bridge = {
    enable = mkEnableOption "OpenClaw inter-instance communication bridge" // {
      default = true;
    };

    port = mkOption {
      type = types.port;
      default = 18800;
      description = "Port for the bridge RPC service (localhost only)";
    };

    rateLimit = mkOption {
      type = types.int;
      default = 60;
      description = "Maximum requests per minute per instance";
    };

    maxDelegationDepth = mkOption {
      type = types.int;
      default = 5;
      description = "Maximum depth of task delegation chain";
    };

    auditLogPath = mkOption {
      type = types.str;
      default = "/var/log/openclaw/bridge-audit.log";
      description = "Path to the bridge audit log file";
    };
  };

  config = mkIf (cfg.enable && bridgeCfg.enable) {
    # Create dedicated system user for the bridge service
    users.users.openclaw-bridge = {
      isSystemUser = true;
      group = "openclaw-bridge";
      description = "OpenClaw bridge service user";
    };

    # Create bridge audit log file (log directory created by openbao.nix)
    systemd.tmpfiles.rules = [
      "f ${bridgeCfg.auditLogPath} 0640 openclaw-bridge openclaw-bridge -"
    ];

    # Bridge service
    systemd.services.openclaw-bridge = {
      description = "OpenClaw Inter-Instance Communication Bridge";
      after = [
        "network.target"
      ] ++ (if cfg.secrets.enable then [ "sops-nix.service" ] else [ ]);
      wantedBy = [ "multi-user.target" ];

      environment = {
        BRIDGE_PORT = toString bridgeCfg.port;
        SHARED_CONTEXT_PATH = "/var/lib/openclaw/shared-context";
        AUDIT_LOG_PATH = bridgeCfg.auditLogPath;
        RATE_LIMIT = toString bridgeCfg.rateLimit;
        MAX_DELEGATION_DEPTH = toString bridgeCfg.maxDelegationDepth;
      };

      serviceConfig = {
        Type = "simple";
        Restart = "always";
        RestartSec = "5s";

        # Run as dedicated non-root user
        User = "openclaw-bridge";
        Group = "openclaw-bridge";

        # Security hardening
        NoNewPrivileges = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        PrivateDevices = true;

        # Required paths
        ReadWritePaths = [
          "/var/lib/openclaw/shared-context"
          "/var/log/openclaw"
        ];
        ReadOnlyPaths = mkIf cfg.secrets.enable [
          config.sops.secrets."openclaw/bridge-shared-secret".path
        ];

        ExecStart = "${pkgs.nodejs_22}/bin/node ${bridgeScript}";
      };

      # Note: sops-nix creates /run/secrets/bridge-shared-secret directly
      # (configured in secrets.nix with path = "/run/secrets/bridge-shared-secret")
    };
  };
}
