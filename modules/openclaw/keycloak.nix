# OpenClaw Keycloak Configuration
# This module CONFIGURES the standalone Keycloak module
# with OpenClaw-specific settings. It is a thin wrapper, not an implementation.
#
# IMPORTANT: The consuming flake must include BOTH this module AND the
# standalone keycloak module (modules/nixos/virtualisation/keycloak) in
# its module tree. This module only SETS options, it does not DEFINE them.
{ config
, pkgs
, lib ? pkgs.lib
, ...
}:
let
  cfg = config.CUSTOM.virtualisation.openclaw;
  keycloakCfg = cfg.zeroTrust.keycloak;
  enabledInstances = lib.filterAttrs (n: v: v.enable) cfg.instances;

  inherit (lib)
    mkIf
    mkOption
    mkEnableOption
    types
    ;

in
{
  # OpenClaw-specific Keycloak options (thin wrapper)
  options.CUSTOM.virtualisation.openclaw.zeroTrust.keycloak = {
    enable = mkEnableOption "Keycloak identity provider for OpenClaw zero-trust secrets";

    adminPasswordFile = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "Path to file containing Keycloak admin password";
    };

    postgresPasswordFile = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "Path to file containing PostgreSQL password";
    };
  };

  # Configure the standalone module with OpenClaw-specific values
  config = mkIf (cfg.enable && cfg.zeroTrust.enable && keycloakCfg.enable) {
    assertions = [{
      assertion = config.CUSTOM.virtualisation ? keycloak;
      message = "openclaw keycloak wrapper requires the standalone keycloak module. Add it to your flake's module imports.";
    }];

    CUSTOM.virtualisation.keycloak = {
      enable = true;
      realm = "openclaw";
      clients = builtins.attrNames enabledInstances;
      clientIdPrefix = "openclaw-injector";
      dataDir = /var/lib/openclaw/keycloak;
      clientSecretsDir = /var/lib/openclaw/keycloak/client-secrets;
      servicePrefix = "openclaw-keycloak";
      network = {
        name = "openclaw-secrets";
        subnet = "10.90.0.0/24";
        gateway = "10.90.0.1";
      };
      adminPasswordFile = keycloakCfg.adminPasswordFile;
      postgres.passwordFile = keycloakCfg.postgresPasswordFile;
    };
  };
}
