# OpenClaw Secrets Module (Dual-Mode)
# Supports two secrets management modes:
#
# 1. sops-nix Mode (v1 / Fallback):
#    - Secrets encrypted in git, decrypted at boot by sops-nix
#    - Mounted directly into containers from sops paths
#    - Permission-based isolation (container user can read their secrets)
#    - Simple, no additional infrastructure required
#
# 2. Zero-Trust Mode (v2 / Recommended):
#    - Containers have NO credentials
#    - External injector authenticates via Keycloak OIDC
#    - Secrets fetched from OpenBao, written to tmpfs
#    - Cryptographic isolation (container cannot authenticate)
#    - sops-nix still used as trust anchor for Keycloak credentials
#
# When zeroTrust.enable = true, this module provides:
# - sops-nix secrets as FALLBACK if zero-trust injection fails
# - Trust anchor for injector service account credentials
{ config
, pkgs
, lib ? pkgs.lib
, ...
}:
let
  cfg = config.CUSTOM.virtualisation.openclaw;
  secretsCfg = cfg.secrets;

  inherit (lib)
    mkIf
    mkOption
    mkEnableOption
    types
    ;

  # Generate secret definitions for each instance
  mkInstanceSecrets = instanceName: instanceCfg: {
    "openclaw/${instanceName}/api-key" = {
      sopsFile = secretsCfg.sopsFile;
      # Default: per-instance API key (alpha_anthropic_api_key, beta_anthropic_api_key)
      # Override via instance.secrets.apiKeyPath if needed
      key = if instanceCfg.secrets.apiKeyPath != null
            then instanceCfg.secrets.apiKeyPath
            else "${instanceName}_anthropic_api_key";
      owner = instanceCfg.user;
      group = instanceCfg.group;
      mode = "0400";
    };

    "openclaw/${instanceName}/instance-token" = {
      sopsFile = secretsCfg.sopsFile;
      key = "${instanceName}_instance_token";
      owner = instanceCfg.user;
      group = instanceCfg.group;
      mode = "0400";
    };

    "openclaw/${instanceName}/bridge-signing-key" = {
      sopsFile = secretsCfg.sopsFile;
      key = "${instanceName}_bridge_signing_key";
      owner = instanceCfg.user;
      group = instanceCfg.group;
      mode = "0400";
    };
  };

in
{
  options.CUSTOM.virtualisation.openclaw.secrets = {
    enable = mkEnableOption ''
      sops-nix secrets management for OpenClaw.

      This is REQUIRED for both modes:
      - v1 (sops-nix mode): Secrets mounted directly from sops paths
      - v2 (zero-trust mode): sops provides trust anchor for injector credentials

      When zeroTrust.enable = true, sops secrets also serve as fallback
      if zero-trust injection fails.
    '';

    sopsFile = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = ''
        Path to the sops-encrypted secrets file.

        WARNING: Ensure all placeholder values (REPLACE_WITH_*) are replaced with actual secrets.
        Use `sops <file>` to edit the encrypted file securely.
      '';
      example = "/etc/nixos/secrets/openclaw/secrets.yaml";
    };

    ageKeyFile = mkOption {
      type = types.path;
      default = "/var/lib/sops-nix/keys.txt";
      description = "Path to the age private key for decryption";
    };

    mode = mkOption {
      type = types.enum [ "sops" "zero-trust" ];
      default = "sops";
      description = ''
        Secrets management mode:
        - sops: Direct sops-nix secrets (v1, simple)
        - zero-trust: Keycloak + OpenBao with sops fallback (v2, recommended for production)

        Note: Setting this to "zero-trust" automatically enables zeroTrust.enable.
      '';
    };
  };

  config = mkIf cfg.enable {
    # Create the bridge group for shared secret access
    users.groups.openclaw-bridge = { };

    # Ensure the sops-nix key directory exists with correct permissions
    # Created unconditionally so users can generate keys before enabling secrets
    systemd.tmpfiles.rules = [
      "d /var/lib/sops-nix 0700 root root -"
    ];

    # Enable zero-trust mode when secrets.mode is set to "zero-trust"
    CUSTOM.virtualisation.openclaw.zeroTrust.enable =
      lib.mkDefault (secretsCfg.mode == "zero-trust");

    # Assertion to ensure sopsFile is set when secrets are enabled
    assertions = [
      {
        assertion = secretsCfg.enable -> secretsCfg.sopsFile != null;
        message = ''
          CUSTOM.virtualisation.openclaw.secrets.enable is true, but sopsFile is not set.
          Set CUSTOM.virtualisation.openclaw.secrets.sopsFile to your encrypted secrets file.
        '';
      }
    ];

    # Configure sops when secrets are enabled
    sops = mkIf (secretsCfg.enable && secretsCfg.sopsFile != null) {
      defaultSopsFile = secretsCfg.sopsFile;
      age.keyFile = secretsCfg.ageKeyFile;

      # Combine bridge secret with all instance secrets
      secrets = {
        # Shared bridge secret (accessible by bridge service)
        "openclaw/bridge-shared-secret" = {
          sopsFile = secretsCfg.sopsFile;
          key = "bridge_shared_secret";
          path = "/run/secrets/bridge-shared-secret";  # bridge.js expects this path
          owner = "root";
          group = "openclaw-bridge";
          mode = "0440";
        };
      } // (builtins.foldl' (acc: name:
        let instanceCfg = cfg.instances.${name};
        in if instanceCfg.enable
           then acc // (mkInstanceSecrets name instanceCfg)
           else acc
      ) { } (builtins.attrNames cfg.instances));
    };
  };
}
