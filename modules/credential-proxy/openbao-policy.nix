# Credential Proxy OpenBao Policy
# Configures a read-only policy for the credential proxy to fetch secrets
# from OpenBao's KV v2 store.
#
# Pattern follows modules/openclaw/openbao.nix:
# - Thin wrapper that SETS options on the standalone openbao module
# - Policy scoped to secret/data/openclaw/credentials/*
{ config
, pkgs
, lib ? pkgs.lib
, ...
}:
let
  cfg = config.CUSTOM.virtualisation.openclaw-vm.credentialProxy;

  inherit (lib)
    mkIf
    ;
in
{
  config = mkIf cfg.enable {
    assertions = [
      {
        assertion = config.CUSTOM.virtualisation ? openbao;
        message = "Credential proxy OpenBao policy requires the standalone openbao module. Add it to your flake's module imports.";
      }
    ];

    CUSTOM.virtualisation.openbao = {
      policies = [
        {
          name = "credproxy-readonly";
          paths = [
            "secret/data/openclaw/credentials/*"
            "secret/metadata/openclaw/credentials/*"
          ];
          capabilities = [ "read" "list" ];
        }
      ];
    };
  };
}
