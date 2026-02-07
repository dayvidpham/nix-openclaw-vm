# OpenClaw Instance Configuration
# Defines per-instance options and generates Podman container services
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
    mkMerge
    types
    mapAttrs
    mapAttrs'
    nameValuePair
    filterAttrs
    concatStringsSep
    optionalString
    attrValues
    ;

  # Instance option type definition
  instanceOptions = { name, config, ... }: {
    options = {
      enable = mkEnableOption "this OpenClaw instance";

      user = mkOption {
        type = types.str;
        default = "openclaw-${name}";
        description = "System user to run this instance";
      };

      group = mkOption {
        type = types.str;
        default = "openclaw-${name}";
        description = "System group for this instance";
      };

      workspace = {
        path = mkOption {
          type = types.str;
          default = "/var/lib/openclaw/${name}/workspace";
          description = "Host path for the instance's isolated workspace";
        };

        configPath = mkOption {
          type = types.str;
          default = "/var/lib/openclaw/${name}/config";
          description = "Host path for instance configuration files";
        };

        sharedContextPath = mkOption {
          type = types.str;
          default = "/var/lib/openclaw/shared-context";
          description = "Host path for shared context store (read-only mount)";
        };
      };

      ports = {
        webchat = mkOption {
          type = types.port;
          description = "Port for WebChat UI";
          example = 3000;
        };

        gateway = mkOption {
          type = types.port;
          description = "Port for Gateway WebSocket";
          example = 18789;
        };
      };

      secrets = {
        apiKeyPath = mkOption {
          type = types.nullOr types.str;
          default = null;
          description = "sops key path for Anthropic API key (null = use shared key)";
        };
      };

      resources = {
        memoryLimit = mkOption {
          type = types.str;
          default = "4g";
          description = "Memory limit for the container";
        };

        cpuLimit = mkOption {
          type = types.str;
          default = "2.0";
          description = "CPU limit for the container (number of CPUs)";
        };
      };

      openclaw = {
        agentName = mkOption {
          type = types.str;
          default = name;
          description = "Name of the OpenClaw agent";
        };

        sandboxMode = mkOption {
          type = types.enum [ "all" "none" "tools-only" ];
          default = "all";
          description = "Sandbox mode for tool execution";
        };

        extraConfig = mkOption {
          type = types.attrs;
          default = { };
          description = "Additional OpenClaw configuration options";
        };
      };
    };
  };

  # Generate container service for an instance
  mkInstanceService = name: instanceCfg: {
    "podman-openclaw-${name}" = {
      description = "OpenClaw instance ${name}";
      after = [
        "podman.service"
      ] ++ (if cfg.zeroTrust.enable && cfg.zeroTrust.injector.enable then [
        # Zero-trust: wait for injector to complete secrets injection
        "openclaw-injector-${name}.service"
      ] else if cfg.secrets.enable then [
        "sops-nix.service"
      ] else []);
      requires = [ "podman.service" ]
        ++ (if cfg.zeroTrust.enable && cfg.zeroTrust.injector.enable then [
          "openclaw-injector-${name}.service"
        ] else []);
      wantedBy = [ "multi-user.target" ];

      # Include /run/wrappers/bin for newuidmap/newgidmap setuid wrappers
      # Note: NixOS automatically appends /bin and /sbin to path entries
      path = [
        pkgs.podman
        "/run/wrappers"
      ];

      # Environment for rootless podman (system users don't have a login session)
      environment = {
        XDG_RUNTIME_DIR = "/run/openclaw-${name}";
        # Use cgroupfs instead of systemd cgroup manager - system services can't access
        # the user's D-Bus socket at /run/user/<uid>/bus needed for systemd cgroups
        CONTAINERS_CGROUP_MANAGER = "cgroupfs";
      };

      serviceConfig = {
        Type = "simple";
        Restart = "always";
        RestartSec = "10s";

        # Run as dedicated user (rootless podman)
        User = instanceCfg.user;
        Group = instanceCfg.group;

        # Runtime directory for rootless podman (system users don't have /run/user/<uid>)
        RuntimeDirectory = "openclaw-${name}";
        RuntimeDirectoryMode = "0700";

        # Security hardening
        # NoNewPrivileges = true;  # Disabled: blocks newuidmap setuid binary needed for rootless podman
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;

        # Allow access to required paths
        ReadWritePaths = [
          instanceCfg.workspace.path
          instanceCfg.workspace.configPath
          "/var/lib/openclaw/${name}/.config"
          "/var/lib/openclaw/${name}/.local"  # Podman rootless storage
        ];
        ReadOnlyPaths = [
          instanceCfg.workspace.sharedContextPath
        ] ++ (if cfg.zeroTrust.enable && cfg.zeroTrust.injector.enable then [
          # Zero-trust: secrets directory is managed by injector
          "/run/openclaw-${name}/secrets"
        ] else if cfg.secrets.enable then [
          config.sops.secrets."openclaw/${name}/api-key".path
          config.sops.secrets."openclaw/${name}/instance-token".path
          config.sops.secrets."openclaw/${name}/bridge-signing-key".path
        ] else [ ]) ++ (if cfg.container.registry == "" then [
          cfg.container.image  # Allow access to container image in Nix store
        ] else [ ]);
      } // {
        # Setup for rootless podman (per-user image and network storage)
        ExecStartPre = pkgs.writeShellScript "openclaw-${name}-setup" ''
          set -euo pipefail

          # Create network for this user (rootless podman has per-user networks)
          if ! ${pkgs.podman}/bin/podman network exists ${cfg.network.bridgeNetwork.name} 2>/dev/null; then
            echo "Creating network ${cfg.network.bridgeNetwork.name} for user ${instanceCfg.user}..."
            ${pkgs.podman}/bin/podman network create \
              --driver bridge \
              --subnet ${cfg.network.bridgeNetwork.subnet} \
              --gateway ${cfg.network.bridgeNetwork.gateway} \
              --internal \
              ${cfg.network.bridgeNetwork.name}
          fi

          ${if cfg.container.registry == "" then ''
          # Load image (rootless podman has per-user image storage)
          # Always reload to pick up Nix store path changes (image hash changes on rebuild)
          CURRENT_IMAGE_ID=$(${pkgs.podman}/bin/podman images -q localhost/openclaw:latest 2>/dev/null || true)
          NEW_IMAGE_ID=$(${pkgs.podman}/bin/podman load -q -i ${cfg.container.image})

          if [ -n "$CURRENT_IMAGE_ID" ] && [ "$CURRENT_IMAGE_ID" != "$NEW_IMAGE_ID" ]; then
            echo "Image updated: removing old image $CURRENT_IMAGE_ID"
            ${pkgs.podman}/bin/podman rmi "$CURRENT_IMAGE_ID" 2>/dev/null || true
          fi
          '' else ""}
        '';
      } // {
        ExecStart = pkgs.writeShellScript "openclaw-${name}-start" ''
          set -euo pipefail

          # Build container arguments
          CONTAINER_ARGS=(
            --name "openclaw-${name}"
            --replace

            # Network configuration
            --network ${cfg.network.bridgeNetwork.name}
            --publish "127.0.0.1:${toString instanceCfg.ports.webchat}:3000"
            --publish "127.0.0.1:${toString instanceCfg.ports.gateway}:18789"

            # Resource limits
            --memory "${instanceCfg.resources.memoryLimit}"
            --cpus "${instanceCfg.resources.cpuLimit}"

            # Security hardening
            --read-only
            --security-opt "no-new-privileges:true"
            --security-opt "seccomp=${cfg.container.seccompProfile}"
            --cap-drop ALL
            --userns keep-id

            # Disable healthcheck - requires systemd user session for timers
            # which isn't available for system services running as system users
            --no-healthcheck

            # Volume mounts
            --volume "${instanceCfg.workspace.path}:/workspace:rw"
            --volume "${instanceCfg.workspace.configPath}:/config:rw"
            --volume "/var/lib/openclaw/${name}/.config:/home/openclaw/.config:rw"
            --volume "${instanceCfg.workspace.sharedContextPath}:/shared-context:ro"

            # Secrets mounts (from tmpfs)
            # Zero-trust mode: secrets injected by external service to /run/openclaw-${name}/secrets/
            # Legacy mode: secrets mounted directly from sops-nix paths
            ${if cfg.zeroTrust.enable && cfg.zeroTrust.injector.enable then ''
            --volume "/run/openclaw-${name}/secrets:/run/secrets:ro"
            '' else optionalString cfg.secrets.enable ''
            --volume "${config.sops.secrets."openclaw/${name}/api-key".path}:/run/secrets/api-key:ro"
            --volume "${config.sops.secrets."openclaw/${name}/instance-token".path}:/run/secrets/instance-token:ro"
            --volume "${config.sops.secrets."openclaw/${name}/bridge-signing-key".path}:/run/secrets/bridge-signing-key:ro"
            ''}

            # Environment
            --env "OPENCLAW_AGENT_NAME=${instanceCfg.openclaw.agentName}"
            --env "OPENCLAW_SANDBOX_MODE=${instanceCfg.openclaw.sandboxMode}"
            --env "NODE_ENV=production"

            # Labels
            --label "openclaw.instance=${name}"
            --label "openclaw.managed=true"
          )

          # Use local image or registry
          ${if cfg.container.registry != "" then ''
          IMAGE="${cfg.container.registry}"
          '' else ''
          IMAGE="localhost/openclaw:latest"
          ''}

          exec ${pkgs.podman}/bin/podman run "''${CONTAINER_ARGS[@]}" "$IMAGE"
        '';

        ExecStop = "${pkgs.podman}/bin/podman stop -t 30 openclaw-${name}";
        ExecStopPost = "${pkgs.podman}/bin/podman rm -f openclaw-${name} || true";
      };
    };
  };

  # Get all enabled instances
  enabledInstances = filterAttrs (n: v: v.enable) cfg.instances;

in
{
  options.CUSTOM.virtualisation.openclaw = {
    instances = mkOption {
      type = types.attrsOf (types.submodule instanceOptions);
      default = { };
      description = "OpenClaw instance configurations";
      example = {
        alpha = {
          enable = true;
          ports.webchat = 3000;
          ports.gateway = 18789;
        };
        beta = {
          enable = true;
          ports.webchat = 3001;
          ports.gateway = 18790;
        };
      };
    };

    subuidBase = mkOption {
      type = types.int;
      default = 300000;
      description = "Base subuid for OpenClaw instance users. Each instance gets 65536 UIDs starting from base + (index * 65536). Avoids conflict with other system users (minttea/gitlab-runner use 100000-265534).";
    };
  };

  config = mkIf cfg.enable {
    # Create system users for each instance (keyed by user name, not instance name)
    # Each user gets subuid/subgid ranges for rootless podman
    users.users = builtins.listToAttrs (lib.imap0 (idx: name:
      let
        instanceCfg = enabledInstances.${name};
        # Each instance gets 65536 subuids starting at cfg.subuidBase + (idx * 65536)
        subuidStart = cfg.subuidBase + (idx * 65536);
      in {
        name = instanceCfg.user;
        value = {
          isSystemUser = true;
          group = instanceCfg.group;
          home = "/var/lib/openclaw/${name}";
          createHome = true;
          description = "OpenClaw ${name} instance user";
          # Add to openclaw-bridge group for shared secret access
          extraGroups = [ "openclaw-bridge" ];
          # Enable linger for rootless podman (requires security.polkit.enable)
          linger = true;
          # Subuid/subgid ranges for rootless podman
          subUidRanges = [{ startUid = subuidStart; count = 65536; }];
          subGidRanges = [{ startGid = subuidStart; count = 65536; }];
        };
      }
    ) (builtins.attrNames enabledInstances));

    # Create groups for each instance (keyed by group name)
    users.groups = builtins.listToAttrs (builtins.map (name:
      let instanceCfg = enabledInstances.${name};
      in { name = instanceCfg.group; value = { }; }
    ) (builtins.attrNames enabledInstances));

    # Create required directories
    systemd.tmpfiles.rules = (builtins.concatMap (name:
      let instanceCfg = enabledInstances.${name};
      in [
        "d ${instanceCfg.workspace.path} 0750 ${instanceCfg.user} ${instanceCfg.group} -"
        "d ${instanceCfg.workspace.configPath} 0750 ${instanceCfg.user} ${instanceCfg.group} -"
        "d /var/lib/openclaw/${name}/.config 0750 ${instanceCfg.user} ${instanceCfg.group} -"
        "d /var/lib/openclaw/${name}/.local 0750 ${instanceCfg.user} ${instanceCfg.group} -"
      ]
    ) (builtins.attrNames enabledInstances)) ++ [
      # Shared context directory (writable by gatekeeper, readable by all)
      "d /var/lib/openclaw/shared-context 0755 root openclaw-bridge -"
    ];

    # Generate systemd services for each enabled instance + image loader
    systemd.services = (builtins.foldl' (acc: name:
      acc // (mkInstanceService name enabledInstances.${name})
    ) { } (builtins.attrNames enabledInstances)) // (lib.optionalAttrs (cfg.container.registry == "") {
      # Load container image into podman (if using local build)
      openclaw-image-load = {
        description = "Load OpenClaw container image into Podman";
        after = [ "podman.service" ];
        requires = [ "podman.service" ];
        before = builtins.map (n: "podman-openclaw-${n}.service") (builtins.attrNames enabledInstances);
        wantedBy = [ "multi-user.target" ];

        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
          ExecStart = "${pkgs.podman}/bin/podman load -i ${cfg.container.image}";
        };
      };
    });
  };
}
