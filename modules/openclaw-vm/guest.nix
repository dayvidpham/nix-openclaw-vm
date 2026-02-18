# OpenClaw MicroVM Guest Configuration
# Simple microvm that runs openclaw gateway with network access to safemolt
{ config
, pkgs
, pkgs-unstable
, lib ? pkgs.lib
, nix-openclaw
, opencode
, ...
}:
let
  inherit (lib)
    mkOption
    types
    ;

  cfg = config.CUSTOM.virtualisation.openclaw-vm.guest;
  openclaw-pkg = nix-openclaw.packages.${pkgs.system}.openclaw;
  opencode-pkg = opencode.packages.${pkgs.system}.opencode;
  debug-tailscale = import ./debug-tailscale.nix { inherit pkgs; };

  # OpenCode configuration for OpenClaw Gateway
  # Uses localhost since OpenCode runs inside the VM where gateway binds
  # Schema: https://opencode.ai/config.json
  opencode-config = builtins.toJSON {
    "$schema" = "https://opencode.ai/config.json";
    # Custom provider using OpenAI-compatible SDK
    provider = {
      openclaw = {
        npm = "@ai-sdk/openai-compatible";
        name = "OpenClaw Gateway";
        options = {
          baseURL = "http://127.0.0.1:${toString cfg.gatewayPort}/v1";
        };
        models = {
          "openclaw:main" = {
            name = "Claude Sonnet 4 (via OpenClaw)";
            limit = {
              context = 200000;
              output = 16384;
            };
          };
        };
      };
    };
    # Default model uses openclaw provider
    model = "openclaw/openclaw:main";
    small_model = "openclaw/openclaw:main";
  };
in
{
  options.CUSTOM.virtualisation.openclaw-vm.guest = {
    vcpu = mkOption {
      type = types.int;
      default = 2;
      description = "Number of virtual CPUs";
    };

    mem = mkOption {
      type = types.int;
      default = 8192; # 4096 MiB per vCPU with default 2 vCPUs
      description = "Memory allocation in MiB";
    };

    gatewayPort = mkOption {
      type = types.port;
      default = 18789;
      description = "Port for the OpenClaw gateway";
    };

    opencodeServerPort = mkOption {
      type = types.port;
      default = 4096;
      description = "Port for the OpenCode server (clients attach via opencode attach http://localhost:<port>)";
    };

    dangerousDevMode = {
      enable = lib.mkEnableOption ''
        DANGEROUS: Enables debug features that should never be used in production.
        - Auto-login as root on console
        - QEMU guest agent for host command execution
      '';

      autologinUser = mkOption {
        type = types.str;
        default = "openclaw";
        description = "user that the serial console automatically logs into";
      };
    };

    useVirtiofs = mkOption {
      type = types.bool;
      default = false;
      description = ''
        Use virtiofs for /nix/store instead of embedding in erofs image.
        Enables instant rebuilds but requires host's /nix/store at runtime.
        Disable for portable/CI builds (uses erofs for self-contained image).
      '';
    };

    # Network configuration (passed from host)
    network = {
      vmAddress = mkOption {
        type = types.str;
        default = "10.88.0.2";
        description = "VM IP address (should match host cfg.network.vmAddress)";
      };

      gatewayAddress = mkOption {
        type = types.str;
        default = "10.88.0.1";
        description = "Gateway/host bridge IP address";
      };

      prefixLength = mkOption {
        type = types.int;
        default = 24;
        description = "Network prefix length";
      };

      tapInterface = mkOption {
        type = types.str;
        default = "vm-openclaw";
        description = "TAP interface name on the host (must match host-side network config)";
      };

      macAddress = mkOption {
        type = types.str;
        default = "02:00:00:00:00:01";
        description = "MAC address for the guest NIC";
      };
    };

    # State volume configuration
    stateVolumeSize = mkOption {
      type = types.int;
      default = 16384;
      description = "Size of persistent state volume in MiB (default 16 GiB)";
    };

    # VSOCK configuration for host-guest communication
    vsock = {
      cid = mkOption {
        type = types.int;
        default = 4; # CID 3 used by llm-sandbox
        description = ''
          VSOCK Context ID for this VM.
          CID 0 = hypervisor, 1 = loopback, 2 = host, 3+ = guests.
        '';
      };

      port = mkOption {
        type = types.port;
        default = 18789;
        description = "VSOCK port for gateway proxy (matches gateway port for clarity)";
      };
    };

    # Tailscale configuration for remote access
    tailscale = {
      enable = lib.mkEnableOption "Tailscale for secure remote access via tailnet";

      hostname = mkOption {
        type = types.str;
        default = "openclaw-vm";
        description = "Hostname for this machine on the tailnet";
      };

      loginServer = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "Custom control server URL (e.g., Headscale). If null, uses Tailscale's default servers.";
        example = "https://headscale.example.com";
      };

      serve = {
        enable = mkOption {
          type = types.bool;
          default = false; # Disabled: Headscale doesn't support HTTPS cert provisioning (issue #1921)
          description = "Enable Tailscale Serve to expose gateway via HTTPS (requires Tailscale, not Headscale)";
        };
      };

      advertiseTags = mkOption {
        type = types.listOf types.str;
        default = [ "tag:openclaw-vm" ];
        description = "ACL tags to advertise for this node (requires pre-authorized auth key with these tags)";
      };

      exitNode = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "Exit node hostname to route traffic through. Set to null to disable. Set AFTER initial connect via tailscale-post-connect service (not during tailscale up).";
        example = "portal";
      };

      sshAuthorizedKeys = mkOption {
        type = types.listOf types.str;
        default = [ ];
        description = "SSH public keys authorized to connect to the openclaw user";
        example = [ "ssh-ed25519 AAAAC3..." ];
      };
    };
  };

  config = {
    system.stateVersion = "25.11";
    networking.hostName = "openclaw-vm";

    # Restrict fw_cfg sysfs to root only - systemd reads as root, then places
    # credentials in service-specific directory. Prevents compromised agent
    # from reading raw credentials via /sys/firmware/qemu_fw_cfg/
    # NOTE: Cannot blacklist qemu_fw_cfg module - systemd needs sysfs to import credentials
    services.udev.extraRules = ''
      SUBSYSTEM=="firmware", DRIVER=="qemu_fw_cfg", MODE="0400", OWNER="root", GROUP="root"
    '';

    # Static IP configuration for TAP networking
    networking.useDHCP = false;
    # TAP interface appears as enp0s4 (predictable naming: PCI slot 0, device 4)
    networking.interfaces.enp0s4 = {
      ipv4.addresses = [{
        address = cfg.network.vmAddress;
        prefixLength = cfg.network.prefixLength;
      }];
    };
    networking.defaultGateway = {
      address = cfg.network.gatewayAddress;
      interface = "enp0s4";
    };
    # Use host as DNS resolver (more secure - uses host's encrypted DNS config)
    networking.nameservers = [ cfg.network.gatewayAddress ];

    networking.firewall = {
      enable = true;
      # No TCP ports exposed on TAP interface (host uses VSOCK proxy)
      allowedTCPPorts = [ ];
      # Trust Tailscale interface - allows direct gateway access on port ${gatewayPort}
      # (trustedInterfaces bypasses all firewall rules for that interface)
      trustedInterfaces = lib.optionals cfg.tailscale.enable [ "tailscale0" ];
    };

    # SSH access - only via Tailscale (TAP interface blocked by firewall)
    # Hardened config from ipcache-config
    services.openssh = lib.mkIf cfg.tailscale.enable {
      enable = true;
      openFirewall = false; # Only accessible via tailscale0 (trusted interface)

      sftpFlags = [ "-f AUTHPRIV" "-l INFO" ];

      # Pubkey auth only, root allowed in devMode
      settings = {
        PasswordAuthentication = false;
        KbdInteractiveAuthentication = false;
        AuthenticationMethods = "publickey";
        PermitRootLogin = if cfg.dangerousDevMode.enable then "prohibit-password" else "no";
        AllowGroups = [ "ssh-users" ] ++ lib.optionals cfg.dangerousDevMode.enable [ "root" ];
        AllowTcpForwarding = true;

        X11Forwarding = false;
        AllowStreamLocalForwarding = false;
        AllowAgentForwarding = false;

        # Strong ciphers only
        Ciphers = [
          "chacha20-poly1305@openssh.com"
          "aes256-gcm@openssh.com"
          "aes128-gcm@openssh.com"
        ];
      } // lib.optionalAttrs (!cfg.dangerousDevMode.enable) {
        # Only deny root when not in dev mode (empty lists cause sshd config errors)
        DenyUsers = [ "root" ];
        DenyGroups = [ "root" ];
      };

      authorizedKeysInHomedir = false;
      authorizedKeysFiles = [
        "%h/.ssh/authorized_keys"
        "/etc/ssh/authorized_keys.d/%u"
      ];

      # Store host keys on persistent volume so they survive rebuilds
      hostKeys = [
        {
          path = "/var/lib/openclaw/ssh/ssh_host_ed25519_key";
          type = "ed25519";
        }
        {
          path = "/var/lib/openclaw/ssh/ssh_host_rsa_key";
          type = "rsa";
          bits = 4096;
        }
      ];
    };
    users.users.openclaw.openssh.authorizedKeys.keys = lib.mkIf cfg.tailscale.enable
      cfg.tailscale.sshAuthorizedKeys;

    # Dev mode: allow root SSH with same keys
    users.users.root.openssh.authorizedKeys.keys = lib.mkIf (cfg.tailscale.enable && cfg.dangerousDevMode.enable)
      cfg.tailscale.sshAuthorizedKeys;

    # Tailscale for secure remote access
    services.tailscale = lib.mkIf cfg.tailscale.enable {
      enable = true;
      # Auth key injected via fw_cfg, read by systemd LoadCredential
      authKeyFile = "/run/credentials/tailscaled.service/tailscale-authkey";
      extraUpFlags = [
        "--hostname"
        cfg.tailscale.hostname
        "--force-reauth" # Required for ephemeral keys - cached state is stale after node deletion
        "--reset" # Reset preferences to default before applying
        "--exit-node"
        "" # Clear any persisted exit node (post-connect sets it if configured)
        "--ssh" # Enable Tailscale SSH - auth via Tailscale ACLs, no keys needed
      ] ++ lib.optionals (cfg.tailscale.loginServer != null) [
        "--login-server"
        cfg.tailscale.loginServer
      ] ++ lib.optionals (cfg.tailscale.advertiseTags != [ ]) [
        "--advertise-tags"
        (lib.concatStringsSep "," cfg.tailscale.advertiseTags)
      ];
      # Note: exitNode is set separately after connect (see tailscale-post-connect service)
      # Ephemeral state: no persistent state file. Each boot re-auths with ephemeral key.
      # This avoids ghost nodes from --force-reauth creating a new identity while the
      # old identity persists in the state file.
    };

    # Configure tailscaled to read auth key from fw_cfg credential
    systemd.services.tailscaled = lib.mkIf cfg.tailscale.enable {
      serviceConfig = {
        LoadCredential = [ "tailscale-authkey" ];
      };
    };

    # Post-connect configuration: set exit node after tailscale is online
    # Exit node cannot be set during initial `tailscale up` with --force-reauth
    systemd.services.tailscale-post-connect = lib.mkIf (cfg.tailscale.enable && cfg.tailscale.exitNode != null) {
      description = "Configure Tailscale exit node after connection";
      after = [ "tailscaled.service" "tailscaled-autoconnect.service" "network-online.target" ];
      requires = [ "tailscaled.service" "tailscaled-autoconnect.service" ];
      wants = [ "network-online.target" ];
      wantedBy = [ "multi-user.target" ];

      path = [ pkgs.tailscale pkgs.jq ];

      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
      };

      script = ''
        set -euo pipefail

        echo "Waiting for Tailscale to be fully connected..."
        for i in $(seq 1 60); do
          state=$(tailscale status --json 2>/dev/null | jq -r '.BackendState // "Unknown"' || echo "Unknown")
          if [ "$state" = "Running" ]; then
            echo "Tailscale connected (state: $state)"
            break
          fi
          echo "Tailscale state: $state (attempt $i/60)"
          sleep 2
        done

        if [ "$state" != "Running" ]; then
          echo "Timeout waiting for Tailscale to connect"
          exit 1
        fi

        echo "Setting exit node to ${cfg.tailscale.exitNode}..."
        tailscale set --exit-node=${cfg.tailscale.exitNode}
        echo "Exit node configured successfully"
      '';
    };

    # Tailscale Serve: expose gateway via HTTPS
    # Runs after tailscale is online, configures serve to proxy to gateway
    systemd.services.tailscale-serve = lib.mkIf (cfg.tailscale.enable && cfg.tailscale.serve.enable) {
      description = "Configure Tailscale Serve for OpenClaw Gateway";
      after = [ "tailscaled.service" "tailscaled-autoconnect.service" "network-online.target" ];
      requires = [ "tailscaled.service" "tailscaled-autoconnect.service" ];
      wants = [ "network-online.target" ];
      wantedBy = [ "multi-user.target" ];

      path = [ pkgs.tailscale pkgs.jq ];

      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
      };

      # Combined script: wait for Running state, then retry serve command with backoff
      # The HTTPS feature API may return 404/500 until certificates are provisioned
      script = ''
        set -euo pipefail

        echo "Waiting for Tailscale to be fully connected..."
        for i in $(seq 1 60); do
          state=$(tailscale status --json 2>/dev/null | jq -r '.BackendState // "Unknown"' || echo "Unknown")
          if [ "$state" = "Running" ]; then
            echo "Tailscale connected (state: $state)"
            break
          fi
          echo "Tailscale state: $state (attempt $i/60)"
          sleep 2
        done

        if [ "$state" != "Running" ]; then
          echo "Timeout waiting for Tailscale to connect"
          exit 1
        fi

        # Retry serve command - HTTPS feature API may not be ready immediately
        # Returns 404/500 until coordination server provisions certificates
        echo "Configuring Tailscale Serve (with retries for HTTPS readiness)..."
        for i in $(seq 1 30); do
          if tailscale serve --bg --https=443 http://localhost:${toString cfg.gatewayPort} 2>&1; then
            echo "Tailscale Serve configured successfully"
            exit 0
          fi
          echo "Tailscale serve not ready yet (attempt $i/30), waiting..."
          sleep 5
        done

        echo "Timeout waiting for Tailscale Serve to configure"
        exit 1
      '';
    };

    # Shared group for workspace access - both users can read/write workspace files
    users.groups.openclaw-shared = { };

    # Gateway user group
    users.groups.openclaw-gateway = { };

    # OpenCode server group
    users.groups.opencode-server = { };

    # SSH access group (required by AllowGroups in sshd config)
    users.groups.ssh-users = { };

    # Gateway user (system user) - runs gateway service, owns credentials
    # System users cannot login interactively and have no home directory by default
    users.users.openclaw-gateway = {
      isSystemUser = true;
      group = "openclaw-gateway";
      extraGroups = [ "openclaw-shared" ];
      description = "OpenClaw Gateway Service";
    };

    # OpenCode server user (system user) - runs OpenCode server with gateway access
    # Keeps API credentials isolated from interactive openclaw user
    users.users.opencode-server = {
      isSystemUser = true;
      group = "opencode-server";
      extraGroups = [ "openclaw-shared" ];
      description = "OpenCode Server Service";
    };

    # Agent/interactive user (normal user) - interactive sessions, agent processes
    users.users.openclaw = {
      isNormalUser = true;
      home = "/home/openclaw";
      extraGroups = [ "openclaw-shared" ]
        ++ lib.optionals cfg.tailscale.enable [ "ssh-users" ]
        ++ lib.optionals cfg.dangerousDevMode.enable [ "wheel" ];
      description = "OpenClaw Agent";
    };

    # Packages
    environment.systemPackages = [
      openclaw-pkg
      pkgs.curl
      pkgs.jq
      pkgs.git
      pkgs.bun # JavaScript runtime
      pkgs.uv # Python package manager
      opencode-pkg # OpenCode CLI (OpenAI-compatible)
      debug-tailscale # Diagnostic script for Tailscale debugging
    ];

    # OpenClaw gateway service
    systemd.services.openclaw-gateway = {
      description = "OpenClaw Gateway";
      after = [ "network-online.target" ]
        ++ lib.optionals cfg.tailscale.enable [ "tailscaled.service" ];
      wants = [ "network-online.target" ];
      # When tailscale enabled, require it for fail-closed security
      requires = lib.optionals cfg.tailscale.enable [ "tailscaled.service" ];
      wantedBy = [ "multi-user.target" ];

      # Crash protection - prevent resource exhaustion from crash loops
      # 5 failures in 5 minutes triggers cooldown
      startLimitBurst = 5;
      startLimitIntervalSec = 300;

      serviceConfig = {
        Type = "simple";
        User = "openclaw-gateway";
        Group = "openclaw-gateway";
        WorkingDirectory = "/var/lib/openclaw/workspace";
        StateDirectory = "openclaw";
        # Always bind to localhost - external access via:
        # - VSOCK proxy (host access)
        # - Caddy reverse proxy with HTTPS (Tailscale access)
        ExecStart = "${openclaw-pkg}/bin/openclaw gateway --bind auto --port ${toString cfg.gatewayPort}";
        Restart = "always";
        RestartSec = 5;
        RestartSteps = 5;
        RestartMaxDelaySec = "60s";
        # Disabled: openclaw gateway doesn't implement systemd watchdog notifications
        # WatchdogSec = "30s";

        # Load credentials via fw_cfg
        LoadCredential = "openclaw-config";

        # Process isolation - hide gateway from agent's /proc view
        # Prevents compromised agent from seeing gateway process or terminating it
        ProtectProc = "invisible";
        ProcSubset = "pid";
        NoNewPrivileges = true;

        # Filesystem isolation
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        PrivateDevices = true;

        # Kernel hardening
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectKernelLogs = true;
        ProtectControlGroups = true;

        # Namespace restrictions
        RestrictNamespaces = true;
        RestrictSUIDSGID = true;

        # Memory protection
        # NOTE: MemoryDenyWriteExecute incompatible with Node.js V8 JIT
        # V8 requires mprotect(PROT_EXEC) on previously writable memory
        LockPersonality = true;

        # Capabilities
        CapabilityBoundingSet = "";
        AmbientCapabilities = "";

        # System call filtering
        SystemCallFilter = [ "@system-service" "~@privileged" "~@resources" ];
        SystemCallArchitectures = "native";

        # %d = credentials directory
        # HOME points to gateway's config dir, not agent's home
        Environment = [
          "HOME=/var/lib/openclaw"
          "XDG_CONFIG_HOME=/var/lib/openclaw/.config"
          "OPENCLAW_CONFIG_PATH=%d/openclaw-config"
          "OPENCLAW_STATE_DIR=/var/lib/openclaw"
        ];
      };
    };

    # OpenCode server - headless server that clients attach to
    # Runs with gateway credentials so openclaw user doesn't need direct API access
    # Usage: openclaw user runs `opencode attach http://localhost:${cfg.opencodeServerPort}`
    systemd.services.opencode-server = {
      description = "OpenCode Server";
      after = [ "network-online.target" "openclaw-gateway.service" ];
      wants = [ "network-online.target" ];
      # Require gateway - opencode needs it to function
      requires = [ "openclaw-gateway.service" ];
      wantedBy = [ "multi-user.target" ];

      # Crash protection - prevent resource exhaustion from crash loops
      startLimitBurst = 5;
      startLimitIntervalSec = 300;

      serviceConfig = {
        Type = "simple";
        User = "opencode-server";
        Group = "opencode-server";
        WorkingDirectory = "/var/lib/openclaw/workspace";
        # Headless server mode on configured port
        ExecStart = "${opencode-pkg}/bin/opencode serve --port ${toString cfg.opencodeServerPort} --hostname 127.0.0.1";
        Restart = "always";
        RestartSec = 5;
        RestartSteps = 5;
        RestartMaxDelaySec = "60s";

        # Process isolation - hide from agent's /proc view
        ProtectProc = "invisible";
        ProcSubset = "pid";
        NoNewPrivileges = true;

        # Filesystem isolation
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        PrivateDevices = true;
        # ReadWritePaths for opencode's state/cache directories and workspace
        ReadWritePaths = [
          "/var/lib/opencode-server"
          "/var/lib/openclaw/workspace"  # WorkingDirectory - where opencode edits code
        ];

        # Kernel hardening
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectKernelLogs = true;
        ProtectControlGroups = true;

        # Namespace restrictions
        RestrictNamespaces = true;
        RestrictSUIDSGID = true;

        # Memory protection
        # NOTE: MemoryDenyWriteExecute incompatible with Node.js V8 JIT
        LockPersonality = true;

        # Capabilities
        CapabilityBoundingSet = "";
        AmbientCapabilities = "";

        # System call filtering - DISABLED pending proper Bun runtime audit
        # See deferred ticket for re-enabling with correct syscall allowlist
        # SystemCallFilter = [ "@system-service" "~@privileged" "~@resources" ];
        # SystemCallArchitectures = "native";

        # XDG directories for OpenCode - isolated from gateway and agent
        Environment = [
          "HOME=/var/lib/opencode-server"
          "XDG_CONFIG_HOME=/var/lib/opencode-server/.config"
          "XDG_DATA_HOME=/var/lib/opencode-server/.local/share"
          "XDG_CACHE_HOME=/var/lib/opencode-server/.cache"
          "XDG_STATE_HOME=/var/lib/opencode-server/.local/state"
        ];
      };
    };

    # VSOCK gateway proxy - forwards VSOCK connections to gateway's localhost port
    # This allows host connections via VSOCK to appear as localhost to the gateway
    systemd.services.vsock-gateway-proxy = {
      description = "VSOCK to Gateway Localhost Proxy";
      after = [ "network.target" ];
      wantedBy = [ "multi-user.target" ];

      serviceConfig = {
        Type = "simple";
        # Listen on VSOCK port, forward to gateway's localhost port
        ExecStart = "${pkgs.socat}/bin/socat VSOCK-LISTEN:${toString cfg.vsock.port},reuseaddr,fork TCP:127.0.0.1:${toString cfg.gatewayPort}";
        Restart = "always";
        RestartSec = "1s";
        # Hardening - this is just a network proxy
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

    # Caddy reverse proxy for HTTPS access via Tailscale
    # Required because control UI WebSocket needs secure context (HTTPS or localhost)
    # Headscale doesn't support Tailscale Serve HTTPS certs, so we use Caddy with self-signed
    services.caddy = lib.mkIf cfg.tailscale.enable {
      enable = true;
      globalConfig = ''
        auto_https disable_redirects
      '';
      # Use tailscale hostname so Caddy knows what certificate to issue
      virtualHosts."https://${cfg.tailscale.hostname}" = {
        extraConfig = ''
          # Use Caddy's internal CA for HTTPS (self-signed)
          # Clients must trust Caddy's CA or ignore cert errors
          tls internal

          # Reverse proxy to gateway on localhost
          reverse_proxy localhost:${toString cfg.gatewayPort} {
            # WebSocket support for control UI
            header_up Host {host}
            header_up X-Real-IP {remote_host}
            header_up X-Forwarded-For {remote_host}
            header_up X-Forwarded-Proto {scheme}
          }
        '';
      };
      # OpenCode server - browser UI for coding assistant
      virtualHosts."https://${cfg.tailscale.hostname}:${toString cfg.opencodeServerPort}" = {
        extraConfig = ''
          tls internal

          reverse_proxy localhost:${toString cfg.opencodeServerPort} {
            header_up Host {host}
            header_up X-Real-IP {remote_host}
            header_up X-Forwarded-For {remote_host}
            header_up X-Forwarded-Proto {scheme}
          }
        '';
      };
    };

    # Note: Port 443 accessible via Tailscale because tailscale0 is in trustedInterfaces

    # Dev mode only: auto-login as root for debugging/admin access via console
    services.getty.autologinUser = lib.mkIf cfg.dangerousDevMode.enable
      cfg.dangerousDevMode.autologinUser;

    # Dev mode only: QEMU Guest Agent for host-to-guest command execution
    # Use from host: ./scripts/vm-exec.sh "command"
    services.qemuGuest.enable = cfg.dangerousDevMode.enable;

    # Security: no passwordless sudo
    # Dev mode: passwordless sudo for wheel group
    security.sudo.wheelNeedsPassword = !cfg.dangerousDevMode.enable;

    # Security: restrict systemctl/journalctl access for openclaw users
    # Prevents compromised agent from enumerating services or reading system logs
    security.polkit.extraConfig = ''
      polkit.addRule(function(action, subject) {
        // Deny systemd status/control queries for openclaw users
        if (action.id.indexOf("org.freedesktop.systemd1") === 0 &&
            (subject.user === "openclaw" || subject.user === "openclaw-gateway" || subject.user === "opencode-server")) {
          return polkit.Result.NO;
        }
        // Deny reading system journal
        if (action.id === "org.freedesktop.login1.journal-read" &&
            (subject.user === "openclaw" || subject.user === "openclaw-gateway" || subject.user === "opencode-server")) {
          return polkit.Result.NO;
        }
        return polkit.Result.NOT_HANDLED;
      });
    '';

    # Enable getty on ttyS1 for console socket access
    systemd.services."serial-getty@ttyS1".enable = true;

    # microvm configuration
    microvm = {
      hypervisor = "qemu";
      vcpu = cfg.vcpu;
      mem = cfg.mem;

      # VSOCK for host-guest communication (gateway access without TCP/IP)
      vsock = {
        cid = cfg.vsock.cid;
      };

      # Add console socket for interactive access (ttyS1)
      # Connect with: socat -,raw,echo=0 UNIX-CONNECT:console.sock
      qemu.extraArgs = [
        "-chardev"
        "socket,id=console,path=console.sock,server=on,wait=off"
        "-device"
        "isa-serial,chardev=console"
      ] ++ lib.optionals cfg.dangerousDevMode.enable [
        # Dev mode only: QEMU Guest Agent socket for host-to-guest command execution
        # Usage: ./scripts/vm-exec.sh "command"
        "-chardev"
        "socket,id=qga,path=guest-agent.sock,server=on,wait=off"
        "-device"
        "virtio-serial-pci"
        "-device"
        "virtserialport,chardev=qga,name=org.qemu.guest_agent.0"
      ];

      # TAP networking for proper isolation
      interfaces = [{
        type = "tap";
        id = cfg.network.tapInterface;
        mac = cfg.network.macAddress;
      }];

      # Persistent state volume
      volumes = [{
        mountPoint = "/var/lib/openclaw";
        image = "openclaw-state.img";
        size = cfg.stateVolumeSize;
      }];

      # Shares configuration
      shares = lib.optionals cfg.useVirtiofs [{
        # useVirtiofs: mount host's /nix/store via virtiofs (instant rebuilds)
        # Note: /nix/store is read-only by NixOS design (no explicit ro flag needed)
        # virtiofs respects host permissions; /nix/store is immutable on the host
        tag = "nix-store";
        source = "/nix/store";
        mountPoint = "/nix/store";
        proto = "virtiofs";
      }];

      # useVirtiofs: don't embed /nix/store in image (use virtiofs instead)
      storeOnDisk = !cfg.useVirtiofs;

      # erofs: use multi-threaded compression when not using virtiofs
      # -j0 = auto-detect CPU count for parallel compression
      storeDiskErofsFlags = lib.mkIf (!cfg.useVirtiofs) [ "-zlz4hc" "-Eztailpacking" "-j0" ];
    };

    # Create directories for openclaw state
    # Dual-user model:
    # - openclaw-gateway: system user that runs gateway, owns credentials and config
    # - openclaw: normal user for interactive/agent sessions
    # - openclaw-shared: group for shared workspace access
    systemd.tmpfiles.rules = [
      # Gateway user config dirs (owned by gateway, not accessible to agent)
      "d /var/lib/openclaw 0755 openclaw-gateway openclaw-gateway -"
      "d /var/lib/openclaw/.config 0755 openclaw-gateway openclaw-gateway -"
      "d /var/lib/openclaw/.openclaw 0755 openclaw-gateway openclaw-gateway -"
      "d /var/lib/openclaw/.openclaw/canvas 0755 openclaw-gateway openclaw-gateway -"
      "d /var/lib/openclaw/cron 0755 openclaw-gateway openclaw-gateway -"

      # SSH host keys on persistent volume (survive rebuilds)
      "d /var/lib/openclaw/ssh 0700 root root -"
      # Ensure private keys are read-only (sshd only needs to read them)
      "z /var/lib/openclaw/ssh/ssh_host_ed25519_key 0400 root root -"
      "z /var/lib/openclaw/ssh/ssh_host_rsa_key 0400 root root -"

      # Shared workspace with setgid for group ownership
      # Mode 2775: rwxrwsr-x - setgid ensures new files inherit openclaw-shared group
      # Both gateway and agent can read/write, but gateway's credentials stay protected
      "d /var/lib/openclaw/workspace 2775 root openclaw-shared -"
      # Z = recursive ownership fix for existing files (from before dual-user migration)
      "Z /var/lib/openclaw/workspace - root openclaw-shared -"

      # OpenCode server directories (isolated from gateway and agent)
      "d /var/lib/opencode-server 0750 opencode-server opencode-server -"
      "d /var/lib/opencode-server/.config 0750 opencode-server opencode-server -"
      "d /var/lib/opencode-server/.config/opencode 0750 opencode-server opencode-server -"
      "d /var/lib/opencode-server/.local 0750 opencode-server opencode-server -"
      "d /var/lib/opencode-server/.local/share 0750 opencode-server opencode-server -"
      "d /var/lib/opencode-server/.local/share/opencode 0750 opencode-server opencode-server -"
      "d /var/lib/opencode-server/.local/state 0750 opencode-server opencode-server -"
      "d /var/lib/opencode-server/.local/state/opencode 0750 opencode-server opencode-server -"
      "d /var/lib/opencode-server/.cache 0750 opencode-server opencode-server -"
      "d /var/lib/opencode-server/.cache/opencode 0750 opencode-server opencode-server -"
      # OpenCode config pointing to local OpenClaw Gateway (same config as agent user)
      "f /var/lib/opencode-server/.config/opencode/config.json 0640 opencode-server opencode-server - ${opencode-config}"

      # Agent user home directories
      "d /home/openclaw 0755 openclaw users -"
      "d /home/openclaw/.openclaw 0755 openclaw users -"
      "d /home/openclaw/.config 0755 openclaw users -"
      "d /home/openclaw/.config/opencode 0755 openclaw users -"
      # OpenCode config pointing to local OpenClaw Gateway
      "f /home/openclaw/.config/opencode/config.json 0644 openclaw users - ${opencode-config}"
      # SSH directory for authorized_keys (Tailscale SSH doesn't need this, but regular SSH does)
      "d /home/openclaw/.ssh 0700 openclaw users -"
    ];
  };
}
