# OpenClaw MicroVM Host Configuration
# This module configures the host to run the openclaw-vm microVM.
# The guest configuration is defined in ./guest.nix
#
# Architecture:
# - Host runs zero-trust infrastructure (Keycloak + OpenBao) or sops fallback
# - Secrets passed to VM via fw_cfg (microvm.credentialFiles)
# - Guest services load credentials via systemd LoadCredential
# - Gateway binds to localhost only inside VM (security requirement)
# - Host accesses gateway via VSOCK (appears as localhost to guest)
# - Gateway accessible at localhost:18789 on host via VSOCK proxy
# - Optional Caddy provides HTTPS at localhost:8443
{ config
, options
, pkgs
, pkgs-unstable
, lib ? pkgs.lib
, nix-openclaw
, opencode
, ...
}:
let
  cfg = config.CUSTOM.virtualisation.openclaw-vm;
  hasMicrovm = options ? microvm;

  inherit (lib)
    mkIf
    mkMerge
    mkOption
    mkEnableOption
    optionalAttrs
    types
    ;

  # Console access script for the microVM
  vm-console = pkgs.writeShellScriptBin "openclaw-vm-console" ''
    set -euo pipefail

    SOCKET_PATH="/var/lib/microvms/openclaw-vm/console.sock"

    if [[ ! -S "$SOCKET_PATH" ]]; then
        echo "Error: Console socket not found at $SOCKET_PATH" >&2
        echo "Is the VM running? Check: systemctl status microvm@openclaw-vm" >&2
        exit 1
    fi

    echo "Connecting to openclaw-vm console..."
    echo "Press Ctrl+] to exit"
    echo "---"

    exec ${pkgs.socat}/bin/socat -,raw,echo=0,escape=0x1d UNIX-CONNECT:"$SOCKET_PATH"
  '';
in
{
  options.CUSTOM.virtualisation.openclaw-vm = {
    enable = mkEnableOption "OpenClaw in microVM";

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

    # Gateway configuration
    gatewayPort = mkOption {
      type = types.port;
      default = 18789;
      description = "Port for OpenClaw gateway (forwarded to VM)";
    };

    # Resource limits
    memory = mkOption {
      type = types.int;
      default = 8192; # 4096 MiB per vCPU with default 2 vCPUs
      description = "Memory allocation in MiB for the microVM";
    };

    vcpu = mkOption {
      type = types.int;
      default = 2;
      description = "Virtual CPU count";
    };

    # Secrets integration
    secrets = {
      enable = mkEnableOption "Inject secrets from host zero-trust infrastructure";

      sopsFile = mkOption {
        type = types.nullOr types.path;
        default = null;
        description = "Path to sops secrets file for fallback secrets";
      };

      ageKeyFile = mkOption {
        type = types.path;
        default = /var/lib/sops-nix/keys.txt;
        description = ''
          DEPRECATED: This option is no longer used. Configure sops.age.keyFile
          directly in your host configuration if needed.

          Path to age key file for sops decryption.
        '';
      };
    };

    # State management
    stateDir = mkOption {
      type = types.path;
      default = /var/lib/microvms/openclaw-vm/state;
      description = "Host path for VM persistent state volume";
    };

    # Caddy reverse proxy configuration
    caddy = {
      enable = mkEnableOption "Caddy reverse proxy with HTTPS for the gateway";

      domain = mkOption {
        type = types.str;
        default = "localhost";
        description = "Domain name for the gateway (default: localhost)";
      };

      httpsPort = mkOption {
        type = types.port;
        default = 8443;
        description = "HTTPS port for Caddy (default: 8443 to avoid conflicts with existing services)";
      };

      httpPort = mkOption {
        type = types.port;
        default = 8080;
        description = "HTTP port for Caddy (redirects to HTTPS)";
      };

      internalCa = mkOption {
        type = types.bool;
        default = true;
        description = ''
          Use Caddy's internal CA for localhost HTTPS.
          For browser trust, run: caddy trust (requires root, installs CA to system store).
          Set to false if using a real domain with ACME/Let's Encrypt.
        '';
      };
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
      enable = mkEnableOption "Tailscale inside the VM for remote access via tailnet";

      hostname = mkOption {
        type = types.str;
        default = "openclaw-vm";
        description = "Hostname for the VM on the tailnet";
      };

      loginServer = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "Custom control server URL (e.g., Headscale). If null, uses Tailscale's default servers.";
        example = "https://headscale.example.com";
      };

      exitNode = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "Exit node hostname to route traffic through. Set AFTER initial connect via tailscale-post-connect service.";
        example = "portal";
      };

      serve = {
        enable = mkOption {
          type = types.bool;
          default = true;
          description = "Enable Tailscale Serve to expose gateway via HTTPS";
        };
      };

      sshAuthorizedKeys = mkOption {
        type = types.listOf types.str;
        default = [ ];
        description = "SSH public keys authorized to connect to the openclaw user";
        example = [ "ssh-ed25519 AAAAC3..." ];
      };
    };

    # Network configuration
    network = {
      bridgeName = mkOption {
        type = types.str;
        default = "br-openclaw"; # Max 15 chars for Linux interface names
        description = "Name of the bridge interface for VM networking";
      };

      bridgeAddress = mkOption {
        type = types.str;
        default = "10.88.0.1/24";
        description = "Host bridge IP address and subnet";
      };

      vmAddress = mkOption {
        type = types.str;
        default = "10.88.0.2";
        description = "VM IP address (used for port forwarding)";
      };

      tapInterface = mkOption {
        type = types.str;
        default = "vm-openclaw";
        description = "Name of the TAP interface (must match guest.nix)";
      };
    };
  };

  config = mkIf cfg.enable (mkMerge [
    # Host-side config (works without microvm module)
    {
      # Dedicated group for secrets access
      users.groups.openclaw-secrets = { };

      # Grant microvm user access to secrets via group membership
      users.users.microvm.extraGroups = [ "openclaw-secrets" ];

      # State dir: 0750 root:kvm - microvm user (in kvm group) needs access
      systemd.tmpfiles.rules = [
        "d ${toString cfg.stateDir} 0750 root kvm -"
      ];

      # Console access script
      environment.systemPackages = [ vm-console ];

      # Assertions
      assertions = [
        {
          assertion = hasMicrovm;
          message = "OpenClaw VM requires microvm.nix. Ensure microvm module is available.";
        }
        {
          assertion = !(cfg.secrets.enable && cfg.secrets.sopsFile != null) || (options ? sops);
          message = "OpenClaw VM secrets require sops-nix module. Add sops-nix to your imports.";
        }
        {
          assertion = !(
            cfg.secrets.enable &&
            cfg.secrets.sopsFile != null &&
            config.CUSTOM.virtualisation.openclaw.zeroTrust.injector.vmMode.enable or false
          );
          message = ''
            Cannot use both sops.templates secrets (cfg.secrets.sopsFile) and injector.vmMode simultaneously.
            Both would try to provide credentials to the microVM.
            Choose one:
            - For zero-trust injection: enable CUSTOM.virtualisation.openclaw.zeroTrust.injector.vmMode
            - For sops-only: set cfg.secrets.sopsFile and disable injector.vmMode
          '';
        }
      ];

      # TAP networking configuration
      # systemd-networkd for TAP interface bridge
      systemd.network.enable = true;

      # Bridge device for microVM networking
      systemd.network.netdevs."10-microvm-openclaw" = {
        netdevConfig = {
          Kind = "bridge";
          Name = cfg.network.bridgeName;
        };
      };

      # Bridge network configuration
      systemd.network.networks."10-microvm-openclaw" = {
        matchConfig.Name = cfg.network.bridgeName;
        address = [ cfg.network.bridgeAddress ];
        linkConfig.RequiredForOnline = "no";
      };

      # Enable IP forwarding for VM networking
      # Use loose rp_filter on bridge to allow VM traffic (strict mode can block bridged packets)
      boot.kernel.sysctl = {
        "net.ipv4.ip_forward" = 1;
        "net.ipv4.conf.br-openclaw.rp_filter" = 0; # Disable for bridge (nftables rpfilter handles it)
      };

      # Enable DNS forwarding for VM (systemd-resolved)
      # VM uses host as DNS resolver for security (encrypted DNS, logging)
      services.resolved = {
        enable = true;
        settings.Resolve.DNSStubListenerExtra =
          lib.head (lib.splitString "/" cfg.network.bridgeAddress);
      };

      # Allow only DNS from VM to host (not full interface trust)
      networking.firewall.extraInputRules = ''
        ip saddr ${cfg.network.bridgeAddress} udp dport 53 accept
        ip saddr ${cfg.network.bridgeAddress} tcp dport 53 accept
      '';

      # Attach TAP interface to bridge
      systemd.network.networks."11-microvm-openclaw-tap" = {
        matchConfig.Name = cfg.network.tapInterface;
        bridge = [ cfg.network.bridgeName ];
        linkConfig.RequiredForOnline = "no";
      };

      # Ensure vhost-vsock module is loaded for VSOCK communication
      boot.kernelModules = [ "vhost_vsock" ];

      # Localhost proxy to VM gateway via VSOCK
      # VSOCK connections appear as localhost to the guest, satisfying gateway security
      systemd.services.openclaw-gateway-proxy = {
        description = "Proxy localhost:${toString cfg.gatewayPort} to VM gateway via VSOCK";
        after = [ "microvm@openclaw-vm.service" ];
        requires = [ "microvm@openclaw-vm.service" ];
        wantedBy = [ "multi-user.target" ];

        serviceConfig = {
          Type = "simple";
          # Forward localhost TCP to VSOCK (CID:port)
          ExecStart = "${pkgs.socat}/bin/socat TCP-LISTEN:${toString cfg.gatewayPort},bind=127.0.0.1,reuseaddr,fork VSOCK-CONNECT:${toString cfg.vsock.cid}:${toString cfg.vsock.port}";
          Restart = "always";
          RestartSec = 5;
          # Hardening
          DynamicUser = true;
          NoNewPrivileges = true;
          PrivateTmp = true;
          ProtectSystem = "strict";
          ProtectHome = true;
        };
      };

      # nftables configuration for VM network isolation
      networking.nftables.enable = true;

      networking.nftables.tables.openclaw-vm-firewall = {
        family = "inet";
        content = ''
          # OpenClaw VM Network Isolation
          # Mark 0x00044F43 combines:
          #   - 0x00040000: Tailscale forwarding bit (allows traffic through exit node)
          #   - 0x00004F43: "OC" OpenClaw identifier
          # Mark is set early in prerouting, then accepted in forward chains

          chain prerouting {
            type filter hook prerouting priority raw; policy accept;

            # Mark packets from VM network for Tailscale exit node access
            # SECURITY: Only mark if BOTH source IP AND interface match
            # This prevents LAN devices from spoofing VM IPs to get the mark
            iifname "${cfg.network.bridgeName}" ip saddr ${cfg.network.bridgeAddress} meta mark set 0x00044F43

            # Mark return traffic to VM (no Tailscale bit needed - conntrack handles it)
            ip daddr ${cfg.network.bridgeAddress} meta mark set 0x00004F43
          }

          chain postrouting {
            type nat hook postrouting priority srcnat; policy accept;

            # Masquerade traffic from VM to internet
            ip saddr ${cfg.network.bridgeAddress} oifname != "${cfg.network.bridgeName}" masquerade
          }

          chain forward {
            type filter hook forward priority -10; policy accept;

            # Accept all marked VM traffic (check our bits, ignore Tailscale bits)
            meta mark & 0x0000FFFF == 0x4F43 accept

            # Allow established/related connections (handles return traffic)
            ct state established,related accept

            # Allow VM-initiated outbound traffic
            iifname "${cfg.network.bridgeName}" accept

            # Allow traffic TO the VM (from proxy or direct)
            oifname "${cfg.network.bridgeName}" accept
          }

          # Note: Input filtering handled by NixOS default firewall (networking.firewall)
        '';
      };

      # Add VM network exception to rpfilter-allow chain after firewall starts
      # This is more secure than loose rpfilter (which would be system-wide)
      systemd.services.openclaw-vm-rpfilter = {
        description = "Add OpenClaw VM rpfilter exception";
        after = [ "firewall.service" "nftables.service" ];
        wants = [ "firewall.service" ];
        wantedBy = [ "multi-user.target" ];

        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
          ExecStart = "${pkgs.nftables}/bin/nft insert rule inet nixos-fw rpfilter-allow ip saddr ${cfg.network.bridgeAddress} accept comment \\\"OpenClaw VM traffic\\\"";
          ExecStop = "${pkgs.nftables}/bin/nft delete rule inet nixos-fw rpfilter-allow handle $(${pkgs.nftables}/bin/nft -a list chain inet nixos-fw rpfilter-allow | grep 'OpenClaw VM' | grep -oP 'handle \\K\\d+') 2>/dev/null || true";
        };
      };
    }

    # microvm-specific config (only when microvm module is available)
    (optionalAttrs hasMicrovm {
      microvm.vms.openclaw-vm = {
        inherit pkgs;
        specialArgs = { inherit pkgs-unstable nix-openclaw opencode; };

        config = { config, ... }: {
          imports = [ ./guest.nix ];

          CUSTOM.virtualisation.openclaw-vm.guest = {
            vcpu = cfg.vcpu;
            mem = cfg.memory;
            gatewayPort = cfg.gatewayPort;
            dangerousDevMode = cfg.dangerousDevMode;
            useVirtiofs = cfg.useVirtiofs;
            # Pass network config to ensure host and guest stay in sync
            network = {
              vmAddress = cfg.network.vmAddress;
              gatewayAddress = lib.head (lib.splitString "/" cfg.network.bridgeAddress);
              prefixLength = lib.toInt (lib.last (lib.splitString "/" cfg.network.bridgeAddress));
            };
            # Pass vsock config to guest
            vsock = {
              cid = cfg.vsock.cid;
              port = cfg.vsock.port;
            };
            # Pass tailscale config to guest
            tailscale = {
              enable = cfg.tailscale.enable;
              hostname = cfg.tailscale.hostname;
              loginServer = cfg.tailscale.loginServer;
              exitNode = cfg.tailscale.exitNode;
              serve.enable = cfg.tailscale.serve.enable;
              sshAuthorizedKeys = cfg.tailscale.sshAuthorizedKeys;
            };
          };
        };
      };

      microvm.host.enable = true;

      # Ensure microvm starts after secrets are ready
      systemd.services."microvm@openclaw-vm" = {
        after = [ "sops-nix.service" ];
        wants = [ "sops-nix.service" ];
      };
    })

    # sops-nix secrets configuration (fallback when zero-trust not available)
    (mkIf (cfg.secrets.enable && cfg.secrets.sopsFile != null) {
      sops.secrets."openclaw/gateway-token" = {
        sopsFile = cfg.secrets.sopsFile;
        key = "gateway_token";
      };

      # Generate openclaw.json config from sops secrets
      # This is passed to the VM via fw_cfg credentials
      sops.templates."openclaw.json" = {
        content = builtins.toJSON {
          gateway = {
            mode = "local";
            bind = "loopback";
            auth = {
              mode = "token";
              token = config.sops.placeholder."openclaw/gateway-token";
              # Accept Tailscale Serve identity headers for authentication
              # This is secure because:
              # 1. Gateway binds to loopback only
              # 2. Tailscale Serve injects verified identity headers
              # 3. OpenClaw verifies via local tailscale daemon (tailscale whois)
              allowTailscale = true;
            };
            # Enable OpenAI-compatible HTTP endpoint for OpenCode
            http = {
              endpoints = {
                chatCompletions = { enabled = true; };
              };
            };
          };
        };
        mode = "0440";
        owner = "root";
        group = "openclaw-secrets"; # microvm user is in this group
      };
    })

    # Tailscale auth key secret (when tailscale enabled)
    (mkIf (cfg.secrets.enable && cfg.secrets.sopsFile != null && cfg.tailscale.enable) {
      sops.secrets."openclaw/tailscale-authkey" = {
        sopsFile = cfg.secrets.sopsFile;
        key = "tailscale_authkey";
        mode = "0440";
        owner = "root";
        group = "openclaw-secrets";
      };
    })

    # Add credentials to microvm when secrets are enabled
    (mkIf (hasMicrovm && cfg.secrets.enable && cfg.secrets.sopsFile != null) {
      microvm.vms.openclaw-vm = {
        # Pass secrets via fw_cfg (QEMU firmware configuration)
        # These become available to guest systemd services via LoadCredential
        config.microvm.credentialFiles = {
          "openclaw-config" = "/run/secrets/rendered/openclaw.json";
        };
      };
    })

    # Add tailscale auth key credential when tailscale enabled
    (mkIf (hasMicrovm && cfg.secrets.enable && cfg.secrets.sopsFile != null && cfg.tailscale.enable) {
      microvm.vms.openclaw-vm = {
        config.microvm.credentialFiles = {
          "tailscale-authkey" = config.sops.secrets."openclaw/tailscale-authkey".path;
        };
      };
    })

    # Caddy reverse proxy configuration
    (mkIf cfg.caddy.enable {
      services.caddy = {
        enable = true;

        # Caddy configuration for HTTPS reverse proxy to gateway
        virtualHosts."${cfg.caddy.domain}:${toString cfg.caddy.httpsPort}" = {
          extraConfig = ''
            ${lib.optionalString cfg.caddy.internalCa ''
            # Use Caddy's internal CA for localhost HTTPS
            # Run 'sudo caddy trust' to install CA in system trust store for browser access
            tls internal
            ''}

            # Reverse proxy to the openclaw gateway
            reverse_proxy localhost:${toString cfg.gatewayPort} {
              # WebSocket support for real-time communication
              header_up Host {host}
              header_up X-Real-IP {remote_host}
              header_up X-Forwarded-For {remote_host}
              header_up X-Forwarded-Proto {scheme}

              # Health check for the backend
              health_uri /health
              health_interval 30s
              health_timeout 5s
            }
          '';
        };
      };

      # HTTP redirect to HTTPS (optional, on different port)
      services.caddy.virtualHosts."${cfg.caddy.domain}:${toString cfg.caddy.httpPort}" = {
        extraConfig = ''
          redir https://${cfg.caddy.domain}:${toString cfg.caddy.httpsPort}{uri} permanent
        '';
      };

      # Open firewall ports for Caddy
      networking.firewall.allowedTCPPorts = [
        cfg.caddy.httpsPort
        cfg.caddy.httpPort
      ];

      # Ensure Caddy starts after the gateway proxy is available
      systemd.services.caddy = {
        after = [ "openclaw-gateway-proxy.service" ];
        wants = [ "openclaw-gateway-proxy.service" ];
      };
    })
  ]);
}
