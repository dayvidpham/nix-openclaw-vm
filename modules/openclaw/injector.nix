# OpenClaw Secrets Injector Service
# Zero-trust secret injection: runs BEFORE container/VM, injects secrets to tmpfs
#
# Design:
# - Container/VM has NO credentials (zero-trust)
# - Injector authenticates to Keycloak using service account credentials
# - Fetches OIDC token, exchanges for OpenBao secrets
# - Writes secrets to tmpfs mount, exits
# - Container/VM starts with bind-mounted secrets
#
# Modes:
# - Container mode: writes to /run/openclaw-${name}/secrets/ (per-instance)
# - VM mode: writes to /run/openclaw-vm/secrets/ (shared for microVM)
#
# Trust Anchor: sops-nix-encrypted client credentials on host
{ config
, pkgs
, lib ? pkgs.lib
, ...
}:
let
  cfg = config.CUSTOM.virtualisation.openclaw;
  injectorCfg = cfg.zeroTrust.injector;
  keycloakCfg = cfg.zeroTrust.keycloak;
  openbaoCfg = cfg.zeroTrust.openbao;
  enabledInstances = lib.filterAttrs (n: v: v.enable) cfg.instances;

  vmModeCfg = injectorCfg.vmMode;

  inherit (lib)
    mkIf
    mkMerge
    mkOption
    mkEnableOption
    types
    optionalString
    optional
    ;

  # VM mode injector script
  # Writes gateway configuration to shared secrets directory for microVM
  mkVmInjectorScript = pkgs.writeShellScript "openclaw-injector-vm" ''
    set -euo pipefail

    SECRETS_DIR="${toString vmModeCfg.secretsDir}"
    OPENBAO_URL="${injectorCfg.openbaoUrl}"

    log() {
      echo "[$(date -Iseconds)] [injector-vm] $*"
    }

    log_error() {
      echo "[$(date -Iseconds)] [injector-vm] ERROR: $*" >&2
    }

    # Create secrets directory
    mkdir -p "$SECRETS_DIR"
    chmod 700 "$SECRETS_DIR"
    log "Secrets directory ready: $SECRETS_DIR"

    # Determine gateway token
    GATEWAY_TOKEN=""

    ${if vmModeCfg.gatewayToken != null then ''
      # Use configured gateway token
      GATEWAY_TOKEN="${vmModeCfg.gatewayToken}"
      log "Using configured gateway token"
    '' else ''
      # Fetch gateway token from OpenBao (if available) or use sops fallback
      ${optionalString injectorCfg.fallbackToSops ''
        # Try sops fallback for gateway token
        SOPS_TOKEN_PATH="${config.sops.secrets."openclaw/gateway-token".path or ""}"
        if [ -n "$SOPS_TOKEN_PATH" ] && [ -f "$SOPS_TOKEN_PATH" ]; then
          GATEWAY_TOKEN="$(cat "$SOPS_TOKEN_PATH")"
          log "Gateway token loaded from sops-nix"
        fi
      ''}

      if [ -z "$GATEWAY_TOKEN" ]; then
        log_error "No gateway token available (neither configured nor from sops)"
        exit 1
      fi
    ''}

    # Write openclaw.json config file
    CONFIG_FILE="$SECRETS_DIR/openclaw.json"
    ${pkgs.jq}/bin/jq -n \
      --arg token "$GATEWAY_TOKEN" \
      '{
        gateway: {
          mode: "local",
          auth: {
            token: $token
          }
        }
      }' > "$CONFIG_FILE"

    chmod 400 "$CONFIG_FILE"
    log "Config written: $CONFIG_FILE"

    log "VM secrets injector finished successfully"
  '';

  # Injector script for a single instance
  # Authenticates to Keycloak, fetches secrets from OpenBao, writes to tmpfs
  mkInjectorScript = name: instanceCfg: pkgs.writeShellScript "openclaw-injector-${name}" ''
    set -euo pipefail

    # Configuration
    INSTANCE="${name}"
    KEYCLOAK_URL="${injectorCfg.keycloakUrl}"
    REALM="${injectorCfg.keycloakRealm}"
    CLIENT_ID="openclaw-injector-${name}"
    OPENBAO_URL="${injectorCfg.openbaoUrl}"
    OPENBAO_ROLE="openclaw-injector-${name}"
    SECRETS_DIR="/run/openclaw-${name}/secrets"

    # Client secret from Keycloak init or sops-nix
    CLIENT_SECRET_FILE="${injectorCfg.clientSecretsDir}/${name}.secret"

    # Retry configuration
    MAX_RETRIES=${toString injectorCfg.maxRetries}
    RETRY_DELAY=${toString injectorCfg.retryDelaySeconds}

    log() {
      echo "[$(date -Iseconds)] [injector-${name}] $*"
    }

    log_error() {
      echo "[$(date -Iseconds)] [injector-${name}] ERROR: $*" >&2
    }

    # Exponential backoff retry
    retry_with_backoff() {
      local cmd="$1"
      local description="$2"
      local attempt=1
      local delay=$RETRY_DELAY

      while [ $attempt -le $MAX_RETRIES ]; do
        log "Attempt $attempt/$MAX_RETRIES: $description"
        if eval "$cmd"; then
          return 0
        fi
        if [ $attempt -lt $MAX_RETRIES ]; then
          log "Failed, retrying in ''${delay}s..."
          sleep $delay
          delay=$((delay * 2))  # Exponential backoff
        fi
        attempt=$((attempt + 1))
      done

      log_error "All $MAX_RETRIES attempts failed: $description"
      return 1
    }

    # Create secrets directory on tmpfs
    mkdir -p "$SECRETS_DIR"
    chmod 700 "$SECRETS_DIR"
    log "Secrets directory ready: $SECRETS_DIR"

    # Read client secret
    if [ ! -f "$CLIENT_SECRET_FILE" ]; then
      log_error "Client secret not found: $CLIENT_SECRET_FILE"
      exit 1
    fi
    CLIENT_SECRET="$(cat "$CLIENT_SECRET_FILE")"

    # Step 1: Authenticate to Keycloak using client credentials
    log "Authenticating to Keycloak..."
    get_oidc_token() {
      OIDC_RESPONSE=$(${pkgs.curl}/bin/curl -sf -X POST \
        "$KEYCLOAK_URL/realms/$REALM/protocol/openid-connect/token" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "grant_type=client_credentials" \
        -d "client_id=$CLIENT_ID" \
        -d "client_secret=$CLIENT_SECRET")

      OIDC_TOKEN=$(echo "$OIDC_RESPONSE" | ${pkgs.jq}/bin/jq -r '.access_token')
      if [ -z "$OIDC_TOKEN" ] || [ "$OIDC_TOKEN" = "null" ]; then
        log_error "Failed to get OIDC token from Keycloak"
        return 1
      fi
      log "OIDC token obtained from Keycloak"
      return 0
    }

    if ! retry_with_backoff "get_oidc_token" "Get OIDC token from Keycloak"; then
      ${optionalString injectorCfg.fallbackToSops ''
        log "Falling back to sops-nix secrets..."
        # Copy sops secrets to tmpfs if they exist
        if [ -f "${config.sops.secrets."openclaw/${name}/api-key".path}" ]; then
          cp "${config.sops.secrets."openclaw/${name}/api-key".path}" "$SECRETS_DIR/api-key"
          chmod 400 "$SECRETS_DIR/api-key"
          log "Fallback: api-key copied from sops-nix"
        fi
        exit 0
      ''}
      exit 1
    fi

    # Step 2: Authenticate to OpenBao using OIDC JWT
    log "Authenticating to OpenBao with OIDC token..."
    get_openbao_token() {
      VAULT_RESPONSE=$(${pkgs.curl}/bin/curl -sf -X POST \
        "$OPENBAO_URL/v1/auth/oidc/login" \
        -H "Content-Type: application/json" \
        -d "{\"role\": \"$OPENBAO_ROLE\", \"jwt\": \"$OIDC_TOKEN\"}")

      VAULT_TOKEN=$(echo "$VAULT_RESPONSE" | ${pkgs.jq}/bin/jq -r '.auth.client_token')
      if [ -z "$VAULT_TOKEN" ] || [ "$VAULT_TOKEN" = "null" ]; then
        log_error "Failed to get OpenBao token"
        return 1
      fi
      log "OpenBao token obtained"
      return 0
    }

    if ! retry_with_backoff "get_openbao_token" "Get OpenBao token via OIDC"; then
      ${optionalString injectorCfg.fallbackToSops ''
        log "Falling back to sops-nix secrets..."
        if [ -f "${config.sops.secrets."openclaw/${name}/api-key".path}" ]; then
          cp "${config.sops.secrets."openclaw/${name}/api-key".path}" "$SECRETS_DIR/api-key"
          chmod 400 "$SECRETS_DIR/api-key"
          log "Fallback: api-key copied from sops-nix"
        fi
        exit 0
      ''}
      exit 1
    fi

    # Step 3: Fetch secrets from OpenBao
    log "Fetching secrets from OpenBao..."
    fetch_secret() {
      local secret_path="$1"
      local output_file="$2"

      RESPONSE=$(${pkgs.curl}/bin/curl -sf \
        "$OPENBAO_URL/v1/secret/data/$secret_path" \
        -H "X-Vault-Token: $VAULT_TOKEN")

      VALUE=$(echo "$RESPONSE" | ${pkgs.jq}/bin/jq -r '.data.data.value // empty')
      if [ -z "$VALUE" ]; then
        log_error "Secret not found or empty: $secret_path"
        return 1
      fi

      echo -n "$VALUE" > "$output_file"
      chmod 400 "$output_file"
      log "Secret written: $output_file"
      return 0
    }

    # Fetch required secrets for this instance
    SECRETS_FETCHED=0

    # API key
    if fetch_secret "openclaw/${name}/api-key" "$SECRETS_DIR/api-key"; then
      SECRETS_FETCHED=$((SECRETS_FETCHED + 1))
    else
      log_error "Failed to fetch api-key"
      ${optionalString injectorCfg.fallbackToSops ''
        if [ -f "${config.sops.secrets."openclaw/${name}/api-key".path}" ]; then
          cp "${config.sops.secrets."openclaw/${name}/api-key".path}" "$SECRETS_DIR/api-key"
          chmod 400 "$SECRETS_DIR/api-key"
          log "Fallback: api-key copied from sops-nix"
          SECRETS_FETCHED=$((SECRETS_FETCHED + 1))
        fi
      ''}
    fi

    # Instance token (optional)
    if fetch_secret "openclaw/${name}/instance-token" "$SECRETS_DIR/instance-token" 2>/dev/null; then
      SECRETS_FETCHED=$((SECRETS_FETCHED + 1))
    fi

    # Bridge signing key (optional)
    if fetch_secret "openclaw/${name}/bridge-signing-key" "$SECRETS_DIR/bridge-signing-key" 2>/dev/null; then
      SECRETS_FETCHED=$((SECRETS_FETCHED + 1))
    fi

    if [ $SECRETS_FETCHED -eq 0 ]; then
      log_error "No secrets were fetched successfully"
      exit 1
    fi

    log "Injection complete: $SECRETS_FETCHED secret(s) written to $SECRETS_DIR"

    # Verify ownership and permissions
    chown -R ${instanceCfg.user}:${instanceCfg.group} "$SECRETS_DIR"

    log "Secrets injector finished successfully"
  '';

in
{
  # Injector-specific options
  options.CUSTOM.virtualisation.openclaw.zeroTrust.injector = {
    enable = mkEnableOption "Zero-trust secrets injector for OpenClaw";

    keycloakUrl = mkOption {
      type = types.str;
      default = "http://127.0.0.1:8080";
      description = "Keycloak URL for OIDC authentication";
    };

    keycloakRealm = mkOption {
      type = types.str;
      default = "openclaw";
      description = "Keycloak realm name";
    };

    openbaoUrl = mkOption {
      type = types.str;
      default = "http://127.0.0.1:8200";
      description = "OpenBao URL for secrets retrieval";
    };

    clientSecretsDir = mkOption {
      type = types.path;
      default = /var/lib/openclaw/keycloak/client-secrets;
      description = "Directory containing Keycloak client secrets";
    };

    maxRetries = mkOption {
      type = types.int;
      default = 5;
      description = "Maximum retry attempts for authentication";
    };

    retryDelaySeconds = mkOption {
      type = types.int;
      default = 2;
      description = "Initial retry delay in seconds (doubles each retry)";
    };

    fallbackToSops = mkOption {
      type = types.bool;
      default = true;
      description = "Fall back to sops-nix secrets if zero-trust injection fails";
    };

    timeout = mkOption {
      type = types.int;
      default = 120;
      description = "Maximum time in seconds for injection to complete";
    };

    # VM mode: inject secrets for microVM instead of/in addition to containers
    vmMode = {
      enable = mkEnableOption "VM mode secrets injection for openclaw-vm microVM";

      secretsDir = mkOption {
        type = types.path;
        default = /run/openclaw-vm/secrets;
        description = "Directory to write secrets for VM consumption via 9p share";
      };

      gatewayToken = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "Gateway token to embed in config. If null, fetched from OpenBao.";
      };
    };
  };

  # Generate injector services for each enabled instance
  config = mkMerge [
    # Container mode: per-instance injectors
    (mkIf (cfg.enable && cfg.zeroTrust.enable && injectorCfg.enable) {
      # Assertions
      assertions = [
        {
          assertion = keycloakCfg.enable;
          message = "OpenClaw secrets injector requires Keycloak. Enable CUSTOM.virtualisation.openclaw.zeroTrust.keycloak";
        }
        {
          assertion = openbaoCfg.enable;
          message = "OpenClaw secrets injector requires OpenBao. Enable CUSTOM.virtualisation.openclaw.zeroTrust.openbao";
        }
      ];

      # Create tmpfs directories for secrets
      systemd.tmpfiles.rules = builtins.map (name:
        # Create secrets dir on tmpfs with restricted permissions
        "d /run/openclaw-${name}/secrets 0700 root root -"
      ) (builtins.attrNames enabledInstances);

      # Generate injector service for each instance
      systemd.services = builtins.listToAttrs (builtins.map (name:
        let instanceCfg = enabledInstances.${name};
        in {
          name = "openclaw-injector-${name}";
          value = {
            description = "OpenClaw Secrets Injector for ${name}";

            # Run AFTER infrastructure is ready, BEFORE container starts
            after = [
              "network.target"
              "podman-openclaw-keycloak.service"
              "openclaw-keycloak-init.service"
              "podman-openclaw-openbao.service"
              "openclaw-openbao-init.service"
            ];
            requires = [
              "podman-openclaw-keycloak.service"
              "podman-openclaw-openbao.service"
            ];
            before = [ "podman-openclaw-${name}.service" ];
            wantedBy = [ "multi-user.target" ];

            # Injector runs once before container, must complete
            serviceConfig = {
              Type = "oneshot";
              RemainAfterExit = true;
              TimeoutStartSec = "${toString injectorCfg.timeout}s";

              # Run as root to access client secrets, then chown to instance user
              User = "root";
              Group = "root";

              # Security hardening
              ProtectSystem = "strict";
              ProtectHome = true;
              PrivateTmp = true;
              NoNewPrivileges = true;

              # Required paths
              ReadOnlyPaths = [
                injectorCfg.clientSecretsDir
              ] ++ (if cfg.secrets.enable then [
                # sops fallback paths
                config.sops.secrets."openclaw/${name}/api-key".path
              ] else []);
              ReadWritePaths = [
                "/run/openclaw-${name}"
              ];

              ExecStart = mkInjectorScript name instanceCfg;
            };
          };
        }
      ) (builtins.attrNames enabledInstances));
    })

    # VM mode: single injector for microVM
    (mkIf vmModeCfg.enable {
      # Create tmpfs directory for VM secrets
      systemd.tmpfiles.rules = [
        "d ${toString vmModeCfg.secretsDir} 0700 root root -"
      ];

      # VM secrets injector service
      systemd.services.openclaw-injector-vm = {
        description = "OpenClaw Secrets Injector for microVM";

        # Run BEFORE the microVM starts
        after = [ "network.target" ];
        before = [ "microvm@openclaw-vm.service" ];
        wantedBy = [ "multi-user.target" ];

        # Oneshot: run once, complete before microVM starts
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
          TimeoutStartSec = "${toString injectorCfg.timeout}s";

          # Run as root to create secrets directory
          User = "root";
          Group = "root";

          # Security hardening
          ProtectSystem = "strict";
          ProtectHome = true;
          PrivateTmp = true;
          NoNewPrivileges = true;

          # Required paths
          ReadOnlyPaths = optional (vmModeCfg.gatewayToken == null && injectorCfg.fallbackToSops)
            (config.sops.secrets."openclaw/gateway-token".path or "/dev/null");
          ReadWritePaths = [ (toString vmModeCfg.secretsDir) "/run/openclaw-vm" ];

          ExecStart = mkVmInjectorScript;
        };
      };
    })
  ];
}
