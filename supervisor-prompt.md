# Supervisor: Implement Credential Proxy Security Layer

## Beads Task
`dotfiles-1art` — Implement credential proxy security layer for openclaw-vm

## Goal
Implement a credential proxy security layer for the openclaw microVM where:
- The agent inside the VM has **zero external network access**
- All auth-required requests are delegated to a **trusted proxy service on the host** via VSOCK
- Credentials are stored in **OpenBao** with **domain binding** enforcement
- The proxy **injects auth headers** — the agent never sees API keys
- Full **audit trail** of all credential access

## Architecture

```
Host (NixOS)
├── OpenBao (secrets store, already has a NixOS module)
│   └── Credentials with domain binding metadata
│       e.g., openclaw/api/key → { key: "sk-xxx", domain: "api.openclaw.com" }
│
├── Credential Proxy Service (NEW — this is what we're building)
│   ├── Listens on VSOCK for requests from guest VM
│   ├── Validates request (ACP subset protocol)
│   ├── Looks up credential in OpenBao by ref + verifies domain binding
│   ├── Injects auth headers into outbound HTTPS request
│   ├── Forwards request to external API
│   ├── Templates response (strips sensitive fields)
│   ├── Returns sanitized response to agent
│   └── Audit logs everything
│
└── openclaw-vm (microVM, already exists)
    └── Agent (zero network — all requests go through VSOCK → proxy)
```

## Key Design Principles
- **Zero network access** for agent (microVM has no external network; only VSOCK to host)
- **Agent never sees credentials** (proxy injects them server-side)
- **Domain binding** (credential X only works for domain Y, prevents misuse)
- **Fail-closed** (proxy error = deny, not pass-through)
- **Audit everything** (who accessed what credential, when, for what domain)

## What Already Exists

### 1. openclaw-vm module (`modules/openclaw-vm/`)
- `default.nix` — Host module: declares microVM, configures VSOCK (CID 4, port 18789), TAP networking, nftables, gateway proxy
- `guest.nix` — Guest module: configures services inside VM, VSOCK proxy, systemd hardening
- VSOCK is already wired up for the gateway proxy (socat TCP↔VSOCK)
- The VM already has `networking.useDHCP = false` and uses TAP for host-only communication

### 2. OpenBao module (`~/dotfiles/modules/nixos/virtualisation/openbao/default.nix`)
- Deploys OpenBao in a Podman container on the host
- Has policies, OIDC auth, auto-unseal, audit logging
- Generic (not tied to openclaw specifically)
- Needs: domain binding metadata on secrets, proxy-specific policy

### 3. Full plan document (`~/dotfiles/docs/agent-sandbox.md`)
- Contains detailed ACP protocol spec, request/response formats, security properties
- **NOTE**: The plan references gVisor — we use microVM instead. VSOCK replaces Unix socket.
- Research section identifies existing projects (Vultrino, Agent Gateway) for reference

## What Needs to Be Built

### Phase 1: Protocol & Types
- Define the ACP subset protocol for agent↔proxy communication over VSOCK
- Request format: credential ref, target domain/path, method, headers, body
- Response format: templated JSON with only requested fields
- Error format: structured denial with reason

### Phase 2: Credential Proxy Service
- Rust or Go service (check plan for language preference)
- Listens on VSOCK (host side)
- Validates incoming ACP requests
- Connects to OpenBao to fetch credentials
- Verifies domain binding (credential.domain == request target domain)
- Injects auth headers into outbound HTTPS request
- Templates response (only return fields agent requested)
- Rate limiting per agent
- Structured audit logging (JSONL)

### Phase 3: NixOS Integration
- NixOS module for the proxy service (systemd unit, hardening)
- Wire into openclaw-vm host module (starts before/with VM)
- OpenBao policy for proxy (read-only access to credentials)
- VSOCK port allocation (new port, separate from gateway's 18789)

### Phase 4: Guest-Side Client
- Lightweight client library/CLI the agent uses to make proxied requests
- Sends ACP requests over VSOCK
- Receives templated responses
- Could be a simple shell script wrapping socat, or a proper CLI

### Phase 5: VM Network Lockdown
- Ensure the VM has zero external network when proxy is enabled
- Only VSOCK communication allowed
- Remove or disable TAP/bridge networking in proxy mode

## Implementation Constraints

From CLAUDE.md:
- Use `git agent-commit` (not `git commit`) for commits
- Run `nix flake check --no-build` before committing
- Use Given/When/Then/Should format for requirements
- Inject all dependencies (including clocks)
- Use structured JSONL logging, never log secrets
- Use PascalCase enums for status/type fields

## Validation

1. `nix flake check --no-build` passes
2. `nix eval .#nixosConfigurations.test-vm.config.system.build.toplevel --apply 'x: "ok"'` returns `"ok"`
3. Proxy service unit evaluates correctly
4. OpenBao policy grants proxy read-only access to credentials
5. Agent cannot reach external network (no DNS, no TCP out)
6. Credential requests via VSOCK succeed with valid domain binding
7. Credential requests with wrong domain are denied
