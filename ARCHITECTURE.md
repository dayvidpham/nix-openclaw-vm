# Architecture

This document maps the ownership hierarchy, data flow, and concurrency protocol
of the nix-openclaw-vm project. It covers both the NixOS module layer (host/guest
VM configuration) and the credential-proxy Go binary (MITM proxy with Temporal
workflow orchestration).

## The Big Picture

An AI agent runs inside a MicroVM guest. When it makes HTTP(S) requests, they
pass through a credential-injection proxy on the host that:

1. Validates the agent's JWT (OIDC / Keycloak)
2. Evaluates authorization policy (OPA / Rego)
3. Fetches real secrets from a vault (OpenBao KV v2)
4. Replaces opaque placeholder tokens with real credentials
5. Forwards the request to the upstream API
6. Scrubs real credentials from the response before returning it to the agent

The agent never sees real secrets — only placeholder tokens like
`agent-vault-00000000-0000-0000-0000-000000000001`.

```
┌─────────────────────────────────────────────────────────────────┐
│                        HOST (NixOS)                             │
│                                                                 │
│  ┌──────────────────┐    VSOCK     ┌──────────────────────────┐ │
│  │   MicroVM Guest  │◄────────────►│  credential-proxy (Go)   │ │
│  │                  │  CID 2↔4     │                          │ │
│  │  ┌────────────┐  │              │  authn ← Keycloak OIDC   │ │
│  │  │ AI Agent   │  │              │  authz ← OPA/Rego        │ │
│  │  │ (OpenCode) │  │              │  vault ← OpenBao KV v2   │ │
│  │  └─────┬──────┘  │              │  audit ← Temporal        │ │
│  │        │         │              │                          │ │
│  │  HTTP_PROXY=     │              │  MITM CA (EC P-256)      │ │
│  │  localhost:18790 │              │  goproxy + CONNECT       │ │
│  │                  │              └──────────┬───────────────┘ │
│  └──────────────────┘                        │                 │
│                                              ▼                 │
│                                     ┌────────────────┐         │
│                                     │ Upstream APIs  │         │
│                                     │ (Anthropic,    │         │
│                                     │  OpenAI, etc.) │         │
│                                     └────────────────┘         │
└─────────────────────────────────────────────────────────────────┘
```

## Three Deployment Modes

| Mode | Module | Description |
|------|--------|-------------|
| **MicroVM** | `openclaw-vm` + `credential-proxy` | Agent in QEMU MicroVM, proxy on host, VSOCK transport |
| **Container** | `openclaw` | Rootless Podman containers, zero-trust injector sidecar |
| **Dev** | `dangerousDevMode` | Local OpenBao + Temporal dev servers, auto-generated MITM CA |

---

## Design Rationale

### Threat Model

The AI agent executes untrusted, LLM-generated code. It needs API credentials
to call external services (Anthropic, OpenAI, etc.), but giving it direct access
to real API keys means a compromised or misbehaving agent can exfiltrate them.
The design goal is:

> **The agent can use credentials but never see them.**

This requires isolation at every layer: compute (the agent can't read host
memory), network (the agent can't bypass the proxy), transport (the channel
between agent and proxy is tamper-proof), and audit (every credential access is
logged with who, what, when, and where).

### Why MicroVM (not containers, not full VMs)

The primary isolation boundary is between the agent and the credential proxy.
The proxy holds real secrets; the agent must not be able to reach them.

**Containers are insufficient.** Containers share the host kernel. A container
escape (which is a realistic threat for an agent running arbitrary code) gives
direct access to the host filesystem, including `/var/lib/credproxy/ca/ca.key`
and the proxy's process memory. cgroups and namespaces are privilege-reduction
mechanisms, not security boundaries — they were never designed to contain an
adversarial workload.

**Full VMs are overkill.** A traditional VM (QEMU with full BIOS, GRUB, ACPI,
USB, etc.) has a large attack surface of emulated devices and boots slowly.
We don't need hardware emulation fidelity — we need a minimal isolation kernel
with a small, auditable device surface.

**MicroVMs hit the sweet spot.** [microvm.nix](https://github.com/astro/microvm.nix)
provides QEMU with a stripped device model: virtio-net (TAP), virtio-vsock,
virtiofs, virtio-blk, and a serial console. No emulated USB, no ACPI, no
PCI passthrough. The guest runs a full NixOS kernel, so the agent has a
real Linux environment, but the host-guest boundary is a hardware
virtualization boundary (KVM / VT-x), not a namespace boundary.

```
Container:     shared kernel ──► escape = host access
Full VM:       full device model ──► large attack surface, slow boot
MicroVM:       minimal virtio devices + KVM ──► hardware isolation, fast boot
```

### Why VSOCK (not TCP over TAP, not Unix sockets)

VSOCK (`AF_VSOCK`) is a virtio transport between host and guest that operates
outside the TCP/IP network stack entirely.

**It can't be intercepted by the guest.** VSOCK is a virtio device backed by
`/dev/vhost-vsock` on the host. The guest kernel presents it as a socket
family (`AF_VSOCK`), but there is no network interface, no IP address, and no
packet that can be captured with tcpdump. A compromised agent with root in the
guest cannot sniff or tamper with VSOCK traffic.

**It's immune to nftables.** The `credproxy-lockdown` nftables table blocks all
TCP/UDP outbound from the VM except DNS and Tailscale. This forces all HTTP(S)
traffic through `HTTP_PROXY=localhost:18790`, which is a socat bridge to the
host's VSOCK port. Because VSOCK is not a network interface, the lockdown rules
don't affect it — the proxy channel works even when the network is fully locked
down.

**It doesn't need IP configuration.** VSOCK uses Context IDs (CIDs) instead of
IP addresses. Host is always CID 2; guest CID is assigned at VM creation. No
DHCP, no ARP, no routing tables. This eliminates an entire class of
misconfiguration bugs.

**It's zero-copy via virtio.** Lower latency than TCP over a TAP bridge, which
traverses the full host network stack (bridge, nftables, conntrack).

```
TCP over TAP:  guest → tap → bridge → nftables → conntrack → host userspace
               (filterable, interceptable, requires IP config)

VSOCK:         guest → virtio ring → host /dev/vhost-vsock → host userspace
               (invisible to guest network stack, immune to firewall)
```

### Why Temporal (not goroutines, not a message queue)

Temporal is used primarily for **audit trail**, not orchestration complexity.

**Every credential access is a workflow execution.** Each proxied request that
involves credential injection creates a `ProxyRequestWorkflow` with typed search
attributes: agent ID, target domain, credential reference, and terminal status.
This provides a queryable, tamper-resistant log of every credential use — who
accessed what, for which domain, when, and what happened.

**The workflow lifecycle captures the full round-trip.** The workflow starts when
the agent's request arrives, stays alive while the upstream API responds, and
completes when goproxy signals `response_complete` after scrubbing. This means
the audit trail records not just "credential was fetched" but "credential was
fetched, request was forwarded, response was received, N credential occurrences
were scrubbed, response was X bytes."

**Local activities keep secrets out of event history.** Temporal normally
serializes activity inputs and outputs into its event history database.
`FetchAndInject` runs as a *local activity* — it executes in the same process
as the worker, and the real credential values exist only in local memory. The
activity input contains only a `requestID` (used to look up the live
`*http.Request` from the in-process `RequestRegistry`). The output contains only
a credential count. Secrets never touch the Temporal server.

**The signal mechanism bridges async boundaries cleanly.** The goproxy
OnResponse handler runs in a different goroutine than the workflow. Rather than
polling or shared state, the handler signals the workflow with
`response_complete` metadata. The workflow selects on the signal channel with a
60-second timeout — if the signal never arrives (e.g., the upstream hung up),
the workflow completes with `StatusTimeout`.

**Retry semantics come free.** If OpenBao is temporarily unavailable, Temporal's
retry policy can re-attempt the vault fetch. (Currently retries are disabled
with `MaximumAttempts: 1` because a retry would find the registry entry cleaned
up, but the infrastructure is there for future refinement.)

### Why Keycloak (not a simpler JWT issuer)

**Standard OIDC with role-based access.** Keycloak provides full OIDC with the
`realm_access.roles` claim structure that the proxy extracts in
`authn.extractRealmRoles()`. Different agents can have different roles
(e.g., `proxy-user`, `admin`), and OPA policies can make decisions based on
these roles. A simpler JWT issuer (e.g., a static signing key) would lack the
role management, client credential grants, and JWKS rotation that Keycloak
provides out of the box.

**Self-hostable and already in the OpenClaw ecosystem.** The container-mode
deployment (`modules/openclaw/keycloak.nix`) already provisions Keycloak for the
OpenClaw platform. The credential proxy reuses the same identity provider rather
than introducing a second auth system.

**Client credential grants for machine-to-machine auth.** The agent obtains a
JWT via a client credential grant (the `credproxy-auth` script on the guest),
not via interactive login. This is the standard OAuth2 flow for service-to-service
authentication.

### Why OpenBao (not environment variables, not a config file)

**Secrets must not be in the Nix store.** The Nix store is world-readable and
content-addressed. Any secret placed in the store is permanently recoverable
from its hash. OpenBao provides runtime secret delivery: the proxy fetches
credentials over the network at request time, and they exist only in process
memory during the activity execution.

**KV v2 with versioning and ACL policies.** OpenBao's KV v2 engine provides
secret versioning (for rollback), and its ACL policy model scopes access to
specific paths. The `credproxy-readonly` policy (defined in
`openbao-policy.nix`) grants read-only access to
`secret/data/openclaw/credentials/*` — the proxy cannot write, delete, or
access secrets outside that path.

**AppRole auth for machine identity.** In production, the proxy authenticates to
OpenBao via AppRole (role ID + secret ID), not a static token. The secret ID is
rotated and delivered via sops-nix. In dev mode, a static `dev-token` is used
for simplicity.

**Open source (not HashiCorp Vault).** OpenBao is the community fork of
HashiCorp Vault, created after HashiCorp changed Vault's license to BSL.
The API is compatible — same client libraries, same KV v2 engine, same ACL
model — but the license permits unrestricted use.

### Why OPA / Rego (not hardcoded rules)

**Policy-as-code, separate from proxy code.** Authorization rules are
declarative Rego files in `credential-proxy/authz/policies/`. An operator can
modify policy (e.g., add a new domain binding, require an additional role)
without recompiling the Go binary. The proxy loads `.rego` files from a
directory at startup.

**Domain binding enforcement.** The critical invariant is: *credential X may
only be used for domain Y*. A placeholder bound to `api.anthropic.com` must not
be injectable into a request to `evil.example.com`. This is a policy rule, not a
code check — expressing it in Rego makes it auditable, testable, and
changeable independently of the proxy implementation.

**Embedded engine, no network call.** `OPAEvaluator` embeds the OPA engine
in-process. Policy evaluation is a local activity with a 5-second timeout and no
network I/O. This means authorization adds negligible latency and doesn't
introduce a network dependency on an external policy server.

**Testable against real policy files.** The `authz` integration tests load the
actual `.rego` files from disk and evaluate real allow/deny decisions. There is
no mock policy — the test exercises the same Rego code that runs in production.

### Security Invariants

These are the properties the system is designed to preserve. Violations of any
of these would be considered a security bug.

| # | Invariant | Enforcement Mechanism |
|---|-----------|----------------------|
| S1 | **Agent never sees real credentials** | Placeholder substitution in proxy; response scrubbing in `ScrubCredentials`; network lockdown forces all traffic through proxy |
| S2 | **Secrets never enter Temporal event history** | `FetchAndInject` is a local activity; inputs contain only `requestID`; outputs contain only `credentialCount` |
| S3 | **Fail-closed domain allowlist** | `cfg.IsAllowedDomain()` checked in `handleConnect`; unknown domains → `RejectConnect` (connection refused) |
| S4 | **Credential domain binding** | Each credential has a `bound_domain`; OPA policy enforces that the credential is only used for requests to that domain |
| S5 | **MITM CA private key never in /nix/store** | Generated at service activation time by `credproxy-ca-init` into `/var/lib/credproxy/ca/` (0400 perms); shared to guest via virtiofs, not Nix closure |
| S6 | **Network lockdown when proxy is enabled** | nftables `credproxy-lockdown` blocks all VM outbound TCP/UDP except DNS (53) and Tailscale (41641); VSOCK is immune (not TCP/IP) |
| S7 | **No double-write on DecisionCh** | TLA+ verified; `DecisionCh` is buffered (cap=1); exactly one sender per request (either `FetchAndInject` or `SendDecision`) |
| S8 | **Handler always terminates** | TLA+ verified; 35-second `select` timeout in `handleRequest`; `defer registry.Delete(requestID)` ensures cleanup |
| S9 | **Registry always cleaned up** | `defer` in handler + background TTL sweeper (120s) as defence-in-depth |
| S10 | **Raw JWT never forwarded upstream** | `req.Header.Del("Proxy-Authorization")` in `handleRequest` before forwarding |
| S11 | **Raw JWT never in Temporal input** | JWT is validated inline in `handleRequest`; only the extracted `IdentityClaims` (subject, roles, groups) are passed to the workflow |

### Systemd Hardening

Every service runs with the minimum privileges needed. The key systemd
directives and what they protect against:

**Process isolation** — prevent the agent from observing or killing the proxy:

| Directive | Effect |
|-----------|--------|
| `ProtectProc=invisible` | `/proc` only shows the service's own processes; agent can't see credproxy PID |
| `DynamicUser=true` | Ephemeral UID/GID; no persistent user entry (used for socat bridges) |
| Dedicated system users | `credproxy`, `openclaw-gateway`, `opencode-server` — no login shell, no home dir |
| Dual-user isolation | Gateway and OpenCode run as system users; interactive `openclaw` user can't signal them |

**Filesystem isolation** — prevent credential reads via filesystem:

| Directive | Effect |
|-----------|--------|
| `ProtectSystem=strict` | Entire filesystem is read-only except explicitly allowed paths |
| `ReadWritePaths=/var/lib/credproxy` | Only the proxy's state directory is writable |
| `PrivateTmp=true` | Isolated `/tmp`; other services can't read temp files |
| `StateDirectory=credproxy` | systemd creates `/var/lib/credproxy` with correct ownership |
| MITM CA perms: `0400`/`0444` | Private key readable only by `credproxy` user; cert is public |

**Privilege escalation prevention** — defence in depth if the service is compromised:

| Directive | Effect |
|-----------|--------|
| `NoNewPrivileges=true` | Can't gain new privileges via setuid/setgid binaries |
| `RestrictNamespaces=true` | Can't create new namespaces (prevents container-in-container escape) |
| `CapabilityBoundingSet=` | No ambient capabilities (services don't need raw sockets, etc.) |
| `DeviceAllow=/dev/vhost-vsock rw` | Only VSOCK device is accessible; no disk, no USB, no GPU |
| `RestrictSUIDSGID=true` | Can't create setuid/setgid files |

**Network isolation** — force traffic through the proxy:

| Directive | Effect |
|-----------|--------|
| `IPAddressDeny=any` (on bridges) | socat bridges can't make arbitrary network connections |
| nftables `credproxy-lockdown` | Blocks all VM outbound except DNS and Tailscale at the host level |
| Services bind to `127.0.0.1` only | Gateway and OpenCode are not reachable from the TAP interface |

**Restart policy** — availability without infinite retry loops:

| Directive | Effect |
|-----------|--------|
| `Restart=on-failure` | Restarts after crashes but not after clean shutdown |
| `RestartSec=5s` / exponential backoff | Prevents tight restart loops if a dependency is down |
| `StartLimitBurst=3` | Gives up after 3 rapid failures rather than thrashing |

### The Constraints Together

The security invariants, systemd hardening, and technology choices form
interlocking layers:

```
                              ┌─────────────────────────────┐
                              │        Agent Code           │
                              │    (untrusted, LLM-gen)     │
                              └──────────┬──────────────────┘
                                         │
                    ┌────────────────────┐│┌────────────────────────┐
                    │  MicroVM (KVM)     │││  Network Lockdown      │
                    │  Hardware boundary │││  nftables blocks all   │
                    │  Separate kernel   │││  outbound except DNS   │
                    └────────────────────┘│└────────────────────────┘
                                         │
                    ┌────────────────────┐│┌────────────────────────┐
                    │  VSOCK Transport   │││  Systemd Hardening     │
                    │  No guest network  │││  ProtectProc, no caps, │
                    │  exposure          │││  read-only fs, no priv │
                    └────────────────────┘│└────────────────────────┘
                                         │
                    ┌────────────────────┐│┌────────────────────────┐
                    │  OIDC (Keycloak)   │││  OPA (Rego)            │
                    │  Identity: who     │││  Authorization: may    │
                    │  is this agent?    │││  this agent use this   │
                    │                    │││  credential for this   │
                    │                    │││  domain?               │
                    └────────────────────┘│└────────────────────────┘
                                         │
                    ┌────────────────────┐│┌────────────────────────┐
                    │  OpenBao           │││  Temporal              │
                    │  Secrets: deliver  │││  Audit: log every      │
                    │  real creds JIT,   │││  credential access     │
                    │  scoped by ACL     │││  with full lifecycle   │
                    └────────────────────┘│└────────────────────────┘
                                         │
                    ┌────────────────────┐│┌────────────────────────┐
                    │  Placeholder       │││  Response Scrubbing    │
                    │  Substitution      │││  Remove real creds     │
                    │  Inject real creds │││  from upstream         │
                    │  into request      │││  responses             │
                    └────────────────────┘│└────────────────────────┘
                                         │
                                         ▼
                              ┌─────────────────────────────┐
                              │      Upstream API           │
                              │  (Anthropic, OpenAI, etc.)  │
                              └─────────────────────────────┘
```

Each layer addresses a different axis of the problem:

- **MicroVM**: Can the agent escape its sandbox? → No, hardware boundary.
- **VSOCK**: Can the agent intercept the proxy channel? → No, not a network interface.
- **Network lockdown**: Can the agent bypass the proxy? → No, all TCP/UDP blocked.
- **OIDC**: Who is this agent? → Verified JWT with roles.
- **OPA**: May this agent use this credential? → Policy-as-code, domain-bound.
- **OpenBao**: Where do secrets live? → In a vault, delivered JIT, scoped by ACL.
- **Temporal**: What happened? → Full lifecycle audit trail, queryable.
- **Placeholder substitution**: How do secrets flow? → Opaque tokens in, real values only in proxy memory.
- **Response scrubbing**: Can secrets leak back? → Real values replaced before agent sees the response.
- **Systemd hardening**: What if a service is compromised? → Minimal privileges, isolated filesystem, no escalation.

---

## NixOS Module Hierarchy

```
flake.nix
├── nixosModules
│   ├── openclaw             ← modules/openclaw/        (9 Nix files)
│   ├── openclaw-vm          ← modules/openclaw-vm/default.nix
│   ├── openclaw-vm-guest    ← modules/openclaw-vm/guest.nix
│   ├── credential-proxy     ← modules/credential-proxy/default.nix
│   ├── credential-proxy-guest    ← modules/credential-proxy/guest.nix
│   ├── credential-proxy-openbao  ← modules/credential-proxy/openbao-policy.nix
│   └── default              ← openclaw + openclaw-vm + credential-proxy
│
├── nixosConfigurations
│   ├── test-vm              (CID 2, TAP vm-oc, MAC 02:...:02)
│   └── test-vm-boot         (CID 42, TAP vm-oc-test, MAC 02:...:42)
│
└── packages
    ├── credential-proxy     (Go binary)
    ├── test-vm              (microvm-run script)
    └── test-vm-boot         (isolated boot-test script)
```

### Module Import Graph

```
HOST:
openclaw-vm/default.nix
  ├── imports into microvm guest config:
  │   ├── openclaw-vm/guest.nix
  │   └── credential-proxy/guest.nix (when credentialProxy.enable)
  │
  └── credential-proxy/default.nix (host-side proxy service)
        └── credential-proxy/openbao-policy.nix

CONTAINER MODE (separate):
openclaw/default.nix
  ├── secrets.nix    (sops-nix)
  ├── container.nix  (Podman)
  ├── network.nix    (container networking)
  ├── instance.nix   (per-instance config)
  ├── bridge.nix     (inter-instance RPC)
  ├── keycloak.nix   (OIDC provider)
  ├── openbao.nix    (secret backend)
  └── injector.nix   (zero-trust sidecar)
```

---

## Host ↔ Guest Architecture

### Systemd Service Map

```
HOST SERVICES                              GUEST SERVICES (inside MicroVM)
═══════════════                            ══════════════════════════════

microvm@openclaw-vm.service                openclaw-gateway
  └── QEMU process (MicroVM)                 └── OpenClaw gateway (:18789, loopback)

openclaw-gateway-proxy                     opencode-server
  └── socat TCP:127.0.0.1:18789               └── OpenCode server (:4096, loopback)
          ↔ VSOCK:4:18789                        (requires openclaw-gateway)

credproxy                                  vsock-gateway-proxy
  └── Go binary (VSOCK listener :18790)      └── socat VSOCK:4:18789
      MITM proxy + Temporal worker                   ↔ TCP:127.0.0.1:18789

credproxy-ca-init                          credproxy-vsock-bridge
  └── OpenSSL: generate EC P-256 MITM CA     └── socat TCP:localhost:18790
                                                     ↔ VSOCK:2:18790

credproxy-temporal                         credproxy-ca-trust (devMode)
  └── temporal server start-dev (:7233)      └── poll /mnt/credproxy/ca/ca.crt
                                                 → /run/credproxy/ca-bundle.crt

credproxy-openbao-dev (devMode)            credproxy-openbao-bridge (devMode)
  └── bao server -dev (:8200)                └── socat TCP:localhost:8200
                                                     ↔ VSOCK:2:8200

credproxy-openbao-provision (devMode)      credproxy-oidc-creds (devMode)
  └── OIDC identity, KV v2 secrets           └── poll /mnt/credproxy/oidc-client.env

credproxy-openbao-vsock (devMode)          credproxy-placeholder-env
  └── socat VSOCK-LISTEN:8200                └── read fw_cfg → /run/credproxy/placeholder.env
          ↔ TCP:localhost:8200
```

### VSOCK Channel Map

```
VSOCK CID 2 (host)                    VSOCK CID 4 (guest, default)
══════════════════                    ════════════════════════════

Port 18789: gateway access ──────────── Port 18789: gateway proxy
  host socat → guest gateway            guest socat → localhost:18789

Port 18790: credproxy listener ──────── Port 18790: credproxy bridge
  Go binary (VSOCK listener)            guest socat → localhost:18790

Port 8200: OpenBao (devMode) ────────── Port 8200: OpenBao bridge
  host socat → localhost:8200           guest socat → localhost:8200
```

### Secrets Delivery

```
fw_cfg (QEMU firmware config):            VirtiOFS (devMode only):
  openclaw-config      → gateway creds      host: /var/lib/credproxy/
  tailscale-authkey    → ephemeral key         ├── ca/ca.key  (0400)
  credproxy-placeholder-env → placeholder      ├── ca/ca.crt  (0444)
                             mappings          ├── oidc-client.env  (0600)
                                               └── temporal.db
                                            guest: /mnt/credproxy/
                                               └── (polled at boot)
```

### Network Topology

```
┌─────────────────────────────────────────────────────────────────────────┐
│ HOST                                                                    │
│                                                                         │
│   systemd-resolved (:53)                                                │
│          │                                                              │
│   br-openclaw (10.88.0.1/24)                                            │
│          │                                                              │
│          ├── vm-oc (TAP) ──── nftables masquerade ──── internet         │
│          │                                                              │
│          └── nftables credproxy-lockdown:                               │
│              BLOCK all VM outbound EXCEPT:                              │
│                - DNS (UDP 53 to host)                                   │
│                - Tailscale (UDP 41641)                                  │
│              FORCE all HTTP(S) through credential proxy                 │
│                                                                         │
│   VSOCK (/dev/vhost-vsock) ───── immune to nftables (not TCP/IP)       │
└─────────────────────────────────────────────────────────────────────────┘
         │
         │ (virtio, zero-copy)
         │
┌─────────────────────────────────────────────────────────────────────────┐
│ GUEST (MicroVM)                                                         │
│                                                                         │
│   enp0s4 (TAP, 10.88.0.2/24) ──── gateway: 10.88.0.1, DNS: 10.88.0.1  │
│   tailscale0 (optional) ──── SSH, HTTPS (Caddy reverse proxy)          │
│   VSOCK ──── ports 18789, 18790, 8200 (no firewall applies)            │
│                                                                         │
│   Environment:                                                          │
│     HTTP_PROXY=http://localhost:18790                                    │
│     HTTPS_PROXY=http://localhost:18790                                   │
│     SSL_CERT_FILE=/run/credproxy/ca-bundle.crt (devMode)                │
│     ANTHROPIC_API_KEY=agent-vault-<uuid>  (placeholder, not real key)   │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## credential-proxy (Go Binary)

### Package Dependency Graph

```
main
  ├── config        Config, OIDCConfig, VaultConfig, TemporalConfig, Credential
  ├── authn         Verifier interface, OIDCVerifier, AgentIdentity
  ├── authz         Evaluator interface, OPAEvaluator, AuthzRequest/Result
  ├── vault         SecretStore interface, OpenBaoClient, CredentialValue
  ├── proxy         Gateway (http.Handler), RequestRegistry, placeholder, sanitizer
  ├── workflows     ProxyRequestWorkflow, Activities, RequestContext, enums
  └── audit         SearchAttributes (Temporal visibility)

proxy ──────────► workflows  (RequestContext, WorkflowDecision, ContextRegistry)
proxy ──────────► authn      (Verifier)
proxy ──────────► config     (Config)
workflows ──────► authz      (Evaluator)
workflows ──────► vault      (SecretStore)
workflows ──────► config     (Config)
workflows ──────► audit      (SearchAttributes)
```

### Key Interfaces

```
authn.Verifier
  └── VerifyToken(ctx, rawToken) → (*AgentIdentity, error)
      Concrete: OIDCVerifier (Keycloak JWKS)

authz.Evaluator
  └── Evaluate(ctx, *AuthzRequest) → (*AuthzResult, error)
      Concrete: OPAEvaluator (embedded Rego)

vault.SecretStore
  └── FetchCredential(ctx, vaultPath) → (*CredentialValue, error)
      Concrete: OpenBaoClient (KV v2)

workflows.ContextRegistry
  └── Load(requestID) → (*RequestContext, bool)
      Concrete: proxy.RequestRegistry (sync.Map + TTL sweeper)
```

### Ownership Hierarchy

```
main()
├── config.Config               ← loaded from YAML at startup
├── authn.OIDCVerifier          ← JWKS fetched at startup
├── authz.OPAEvaluator          ← .rego files loaded at startup
├── vault.OpenBaoClient         ← health-checked at startup
├── temporalclient.Client       ← connected at startup
├── proxy.RequestRegistry       ← sync.Map + background sweeper goroutine
│     └── sweeper goroutine (TTL: 120s, interval: 30s)
├── proxy.Gateway               ← http.Handler (holds all above)
│     ├── goproxy.ProxyHttpServer
│     │     ├── HandleConnect    → handleConnect (domain allowlist + JWT extract)
│     │     ├── OnRequest.DoFunc → handleRequest (JWT verify + workflow start)
│     │     └── OnResponse.DoFunc→ handleResponse (scrub + signal)
│     ├── connTokens (sync.Map)  → remoteAddr → JWT (TTL-evicted)
│     ├── registry               → requestID → *RequestContext
│     └── verifier               → authn.Verifier
├── worker.Worker               ← Temporal worker (same process)
│     ├── ProxyRequestWorkflow   (registered)
│     └── Activities             (registered)
│           ├── Store     → vault.SecretStore
│           ├── Config    → *config.Config
│           ├── Evaluator → authz.Evaluator
│           └── Registry  → workflows.ContextRegistry
└── http.Server                 ← serving on VSOCK listener
```

### Typed Enums

```
DecisionStatus (int, iota):     DenialReason (int, iota):
  DecisionAllowed = 0             ReasonNone = 0
  DecisionDenied  = 1             ReasonAuthenticationFailed = 1  → 407
  DecisionError   = 2             ReasonAuthorizationDenied  = 2  → 403
                                  ReasonCredentialInjectionFailed = 3 → 502
ProxyStatus (int, iota):          ReasonTimeout = 4               → 504
  StatusInProgress = 0
  StatusSuccess    = 1          SignalName (string):
  StatusDenied     = 2            SignalResponseComplete = "response_complete"
  StatusError      = 3
  StatusTimeout    = 4          CredentialType (string):
                                  "api_key", "bearer", "basic_auth", "header"
```

---

## Per-Request Data Flow

### Full Lifecycle (HTTPS with credential injection)

```
Agent (guest VM)
  │
  │  CONNECT api.anthropic.com:443
  │  Proxy-Authorization: Bearer <JWT>
  │
  ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ handleConnect                                                           │
│  1. stripPort("api.anthropic.com:443") → "api.anthropic.com"           │
│  2. cfg.IsAllowedDomain("api.anthropic.com") → true                    │
│  3. storeConnToken(remoteAddr, JWT)  [with TTL timer]                   │
│  4. return MitmConnect (goproxy performs TLS interception using CA)     │
└──────────────────────────────┬──────────────────────────────────────────┘
                               │
  Agent sends request inside tunnel:
  │  POST /v1/messages
  │  x-api-key: agent-vault-deadbeef-1234-5678-9abc-def012345678
  │  {"model": "claude-sonnet-4-20250514", ...}
  │
  ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ handleRequest                                                           │
│                                                                         │
│  1. resolveToken(req)                                                   │
│     └── loadConnToken(remoteAddr) → JWT                                 │
│                                                                         │
│  2. verifier.VerifyToken(ctx, JWT) → AgentIdentity                      │
│     └── OIDC JWKS validation against Keycloak                           │
│     └── extract: subject, realm_access.roles, groups                    │
│     (reject 407 if invalid)                                             │
│                                                                         │
│  3. req.Header.Del("Proxy-Authorization")                               │
│     req.Header.Set("Accept-Encoding", "identity")                       │
│                                                                         │
│  4. Extract(req) → ["agent-vault-deadbeef-1234-5678-9abc-def012345678"] │
│     └── scan headers, query params, body for placeholder pattern        │
│                                                                         │
│  5. registry.Store(requestID, &RequestContext{                           │
│         Request:    req,                                                │
│         ScrubMap:   {},                                                  │
│         DecisionCh: make(chan *WorkflowDecision, 1),                     │
│         ReplaceFunc: ReplaceInRequest,                                   │
│     })                                                                  │
│                                                                         │
│  6. temporal.ExecuteWorkflow(ProxyRequestWorkflow, ProxyInput{           │
│         RequestID:    requestID,                                        │
│         Claims:       {Subject, Roles, Groups, RawClaims},              │
│         Placeholders: [...],                                            │
│         TargetDomain: "api.anthropic.com",                              │
│     })                                                                  │
│                                                                         │
│  7. BLOCK on <-decisionCh (35s timeout)                                 │
│     └── (workflow runs in parallel — see below)                         │
│                                                                         │
│  8. decision.Status == DecisionAllowed                                  │
│     └── store requestState{scrubMap, workflowID, runID} in ctx.UserData │
│     └── return modified req (credentials already injected in-place)     │
└──────────────────────────────┬──────────────────────────────────────────┘
                               │
              PARALLEL: ProxyRequestWorkflow
              ┌────────────────────────────────────────────────────────┐
              │                                                        │
              │  Step 1: EvaluatePolicy (local activity, 5s timeout)   │
              │    └── resolve credential bindings from config         │
              │    └── OPAEvaluator.Evaluate(AuthzRequest{             │
              │          Identity:     rawClaims,                      │
              │          Placeholders: [...],                          │
              │          TargetDomain: "api.anthropic.com",            │
              │          Credentials:  [{placeholder, bound_domain}],  │
              │        })                                              │
              │    └── if denied → SendDecision(denied) → return       │
              │                                                        │
              │  Step 2: FetchAndInject (local activity, 30s timeout)  │
              │    └── registry.Load(requestID) → *RequestContext      │
              │    └── config.LookupCredential(placeholder) → cred    │
              │    └── vault.FetchCredential(cred.VaultPath)           │
              │          → CredentialValue{Key, HeaderName, Prefix}    │
              │    └── reqCtx.ReplaceFunc({placeholder → realValue})   │
              │          (modifies *http.Request in-place)             │
              │    └── reqCtx.ScrubMap[realValue] = placeholder        │
              │    └── reqCtx.DecisionCh <- &WorkflowDecision{Allowed} │
              │                                                        │
              │  Step 3: Wait for SignalResponseComplete (60s timeout)  │
              │    └── (handleResponse signals after scrubbing)        │
              │                                                        │
              └────────────────────────────────────────────────────────┘
                               │
  goproxy forwards modified request to upstream:
  │  POST https://api.anthropic.com/v1/messages
  │  x-api-key: sk-ant-real-secret-key-12345
  │
  upstream responds
  │
  ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ handleResponse                                                          │
│                                                                         │
│  1. deleteConnToken(remoteAddr) [stops TTL timer]                       │
│                                                                         │
│  2. ScrubCredentials(resp, scrubMap)                                     │
│     └── replace "sk-ant-real-secret-key-12345"                          │
│            with "agent-vault-deadbeef-1234-5678-9abc-def012345678"      │
│     └── update Content-Length                                           │
│                                                                         │
│  3. temporal.SignalWorkflow(workflowID, "response_complete",             │
│        ResponseCompleteMeta{StatusCode, ScrubCount, Bytes})             │
│                                                                         │
│  4. return scrubbed response to agent                                   │
└─────────────────────────────────────────────────────────────────────────┘
```

### Plain HTTP (no CONNECT, no placeholders)

```
Agent → handleRequest → no placeholders found → pass through → upstream → handleResponse → agent
        (JWT still validated; Proxy-Authorization stripped; no workflow started)
```

### Error Paths

```
Domain not in allowlist:
  handleConnect → RejectConnect (connection refused)

Missing/invalid JWT:
  handleRequest → 407 Proxy Auth Required (no workflow started)

OPA policy denies:
  ProxyRequestWorkflow → EvaluatePolicy → denied
    → SendDecision(ReasonAuthorizationDenied) → handler gets 403

Vault fetch fails:
  ProxyRequestWorkflow → FetchAndInject → vault error
    → deny(ReasonCredentialInjectionFailed) → handler gets 502

Timeout (workflow hangs):
  handleRequest → 35s select timeout → 504 Gateway Timeout
  ProxyRequestWorkflow → 60s signal timeout → finalize(StatusError)
```

---

## Concurrency Protocol (TLA+ Verified)

The concurrency protocol between the Handler (goproxy goroutine), the Workflow
(Temporal local activity), and the Response handler is formally modeled in
TLA+/PlusCal at `credential-proxy/model/proxy_protocol.tla`.

### Actors

```
Handler goroutine            Temporal worker goroutine       Response handler goroutine
(goproxy OnRequest)          (ProxyRequestWorkflow)          (goproxy OnResponse)
        │                            │                               │
        │  1. Store RequestContext    │                               │
        │     in registry            │                               │
        │                            │                               │
        │  2. Start workflow ────────►                               │
        │                            │                               │
        │                    3. EvaluatePolicy                       │
        │                       (local activity)                     │
        │                            │                               │
        │                    4. FetchAndInject                        │
        │                       - registry.Load()                    │
        │                       - vault.Fetch()                      │
        │                       - ReplaceInRequest()                 │
        │                       - ScrubMap populated                 │
        │  ◄─── DecisionCh ────── 5. send decision ──┐              │
        │       (buffered, cap=1)                     │              │
        │                                             │              │
        │  6. Return req to goproxy                   │              │
        │     (forwards to upstream)                  │              │
        │                                     7. Wait for signal     │
        │                                        (60s timeout)       │
        │                                             │              │
        │                                             │  8. Upstream responds
        │                                             │              │
        │                                             │  9. ScrubCredentials()
        │                                             │
        │                            ◄── signal ───── 10. SignalWorkflow
        │                            │   "response_     (response_complete)
        │                            │    complete"
        │                    11. finalize()
        │                        upsert search attrs
        │                        return ProxyOutput
```

### Safety Invariants (TLC verified)

- **No double-write**: At most one value is ever sent on DecisionCh
- **Handler always terminates**: Either receives a decision or times out (35s)
- **Registry always cleaned up**: `defer registry.Delete(requestID)` in handler
- **Secrets never serialized**: Real credentials exist only in local activity memory

---

## Placeholder Token Format

```
agent-vault-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}
└── prefix ─┘└──────────────────── UUID v4 ──────────────────────────────┘

Example: agent-vault-deadbeef-1234-5678-9abc-def012345678
```

Placeholders are scanned in: request headers, URL query parameters, request body
(up to 10 MiB). Replacement uses `strings.NewReplacer` for single-pass
substitution (prevents double-substitution when a replacement value contains
another placeholder pattern).

---

## Audit Trail (Temporal Search Attributes)

Every proxied request with credential injection creates a Temporal workflow
execution with typed search attributes:

| Attribute | Key | Type | Example |
|-----------|-----|------|---------|
| Agent ID | `CredProxyAgentID` | string | `agent-test-001` |
| Target Domain | `CredProxyTargetDomain` | string | `api.anthropic.com` |
| Credential Ref | `CredProxyCredentialRefHash` | string | `agent-vault-dead...` |
| Status | `CredProxyStatus` | string | `success`, `denied`, `error` |

Workflow output (`ProxyOutput`) records: status, latency_ms, scrub_count, bytes.

---

## Config System

```yaml
listener:
  cid: 2           # VSOCK context ID (host = 2)
  port: 18790      # VSOCK port

oidc:
  issuer_url: "http://127.0.0.1:8080/realms/openclaw"
  audience: "credproxy"

opa:
  policy_dir: "/nix/store/.../policies"

vault:
  address: "http://127.0.0.1:8200"
  token: "dev-token"    # devMode only; production uses AppRole

temporal:
  host_port: "localhost:7233"
  namespace: "default"
  task_queue: "credproxy"

allowed_domains:
  - "api.anthropic.com"
  - "api.openai.com"

credentials:
  - placeholder: "agent-vault-00000000-0000-0000-0000-000000000001"
    type: "api_key"
    vault_path: "secret/data/openclaw/credentials/anthropic"
    bound_domain: "api.anthropic.com"
    header_name: "x-api-key"
    header_prefix: ""

ca_key_path: "/var/lib/credproxy/ca/ca.key"
ca_cert_path: "/var/lib/credproxy/ca/ca.crt"
```

Config is generated by Nix as JSON (valid YAML 1.2) and passed to the Go binary
via `--config`. At load time, two indexes are built: `placeholder → Credential`
and `domain → allowed` for O(1) lookup.

---

## Key File Reference

| File | Role |
|------|------|
| `flake.nix` | Flake outputs: 7 nixosModules, 2 nixosConfigurations, packages, checks |
| `modules/openclaw-vm/default.nix` | Host: MicroVM, TAP bridge, VSOCK socat, nftables, Caddy |
| `modules/openclaw-vm/guest.nix` | Guest: gateway, OpenCode, Tailscale, user model, state dirs |
| `modules/credential-proxy/default.nix` | Host: credproxy service, Temporal, CA init, OpenBao dev |
| `modules/credential-proxy/guest.nix` | Guest: VSOCK bridge, HTTP_PROXY, CA trust, placeholder env |
| `modules/credential-proxy/openbao-policy.nix` | OpenBao read-only KV v2 policy |
| `modules/openclaw/default.nix` | Container mode: Podman orchestration + zero-trust |
| `credential-proxy/main.go` | Entry point: init all components, VSOCK listener |
| `credential-proxy/proxy/gateway.go` | Gateway (http.Handler): goproxy + MITM CA + connTokens |
| `credential-proxy/proxy/handlers.go` | handleConnect, handleRequest, handleResponse |
| `credential-proxy/proxy/placeholder.go` | Extract + ReplaceInRequest (regex scan + single-pass replace) |
| `credential-proxy/proxy/sanitizer.go` | ScrubCredentials (response body credential removal) |
| `credential-proxy/proxy/registry.go` | RequestRegistry (sync.Map + TTL sweeper) |
| `credential-proxy/workflows/proxy_workflow.go` | ProxyRequestWorkflow (Temporal: authz → inject → signal) |
| `credential-proxy/workflows/activities.go` | EvaluatePolicy, FetchAndInject, SendDecision |
| `credential-proxy/authn/oidc.go` | OIDC Verifier (Keycloak JWKS, error classification) |
| `credential-proxy/authz/engine.go` | OPA Evaluator (embedded Rego, allow + deny_reasons) |
| `credential-proxy/vault/client.go` | OpenBao KV v2 client (FetchCredential, HealthCheck) |
| `credential-proxy/config/config.go` | Config parsing, validation, credential/domain indexes |
| `credential-proxy/audit/search_attributes.go` | Temporal search attribute keys + typed updates |
| `credential-proxy/model/proxy_protocol.tla` | TLA+/PlusCal concurrency model (source of truth) |
| `credential-proxy/authz/policies/*.rego` | OPA authorization policies |
| `scripts/test-vm-boot.sh` | Isolated boot-test helper (TAP setup, virtiofsd, cleanup) |
