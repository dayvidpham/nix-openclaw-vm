# nix-openclaw-vm

OpenClaw NixOS modules for container-based and microVM-based deployments, with a MITM credential-injection proxy for zero-trust secret delivery.

## Modules

The flake exports 7 NixOS modules:

| Module | Path | Description |
|--------|------|-------------|
| `openclaw` | `modules/openclaw/` | Container-based OpenClaw deployment (9 Nix files: default, secrets, container, network, instance, bridge, keycloak, openbao, injector) |
| `openclaw-vm` | `modules/openclaw-vm/default.nix` | MicroVM host configuration (launcher, dev mode, VSOCK/TAP/MAC options) |
| `openclaw-vm-guest` | `modules/openclaw-vm/guest.nix` | MicroVM guest configuration (OpenCode on port 4096, OpenClaw gateway on port 18789) |
| `credential-proxy` | `modules/credential-proxy/default.nix` | Host-side credential proxy service (VSOCK listener, OIDC/Vault config, MITM CA) |
| `credential-proxy-guest` | `modules/credential-proxy/guest.nix` | Guest-side proxy wiring (socat bridge, HTTP_PROXY env vars, CA trust) |
| `credential-proxy-openbao` | `modules/credential-proxy/openbao-policy.nix` | OpenBao ACL policy for proxy's AppRole |
| `default` | — | Composes `openclaw` + `openclaw-vm` + `credential-proxy` |

Additionally, `modules/openclaw-vm/debug-tailscale.nix` provides a development-only Tailscale helper.

## Usage

Add as a flake input:

```nix
{
  inputs.openclaw-modules.url = "github:dayvidpham/nix-openclaw-vm";
  inputs.openclaw-modules.inputs.nixpkgs.follows = "nixpkgs";
}
```

Then include in your NixOS configuration:

```nix
{ openclaw-modules, ... }: {
  imports = [ openclaw-modules.nixosModules.default ];
}
```

The `default` module pulls in `openclaw`, `openclaw-vm`, and `credential-proxy`. You can also import individual modules for finer control.

**Important:** The openclaw container modules require standalone `keycloak` and `openbao` modules in your module tree if using zero-trust mode.

## Flake Inputs

| Input | Description |
|-------|-------------|
| `nixpkgs` | NixOS unstable |
| `microvm` | [astro/microvm.nix](https://github.com/astro/microvm.nix) — MicroVM host/guest infrastructure |
| `nix-openclaw` | [openclaw/nix-openclaw](https://github.com/openclaw/nix-openclaw) — OpenClaw application packages |
| `opencode` | [anomalyco/opencode](https://github.com/anomalyco/opencode) — OpenCode editor |
| `credential-proxy` | `path:./credential-proxy` — local Go MITM proxy (vendored as a sub-flake) |

## Flake Outputs

| Output | Description |
|--------|-------------|
| `nixosModules.*` | 7 NixOS modules (see table above) |
| `nixosConfigurations.test-vm` | Standard dev VM (VSOCK CID 2, TAP `vm-oc`, MAC `02:...:02`) |
| `nixosConfigurations.test-vm-boot` | Isolated boot-test VM (VSOCK CID 42, TAP `vm-oc-test`, MAC `02:...:42`) |
| `packages.x86_64-linux.credential-proxy` | Go binary |
| `packages.x86_64-linux.test-vm` | MicroVM runner script |
| `packages.x86_64-linux.test-vm-boot` | Isolated boot-test runner script |
| `devShells.x86_64-linux.default` | Go toolchain + TLA+ tools |
| `checks.x86_64-linux.eval-test-vm` | Module evaluation check |

## Testing

### Nix flake check

`nix flake check` runs the `eval-test-vm` check defined in `flake.nix`. This check evaluates the full `nixosConfigurations.test-vm` module tree — including all openclaw-vm, credential-proxy, and microvm modules — and verifies that NixOS module evaluation succeeds without errors. It does **not** boot the VM; it validates that the module options, types, and conditional logic are consistent.

```bash
nix flake check
```

If you are iterating on module option types or `mkIf` conditions, this is the fastest feedback loop.

### credential-proxy Go tests

The `credential-proxy/` subdirectory is a standalone Go module with its own flake. Run the full test suite from within that directory:

```bash
cd credential-proxy
go test -race ./...
```

The `-race` flag is mandatory — it enables the Go data race detector and matches what the Nix `checkPhase` runs.

The tests are organized by package:

| Package | Type | Coverage |
|---------|------|----------|
| `proxy` | Integration | Full gateway round-trip: placeholder substitution, response scrubbing, domain allowlist, 407/403 enforcement. Spins up real `httptest` servers and a real `Gateway`. Mocks only `authn.Verifier`, `vault.SecretStore`, and Temporal client. |
| `workflows` | Integration | Temporal activity tests (`FetchAndForward`, `ValidateAndResolve`) using `testsuite.TestActivityEnvironment` |
| `authz` | Integration | OPA evaluator tests against the real Rego policy: allow/deny decisions, domain binding, role checking |
| `authn` | Unit | OIDC error classification and Keycloak `realm_access.roles` extraction |

### TLA+ formal concurrency model

The credential-proxy's concurrency protocol (Handler, Workflow, and Response actors communicating via a buffered decision channel and Temporal signals) is formally modeled in TLA+/PlusCal. TLC exhaustively verifies safety invariants (no double-write on the decision channel) and liveness properties (handler always terminates, registry always cleaned up) across all reachable states.

**The TLA+ model is the source of truth for protocol design.** Protocol changes must be modeled and verified in TLA+ before Go code is written. Run the model checker from the dev shell:

```bash
cd credential-proxy
pcal model/proxy_protocol.tla && tlc model/proxy_protocol.tla -config model/proxy_protocol.cfg
```

For the full model documentation — verified properties, actor descriptions, abstraction rationale, actor-to-file correspondence, variable mapping, and the change trigger checklist — see [`credential-proxy/model/README.md`](credential-proxy/model/README.md).

### Dev shell (iterating on credential-proxy)

Enter the dev shell to get Go toolchain, `gopls`, `staticcheck`, `delve`, `temporal-cli`, and TLA+ tools (`pcal`, `tlc`):

```bash
cd credential-proxy
nix develop
```

From inside the shell:

```bash
go test -race ./...                     # run all tests
go test -race ./proxy/ -run TestGateway # run a specific test
go vet ./...                            # run vet
staticcheck ./...                       # run staticcheck
```

### Building the VM image

Build the test-vm runner (does not require booting):

```bash
nix build .#test-vm
```

This evaluates the microvm configuration and produces a runnable script at `result/`. The `eval-test-vm` check in `nix flake check` validates the same configuration at a lower cost.

### Running VM boot tests

To actually boot the VM locally:

```bash
nix build .#test-vm
./result/bin/microvm-run
```

The test-vm configuration (`nixosConfigurations.test-vm`) enables `dangerousDevMode`, disables sops secrets, Tailscale, and Caddy, so it boots with minimal external dependencies.

#### Isolated boot tests (test-vm-boot)

A second VM configuration (`test-vm-boot`) uses a different VSOCK CID (42), TAP interface (`vm-oc-test`), and MAC address so it can run alongside the production VM without conflicts:

```bash
nix build .#test-vm-boot
sudo ./scripts/test-vm-boot.sh
```

The `scripts/test-vm-boot.sh` script handles TAP setup, virtiofsd launch, socket readiness, and cleanup on exit.

### VSOCK

The credential-proxy is designed to forward traffic over VSOCK between VM guest and host. The current test suite validates the HTTP/HTTPS proxy pipeline end-to-end using `httptest` servers; VSOCK transport is exercised only in a live VM boot. If you need to test the VSOCK path without a full boot, use `socat` to emulate the channel:

```bash
# guest side (inside VM)
socat VSOCK-CONNECT:2:8080 TCP:localhost:8080

# host side
socat TCP-LISTEN:8080,fork VSOCK-LISTEN:8080
```
