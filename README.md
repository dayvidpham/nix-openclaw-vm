# nix-openclaw-vm

OpenClaw NixOS modules for container-based and microVM-based deployments.

## Modules

- `openclaw` — Container-based OpenClaw deployment (9 NixOS modules + bridge script)
- `openclaw-vm` — MicroVM-based deployment (host module)
- `openclaw-vm-guest` — MicroVM guest configuration

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

**Important:** The openclaw container modules require standalone `keycloak` and `openbao` modules in your module tree if using zero-trust mode.

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
go test ./...
```

The tests are organized by package:

| Package | Coverage |
|---------|----------|
| `proxy` | Integration tests for the HTTP gateway: placeholder substitution, response scrubbing, domain allowlist enforcement, auth rejection, authz deny |
| `workflows` | Temporal activity tests (`FetchAndForward`, `ValidateAndResolve`) using `testsuite.TestActivityEnvironment` |
| `authz` | OPA evaluator tests against the real Rego policy: allow/deny decisions, domain binding, role checking |
| `authn` | Unit tests for OIDC error classification and Keycloak `realm_access.roles` extraction |

The `proxy` tests spin up real `httptest` servers and a real `Gateway` instance. They mock only external dependencies (`authn.Verifier`, `vault.SecretStore`, Temporal client) — the system under test is the gateway itself.

### TLA+ formal concurrency model

The credential-proxy's concurrency protocol (Handler, Workflow, and Response actors communicating via a buffered decision channel and Temporal signals) is formally modeled in TLA+/PlusCal. TLC exhaustively verifies safety invariants (no double-write on the decision channel) and liveness properties (handler always terminates, registry always cleaned up) across all reachable states.

**The TLA+ model is the source of truth for protocol design.** Protocol changes must be modeled and verified in TLA+ before Go code is written. Run the model checker from the dev shell:

```bash
cd credential-proxy
pcal model/proxy_protocol.tla && tlc model/proxy_protocol.tla -config model/proxy_protocol.cfg
```

For the full model documentation — verified properties, actor descriptions, abstraction rationale, actor-to-file correspondence, variable mapping, and the change trigger checklist — see [`credential-proxy/model/README.md`](credential-proxy/model/README.md).

### Dev shell (iterating on credential-proxy)

Enter the dev shell to get Go toolchain, `gopls`, `staticcheck`, `delve`, and `temporal-cli`:

```bash
cd credential-proxy
nix develop
```

From inside the shell:

```bash
go test ./...                     # run all tests
go test ./proxy/ -run TestGateway # run a specific test
go vet ./...                      # run vet
staticcheck ./...                 # run staticcheck
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

### VSOCK

The credential-proxy is designed to forward traffic over VSOCK between VM guest and host. The current test suite validates the HTTP/HTTPS proxy pipeline end-to-end using `httptest` servers; VSOCK transport is exercised only in a live VM boot. If you need to test the VSOCK path without a full boot, use `socat` to emulate the channel:

```bash
# guest side (inside VM)
socat VSOCK-CONNECT:2:8080 TCP:localhost:8080

# host side
socat TCP-LISTEN:8080,fork VSOCK-LISTEN:8080
```
