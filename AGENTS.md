# Agent Instructions

This project uses **bd** (beads) for issue tracking. Run `bd onboard` to get started.

## Quick Reference

```bash
bd ready              # Find available work
bd show <id>          # View issue details
bd update <id> --status in_progress  # Claim work
bd close <id>         # Complete work
bd sync               # Sync with git
```

## Dependencies

Dependencies flow from **leaf work up to the user-facing request**. The leaf tasks (implementation details) must complete first, unblocking higher-level items, until the original request can be closed.

The chain reads left-to-right as "blocked by":

```
REQUEST -> URE -> PROPOSAL -> IMPL PLAN -> slices -> leaf tasks
```

Meaning: REQUEST is blocked by URE, URE is blocked by PROPOSAL, PROPOSAL is blocked by the IMPL PLAN (implementation plan), the IMPL PLAN is blocked by each vertical slice, and each slice is blocked by its individual leaf tasks.

### Correct: `--blocked-by` points at what must finish first

```bash
# "REQUEST is blocked by URE" — URE must complete before REQUEST can close
bd dep add request-id --blocked-by ure-id

# "PROPOSAL is blocked by IMPL PLAN"
bd dep add proposal-id --blocked-by impl-plan-id

# "IMPL PLAN is blocked by each slice"
bd dep add impl-plan-id --blocked-by slice-1-id
bd dep add impl-plan-id --blocked-by slice-2-id

# "slice is blocked by its leaf tasks"
bd dep add slice-1-id --blocked-by leaf-task-a-id
bd dep add slice-1-id --blocked-by leaf-task-b-id
```

Produces the correct tree (leaf work at the bottom, user request at the top):

```
REQUEST
  └── blocked by URE
        └── blocked by PROPOSAL
              └── blocked by IMPL PLAN
                    ├── blocked by slice-1
                    │     ├── blocked by leaf-task-a
                    │     └── blocked by leaf-task-b
                    └── blocked by slice-2
                          ├── blocked by leaf-task-c
                          └── blocked by leaf-task-d
```

### Wrong: reversed direction

```bash
# WRONG — this says "URE is blocked by REQUEST", meaning the request
# must finish before requirements gathering can start (backwards)
bd dep add ure-id --blocked-by request-id
```

Produces a nonsensical tree where leaf tasks must wait for the request to close:

```
leaf-task-a
  └── blocked by slice-1
        └── blocked by IMPL PLAN
              └── blocked by PROPOSAL
                    └── blocked by URE
                          └── blocked by REQUEST   # backwards
```

**Rule of thumb:** The `--blocked-by` target is always the thing you do *first*. Work flows bottom-up; closure flows top-down.

## Testing

### How to run tests

**Nix module evaluation check** — validates the full module tree without booting:
```bash
nix flake check
```
This runs `checks.x86_64-linux.eval-test-vm`, which builds `nixosConfigurations.test-vm.config.system.build.toplevel`. If module options, `mkIf` conditions, or types are broken it fails here.

**credential-proxy Go tests** — run from the subdirectory:
```bash
cd credential-proxy
go test -race ./...
```

Run a single package or test:
```bash
go test -race ./proxy/ -run TestGateway_PlaceholderSubstitution -v
go test -race ./authz/ -v
```

The `-race` flag is mandatory for all test runs. It enables the Go data race detector and is also set in the Nix `checkPhase` so Nix builds reproduce the same check.

**Dev shell** — provides Go toolchain, gopls, staticcheck, delve, temporal-cli:
```bash
cd credential-proxy
nix develop   # or direnv allow if .envrc is present
```

**Build the VM image** (no boot required):
```bash
nix build .#test-vm
```

**Boot the test VM**:
```bash
nix build .#test-vm && ./result/bin/microvm-run
```
The `test-vm` config has `dangerousDevMode` enabled and sops/Tailscale/Caddy disabled, so it boots without external infrastructure.

### Test package map

| Package | Type | What it covers |
|---------|------|----------------|
| `proxy` | Integration | Full gateway round-trip: placeholder substitution, response scrubbing, domain allowlist, 407/403 enforcement. Spins up real `httptest` servers and a real `Gateway`. Mocks only `authn.Verifier`, `vault.SecretStore`, and the Temporal client. |
| `workflows` | Integration (Temporal testsuite) | `FetchAndForward` and `ValidateAndResolve` activities via `testsuite.TestActivityEnvironment`. |
| `authz` | Integration | OPA evaluator against the **real** Rego policy (`authz/policies/`). Tests allow/deny decisions, domain binding enforcement, role requirements. |
| `authn` | Unit | OIDC error classification (`ErrTokenExpired`, `ErrInvalidIssuer`, `ErrInvalidAudience`) and Keycloak `realm_access.roles` extraction. |

### TLA+ formal model

The TLA+/PlusCal model in `credential-proxy/model/` formally verifies the concurrency protocol between the Handler, Workflow, and Response actors. It is the **source of truth** for protocol design.

**Model-first rule:** Any change to the concurrency protocol MUST be modeled and verified in TLA+ **before** the corresponding Go code is written. Agents that refactor protocol-relevant code MUST run `pcal` + `tlc` as a quality gate before committing.

**Validation command** (from `credential-proxy/`, inside the dev shell):
```bash
pcal model/proxy_protocol.tla && tlc model/proxy_protocol.tla -config model/proxy_protocol.cfg
```

Expected output: `Model checking completed. No error has been found.`

For the full model documentation — actor-to-file correspondence, variable mapping, change triggers, and the protocol change workflow — see [`credential-proxy/model/README.md`](credential-proxy/model/README.md).

### Type safety rules

- **No stringly-typed APIs.** All status codes, denial reasons, decision types, signal names, and error categories MUST be strongly-typed Go enums (`type Foo int` with `iota` constants). String representations are only acceptable at serialization boundaries (JSON, Temporal search attributes, HTTP responses) via `.String()` methods.
- **No string literals at API boundaries.** Every string that crosses a function signature, channel, or struct field must reference a named constant or typed enum value. Bare `"authentication_failed"` or `"response_complete"` literals are not acceptable.
- **Use `ast-grep` to audit.** Run the project's rules before submitting changes. Any new string literal in a function signature, struct field type, or channel type is a code smell.

  ```bash
  # Run all rules at once via the project config (from credential-proxy/):
  cd credential-proxy && ast-grep scan --config sgconfig.yml .

  # Or run individual rules from repo root:
  ast-grep scan -r credential-proxy/ast-grep/no-bare-signal-literals.yml credential-proxy/
  ast-grep scan -r credential-proxy/ast-grep/no-string-status-types.yml credential-proxy/
  ast-grep scan -r credential-proxy/ast-grep/no-stringly-typed-args.yml credential-proxy/
  ast-grep scan -r credential-proxy/ast-grep/no-untyped-string-const.yml credential-proxy/
  ```

  | Rule file | Detects | Severity |
  |-----------|---------|----------|
  | `ast-grep/no-bare-signal-literals.yml` | Bare string literals in `GetSignalChannel()` or `SignalWorkflow()` signal-name argument | error |
  | `ast-grep/no-string-status-types.yml` | `type XStatus string`, `type XDecision string`, `type XReason string` declarations | warning |
  | `ast-grep/no-stringly-typed-args.yml` | String literals in `WorkflowDecision` or `SendDecisionInput` Status/Reason fields | error |
  | `ast-grep/no-untyped-string-const.yml` | Untyped `const X = "..."` where X contains Status/Reason/Decision/Signal | warning |

  All four rules must produce **zero violations in non-vendor code** before merging.

### Test writing rules for agents

- **Do not mock the system under test.** `proxy` tests mock `authn.Verifier` and `vault.SecretStore`, but the `Gateway` itself is real. `authz` tests run against the real `OPAEvaluator` with the real Rego files.
- **Use shared fixtures.** `gateway_test.go` defines `defaultMockVerifier()`, `defaultMockEvaluator()`, `defaultMockStore()`, and `testConfig()` for reuse across cases. Add new cases using those helpers; do not inline config YAML in individual tests.
- **Assert observable outcomes.** Test HTTP status codes, response bodies, and header values. Do not assert on internal struct fields.
- **Compile-time interface checks.** Each test file uses `var _ SomeInterface = (*mockFoo)(nil)` to catch interface drift early. Add this pattern for any new mock.

### VSOCK testing

The VSOCK transport between VM guest and host is exercised only in a live VM boot (`nix build .#test-vm && ./result/bin/microvm-run`). For isolated VSOCK channel testing without a full boot, use `socat`:

```bash
# Emulate host side (listens on VSOCK CID 2, port 8080)
socat VSOCK-LISTEN:8080,fork TCP:localhost:8080

# Emulate guest side (connects out through VSOCK)
socat TCP-LISTEN:9090,fork VSOCK-CONNECT:2:8080
```

## Design References

The credential-proxy design draws on patterns from established OSS projects. Detailed research reports live in `docs/research/`.

| Project | What We Took | Report |
|---------|-------------|--------|
| [elazarl/goproxy](https://github.com/elazarl/goproxy) | HTTP proxy foundation — MITM CONNECT, handler registration, `UserData` propagation, `CertStorage` interface | [`goproxy.Rmd`](docs/research/goproxy.Rmd) |
| [CyberArk Secretless Broker](https://github.com/cyberark/secretless-broker) | Provider factory pattern, credential zeroization, fail-through error collection | [`secretless-broker.Rmd`](docs/research/secretless-broker.Rmd) |
| [Octelium](https://github.com/octelium/octelium) | `SecretManager` caching with watch-based invalidation, typed auth scheme union | [`octelium.Rmd`](docs/research/octelium.Rmd) |
| [Ory Oathkeeper](https://www.ory.com/docs/oathkeeper) | Pipeline architecture (authn→authz→mutate), session state threading | [`oathkeeper.Rmd`](docs/research/oathkeeper.Rmd) |
| [Vultrino](https://github.com/zachyking/vultrino) | Human-readable alias system, two-phase config validation | [`vultrino.Rmd`](docs/research/vultrino.Rmd) |
| [Agent Gateway](https://github.com/agentgateway/agentgateway) | CEL-based authorization, per-route inline policies | [`agent-gateway.Rmd`](docs/research/agent-gateway.Rmd) |
| [Peta Core](https://github.com/dunialabs/peta-core) | JIT decryption with TTL, short-lived agent tokens, batch audit logging | [`peta-core.Rmd`](docs/research/peta-core.Rmd) |
| [Keycloak](https://www.keycloak.org/) | OIDC realm config, client credential grants, `realm_access.roles` claim structure | [`keycloak.Rmd`](docs/research/keycloak.Rmd) |
| [OpenBao](https://openbao.org/) | KV v2 secret engine, ACL policy model, AppRole auth, audit devices | [`openbao.Rmd`](docs/research/openbao.Rmd) |
| [Temporal](https://temporal.io/) | Workflow vs activity distinction, search attributes, sealed activities for secret safety | [`temporal.Rmd`](docs/research/temporal.Rmd) |
| [Temporal Go SDK](https://go.temporal.io/sdk) | `workflow.Context`, typed search attributes, `testsuite` patterns, non-retryable errors | [`temporal-go-sdk.Rmd`](docs/research/temporal-go-sdk.Rmd) |
| [Temporal Agent Ecosystem](https://github.com/temporalio/awesome-temporal) | Workflow-as-orchestrator for access decisions, JIT credential delivery via Vault activities, signal-driven HITL gates | [`temporal-agent-orchestration.Rmd`](docs/research/temporal-agent-orchestration.Rmd) |

## Review Criteria

All implementation plans, slices, and code changes must be reviewed against these three axes:

### 1. Correctness (spirit and technicality)

- Does the implementation faithfully serve the user's original request (REQUEST) and the requirements captured in the URD?
- Are the technical decisions consistent with the rationale in the PROPOSAL?
- Are there gaps where the proposal says one thing but the code does another?
- Are there requirements from the URD that are silently dropped or contradicted?

### 2. Test quality

- **Favour integration and end-to-end tests** over brittle unit tests that break on every refactor. Unit tests are appropriate for pure logic; anything involving I/O, state, or multi-component interaction should be integration-tested.
- **The system under test must NOT be mocked out.** If the test mocks the very thing it claims to test, nothing is actually tested. Mock *dependencies*, not the subject.
- **Use fixtures for common test values.** Repeatedly defining the same config, identity, placeholder, or credential inline across tests is brittle — a single schema change forces N updates. Define shared fixtures once and reference them.
- **Test real behaviour, not implementation details.** Tests should assert on observable outcomes (HTTP status codes, response bodies, side effects) not on internal method calls or struct field values.

### 3. Elegance and complexity matching

- **Design the API you know you will need**, even if further complexity is deferred. Public interfaces should be complete for the known use cases — don't force callers to work around missing methods that are obviously needed.
- **Do not over-engineer.** If the problem has 3 moving parts, the solution should have ~3 moving parts. Premature abstractions, plugin systems, and configurability for hypothetical futures add cost without value.
- **Do not under-engineer.** If the problem is inherently complex (e.g., MITM TLS + credential injection + response scrubbing + audit), the solution should match that complexity. Cutting corners on security or correctness to reduce code is not simplicity.
- **Complexity should be proportional to the innate complexity of the problem domain**, not to the amount of code written. Three similar lines are better than a premature abstraction. But a genuine 5-component pipeline deserves 5 clear components.

## Agent Orchestration

This project uses two external tools for multi-agent coordination. Both live in `~/codebases/dayvidpham/aura-scripts/`.

### aura-swarm — Epic-based worktree workflow

Creates an isolated git worktree for an epic, gathers beads task context, and launches a single Claude instance (in a tmux session) that uses Agent Teams internally to coordinate workers.

```bash
~/codebases/dayvidpham/aura-scripts/aura-swarm start --epic <epic-id> --model sonnet
~/codebases/dayvidpham/aura-scripts/aura-swarm status
~/codebases/dayvidpham/aura-scripts/aura-swarm attach <epic-id>
~/codebases/dayvidpham/aura-scripts/aura-swarm stop <epic-id>
~/codebases/dayvidpham/aura-scripts/aura-swarm merge <epic-id>
~/codebases/dayvidpham/aura-scripts/aura-swarm cleanup <epic-id>
```

Branch model:
```
main
 └── epic/<epic-id>                 (aura-swarm creates this branch + worktree)
       ├── agent/<task-id-1>         (Claude's Agent Teams creates these)
       ├── agent/<task-id-2>
       └── agent/<task-id-3>
```

### launch-parallel.py — Ad-hoc parallel agent launches

Launches parallel Claude agents in tmux sessions with role-based instructions from `~/.claude/commands/aura:{role}.md`.

```bash
# Launch 3 reviewers
~/codebases/dayvidpham/aura-scripts/launch-parallel.py --role reviewer -n 3 --prompt "Review plan..."

# Launch supervisor with task IDs
~/codebases/dayvidpham/aura-scripts/launch-parallel.py --role supervisor -n 1 \
  --task-id id1 --task-id id2 --prompt "Coordinate these tasks"

# Launch with skill invocation
~/codebases/dayvidpham/aura-scripts/launch-parallel.py --role reviewer -n 3 \
  --skill aura:reviewer:review-plan --prompt "Review plan aura-xyz"

# Dry run (show commands without executing)
~/codebases/dayvidpham/aura-scripts/launch-parallel.py --role supervisor -n 1 --prompt "..." --dry-run
```

### Role instruction files

Both tools load role instructions from `.claude/commands/aura:{role}.md`:
1. Check the project's `.claude/commands/` directory first
2. Fall back to `~/.claude/commands/`

Available roles: `architect`, `supervisor`, `reviewer`, `worker`

### Inter-agent communication

Agents coordinate through **beads** (not a dedicated messaging CLI):
```bash
bd comments add <task-id> "Status update: ..."      # Add comments to shared tasks
bd update <task-id> --notes="Blocked on X"           # Update task notes
bd show <task-id>                                    # Read task state
bd update <task-id> --status=in_progress             # Claim work
bd close <task-id>                                   # Signal completion
```

## Landing the Plane (Session Completion)

**When ending a work session**, you MUST complete ALL steps below. Work is NOT complete until `git push` succeeds.

**MANDATORY WORKFLOW:**

1. **File issues for remaining work** - Create issues for anything that needs follow-up
2. **Run quality gates** (if code changed) - Tests, linters, builds
3. **Update issue status** - Close finished work, update in-progress items
4. **PUSH TO REMOTE** - This is MANDATORY:
   ```bash
   git pull --rebase
   bd sync
   git push
   git status  # MUST show "up to date with origin"
   ```
5. **Clean up** - Clear stashes, prune remote branches
6. **Verify** - All changes committed AND pushed
7. **Hand off** - Provide context for next session

**CRITICAL RULES:**
- Work is NOT complete until `git push` succeeds
- NEVER stop before pushing - that leaves work stranded locally
- NEVER say "ready to push when you are" - YOU must push
- If push fails, resolve and retry until it succeeds

