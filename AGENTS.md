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

