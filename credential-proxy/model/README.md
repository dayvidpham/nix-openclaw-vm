# credential-proxy: Formal Concurrency Model

This directory contains a **TLA+/PlusCal formal model** of the cross-goroutine
concurrency protocol in `credential-proxy`.  The model is verified by the TLC
model checker and confirms that the protocol is free of deadlock and satisfies
key safety invariants.

## What the model verifies

The proxy handles each request across three concurrent actors:

| Actor | Go counterpart |
|-------|----------------|
| `Handler` | `goproxy` `OnRequest` goroutine |
| `Workflow` | Temporal `ProxyRequestWorkflow` |
| `Response` | `goproxy` `OnResponse` handler |

**Safety invariants** (checked in every reachable state):

| Invariant | What it means |
|-----------|---------------|
| `TypeInvariant` | All variables stay within their declared domains |
| `NoDoubleDecision` | `DecisionCh` receives **at most one** send per request |

`NoDoubleDecision` is the critical one: the buffered channel (cap=1) between the
Workflow's activity goroutines and the Handler goroutine must never receive more
than one write.  A double-write would deadlock or corrupt the result.

**Liveness properties** (checked under WF fairness from `fair process`):

| Property | What it means |
|----------|---------------|
| `HandlerEventuallyCompletes` | The handler goroutine always terminates |
| `RegistryEventuallyCleanedUp` | The registry entry (`defer Delete`) always fires |

**Deadlock detection**: TLC checks by default that every reachable state has at
least one enabled action.

## Results

```
Model checking completed. No error has been found.
154 states generated, 89 distinct states found, 0 states left on queue.
The depth of the complete state graph search is 11.
```

All safety invariants and liveness properties hold across all 89 reachable states.

## How to run TLC

The `tlaplus18` package is already in the `credential-proxy` devShell.  Enter it
and run from the `credential-proxy/` directory:

```bash
nix develop   # enter the devShell (or direnv allow if .envrc present)

# Step 1: translate PlusCal -> TLA+ (modifies the .tla file in-place)
pcal model/proxy_protocol.tla

# Step 2: run the model checker
tlc model/proxy_protocol.tla -config model/proxy_protocol.cfg
```

Expected output: `Model checking completed. No error has been found.`

## File layout

```
model/
  proxy_protocol.tla   -- PlusCal source + auto-generated TLA+ translation
  proxy_protocol.cfg   -- TLC configuration (SPEC, INVARIANTS, PROPERTIES)
  README.md            -- this file
```

## Model structure and abstractions

### Actors

The **Handler** process models the `handleRequest` goroutine, starting at the
point _after_ JWT validation succeeds.  Before `h_register`, `handleRequest`
calls `gw.verifier.VerifyToken` inline: if the JWT is invalid it returns 407
immediately with no registry registration and no workflow start.  The model
covers only the interesting concurrency path (JWT valid, placeholders present).

1. `h_register` — stores `RequestContext` in the registry with a buffered `DecisionCh`
2. `h_start_workflow` — non-blocking `ExecuteWorkflow` call (modeled as `skip`).
   `ProxyInput` carries already-validated `IdentityClaims` (raw JWT never reaches Temporal).
3. `h_wait_decision` — `select { case d := <-DecisionCh: | case <-time.After(35s): }`
   (modeled as a non-deterministic `either` with `await` or `skip`)
4. `h_cleanup` — `defer gw.registry.Delete(requestID)`; sets `handlerDone`

The **Workflow** process abstracts the two Temporal local activities into a single
non-deterministic step (`w_activities`):
- If the registry still exists: non-deterministically sends `"allowed"` or `"denied"`.
  - `"denied"` covers: EvaluatePolicy denial (via `SendDecision` activity) or
    FetchAndInject vault/inject failure (FetchAndInject sends directly).
  - `"allowed"` covers: EvaluatePolicy grants + FetchAndInject succeeds.
- If the registry is gone (handler timed out): no send (no-op).
- After an `"allowed"` send: waits for the `respSig` signal or a 60-second timeout.

This abstraction is correct for the properties being verified because `NoDoubleDecision`
only depends on the _send/no-send_ logic against the registry, not on which specific
activity fails.  The real sequential ordering (EvaluatePolicy → FetchAndInject) is
enforced by the Temporal SDK and does not affect the channel safety property.

The **Response** process models `handleResponse`:
- Waits for `handlerDone` (handler goroutine has settled the request).
- If the request was forwarded, sets `respSig = "sent"` (scrub + signal workflow).
- If not forwarded (denied or timed out): no-op.

### Key design properties captured

- `DecisionCh` is **buffered** (cap=1) and receives exactly one send per request.
- `FetchAndInject` **always** sends on `DecisionCh` before returning, UNLESS the
  registry entry is already gone (handler timed out).
- `defer gw.registry.Delete` **always** fires, preventing registry leaks.
- Credential values **never** enter Temporal event history (they live only in
  the process-local memory of `FetchAndInject`; `InjectResult` contains only
  metadata).  This property is enforced by construction in the code and not
  directly modeled as a state transition.

## TLA+ model-first development rule

The TLA+ model is the **source of truth** for the concurrency protocol. Any change to the protocol — new states, new actors, changed channel semantics, modified timeouts, added signal paths — MUST be modeled and verified in TLA+ **before** the corresponding Go code is written.

**Workflow for protocol changes:**

1. Update the PlusCal spec in `proxy_protocol.tla`
2. Run `pcal proxy_protocol.tla` to regenerate the TLA+ translation
3. Run `tlc proxy_protocol.tla -config proxy_protocol.cfg` and confirm zero violations
4. Update the correspondence table below if new actors, variables, or files are involved
5. Implement the Go code to match the verified model
6. Update the "What to update" checklist if a new trigger category was introduced

This ordering exists because TLC exhaustively checks all reachable states. A protocol bug caught at the model level costs minutes; the same bug caught in production costs hours or worse. Writing Go first and back-fitting the model defeats the purpose of formal verification.

### Actor-to-file correspondence

Changes to these Go files likely affect the protocol model. If your change touches the **Protocol-relevant code** column, check whether the TLA+ model needs updating.

| TLA+ Actor | TLA+ Labels | Go File(s) | Protocol-relevant code |
|------------|-------------|------------|----------------------|
| `Handler` | `h_register`, `h_start_workflow`, `h_wait_decision`, `h_cleanup` | `proxy/handlers.go` | `handleRequest`: registry Store, ExecuteWorkflow, `select` on DecisionCh, `defer registry.Delete` |
| `Workflow` | `w_activities`, `w_wait_signal` | `workflows/proxy_workflow.go`, `workflows/activities.go` | `ProxyRequestWorkflow`: activity sequencing, signal wait. `FetchAndInject`/`SendDecision`: DecisionCh sends |
| `Response` | `r_check`, `r_signal` | `proxy/handlers.go` | `handleResponse`: scrub-and-signal path, `SignalWorkflow` call |

### TLA+ variable-to-Go mapping

| TLA+ Variable | Go Counterpart | File |
|---------------|----------------|------|
| `reg` | `Gateway.registry` (sync.Map lifecycle) | `proxy/handlers.go` |
| `decCh` | `RequestContext.DecisionCh` (buffered chan, cap=1) | `workflows/activities.go` |
| `decChWrites` | Implicit — enforced by single-send discipline in `FetchAndInject`/`SendDecision` | `workflows/activities.go` |
| `handlerDone` | Handler goroutine return (goproxy sequences OnRequest → OnResponse) | `proxy/handlers.go` |
| `respSig` | `SignalResponseComplete` via `temporal.SignalWorkflow` | `proxy/handlers.go`, `workflows/activities.go` |

## What to update when the protocol changes

Re-run the full workflow (`pcal` then `tlc`) after changing:

1. **JWT validation moved back to workflow** — if `VerifyToken` is ever moved back
   into a Temporal activity, add an `h_jwt_validate` label before `h_register` with
   a non-deterministic early-exit path (returns 407, skips registration).

2. **Handler timeout** — if the 35-second timeout is removed or made conditional,
   remove the `or skip;` branch from `h_wait_decision`.

3. **Channel capacity** — if `DecisionCh` capacity changes from 1, update the
   `NoDoubleDecision` invariant and the `decChWrites \in 0..2` type bound.

4. **Registry lifecycle** — if `Delete` can happen before handler returns, add
   a new registry state and update the `reg \in` domain in `TypeInvariant`.

5. **Workflow signal** — if the `response_complete` signal is removed, remove
   the `w_wait_signal` label and the `respSig` variable.

6. **Additional send paths** — any new code path that calls `DecisionCh <-`
   must be reflected in `w_activities` as a new `either` branch.
