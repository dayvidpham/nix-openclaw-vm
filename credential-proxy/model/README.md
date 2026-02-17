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
