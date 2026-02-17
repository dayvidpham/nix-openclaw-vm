---------------------------- MODULE proxy_protocol ---------------------------
\* PlusCal model of the credential-proxy concurrency protocol.
\*
\* Models three concurrent actors:
\*   Handler  -- goproxy OnRequest goroutine
\*              (register context -> start workflow -> wait decision -> cleanup)
\*   Workflow -- Temporal ProxyRequestWorkflow
\*              (run activities -> optionally wait for response_complete signal)
\*   Response -- goproxy OnResponse handler
\*              (run after handler finishes -> scrub + signal if forwarded)
\*
\* JWT validation is performed inline in handleRequest (via gw.verifier.VerifyToken)
\* before any registry registration or workflow start.  The model begins at that
\* post-validation point (h_register).  The workflow's two activities (EvaluatePolicy
\* and FetchAndInject) are abstracted into a single non-deterministic step that
\* chooses between all possible outcomes.  This is sufficient to verify the
\* cross-goroutine safety properties without modeling Temporal's internal
\* activity retry machinery.
\*
\* Safety invariants checked by TLC:
\*   TypeInvariant    -- all variables stay within declared domains
\*   NoDoubleDecision -- DecisionCh receives at most one send per request
\*
\* Liveness properties checked under WF fairness ("fair process"):
\*   HandlerEventuallyCompletes  -- handler goroutine always terminates
\*   RegistryEventuallyCleanedUp -- registry entry is always removed
\*
\* Usage:
\*   cd credential-proxy/model
\*   pcal proxy_protocol.tla          \* translate PlusCal -> TLA+ (in-place)
\*   tlc proxy_protocol.tla -config proxy_protocol.cfg

EXTENDS Naturals, TLC

(* --algorithm ProxyProtocol

variables
  \* RequestRegistry entry lifecycle.
  \* "empty"  -- not yet registered (before h_register)
  \* "exists" -- registered; handler goroutine is blocking on decisionCh
  \* "gone"   -- handler cleaned up via defer gw.registry.Delete(requestID)
  reg = "empty",

  \* Buffered decision channel (cap=1).  Exactly one send unblocks the handler.
  \* "empty"   -- no decision yet
  \* "allowed" -- FetchAndInject succeeded; request will be forwarded upstream
  \* "denied"  -- authn/authz/vault failure; request will be rejected
  decCh = "empty",

  \* Counts writes to decCh.  Safety invariant: must never exceed 1.
  decChWrites = 0,

  \* TRUE when the handler goroutine received "allowed" and returned the
  \* modified request for goproxy to forward upstream.
  requestForwarded = FALSE,

  \* TRUE after h_cleanup finishes.  Guards the OnResponse process.
  handlerDone = FALSE,

  \* TRUE after FetchAndInject successfully injected credentials.
  \* Credential values exist only in process-local memory during the activity;
  \* they are NEVER serialized to Temporal event history.
  injected = FALSE,

  \* response_complete signal from OnResponse -> Temporal workflow.
  \* "none" -- not yet sent
  \* "sent" -- OnResponse scrubbed the response body and signalled the workflow
  respSig = "none";

define
  TypeInvariant ==
    /\ reg              \in {"empty", "exists", "gone"}
    /\ decCh            \in {"empty", "allowed", "denied"}
    /\ decChWrites      \in 0..2
    /\ requestForwarded \in BOOLEAN
    /\ handlerDone      \in BOOLEAN
    /\ injected         \in BOOLEAN
    /\ respSig          \in {"none", "sent"}

  \* Safety: the buffered decision channel is written at most once per request.
  \* Three send paths exist (all mutually exclusive per request):
  \*   (a) SendDecision(denied)  -- EvaluatePolicy failure
  \*   (b) FetchAndInject deny   -- vault/inject failure
  \*   (c) FetchAndInject allow  -- success
  \* Only one can fire because (a) causes early return before FetchAndInject,
  \* and (b)/(c) are branches within a single FetchAndInject call.
  NoDoubleDecision == decChWrites <= 1

  \* Liveness: the handler goroutine always terminates.
  \* Corresponds to the Go guarantee that handleRequest always returns
  \* (either via the select decision or the 35-second timeout).
  HandlerEventuallyCompletes == <>(handlerDone = TRUE)

  \* Liveness: the registry entry is always removed.
  \* Corresponds to the Go guarantee that `defer gw.registry.Delete(requestID)`
  \* fires regardless of the request outcome.
  RegistryEventuallyCleanedUp == <>(reg = "gone")
end define

\* -----------------------------------------------------------------------
\* GoproxyHandler: OnRequest goroutine.
\*
\* Before h_register, handleRequest validates the JWT inline via
\* gw.verifier.VerifyToken (returns 407 immediately on failure, no registry
\* registration).  The model begins at h_register, covering only the path
\* where JWT validation succeeded.  After registration the handler starts
\* the Temporal workflow and blocks on a select over DecisionCh and a
\* 35-second timeout.  The defer always deletes the registry entry on exit.
\* -----------------------------------------------------------------------
fair process Handler = "handler"
begin
  h_register:
    \* Store RequestContext keyed by requestID.  DecisionCh is buffered (cap=1).
    reg := "exists";

  h_start_workflow:
    \* gw.temporal.ExecuteWorkflow is non-blocking; Workflow runs concurrently.
    skip;

  h_wait_decision:
    either
      \* Normal path: select fires on decisionCh before the 35-second timeout.
      await decCh /= "empty";
      if decCh = "allowed" then
        \* Request was modified in-place by FetchAndInject; forward it.
        requestForwarded := TRUE;
      end if;
    or
      \* 35-second handler timeout: return 504 GatewayTimeout.
      skip;
    end either;

  h_cleanup:
    \* defer gw.registry.Delete(requestID) always fires here.
    reg := "gone";
    handlerDone := TRUE;
end process;

\* -----------------------------------------------------------------------
\* ProxyRequestWorkflow: Temporal workflow.
\*
\* The real workflow runs two sequential local activities (JWT validation
\* moved to the proxy layer in Slice 1, so raw tokens never enter history):
\*   1. EvaluatePolicy  (local activity -- OPA in-process, no network)
\*      On failure: SendDecision(denied) unblocks handler, workflow returns.
\*   2. FetchAndInject  (local activity -- vault fetch + in-place inject)
\*      On failure: sends denied on DecisionCh, returns error.
\*      On success: sends allowed on DecisionCh.
\*
\* This model abstracts both activities into a single non-deterministic step
\* (w_activities) that chooses between deny (EvaluatePolicy or FetchAndInject
\* failure) and allow (FetchAndInject success).  The concurrency invariant --
\* that DecisionCh is written at most once -- does not depend on which step
\* fails, only on the send/no-send logic against the registry entry.
\*
\* After a successful FetchAndInject the workflow waits for the
\* response_complete signal from OnResponse (or a 60-second timeout).
\* -----------------------------------------------------------------------
fair process Workflow = "workflow"
variables wAllowed = FALSE;
begin
  w_activities:
    \* Model all possible activity outcomes non-deterministically.
    \* SendDecision (deny path) and FetchAndInject (allow path) both contract:
    \*   "MUST send on DecisionCh iff registry entry still exists."
    if reg = "exists" then
      either
        \* Deny outcome: EvaluatePolicy denial/error (SendDecision activity) or
        \* FetchAndInject vault/inject error (FetchAndInject sends denied).
        decCh := "denied";
        decChWrites := decChWrites + 1;
      or
        \* Allow outcome: FetchAndInject success.
        \* Credentials live only in local memory; NOT in Temporal event history.
        injected := TRUE;
        decCh := "allowed";
        decChWrites := decChWrites + 1;
        wAllowed := TRUE;
      end either;
    end if;
    \* If reg = "gone" (handler already timed out): no send, fall through.

  w_wait_signal:
    \* Only wait for response_complete if credentials were actually injected.
    if wAllowed then
      either
        await respSig = "sent";  \* audit trail: OnResponse scrubbed + signalled
      or
        skip;                    \* 60-second workflow timeout: complete anyway
      end either;
    end if;

  w_done:
    skip;
end process;

\* -----------------------------------------------------------------------
\* OnResponse: goproxy response handler.
\*
\* In goproxy, OnResponse is called for every proxied request.  The handler
\* checks ctx.UserData for a requestState (set only on the allow path).
\* If credentials were injected, it scrubs the response body and signals
\* the Temporal workflow with "response_complete".
\*
\* This process waits until the handler goroutine finishes (handlerDone),
\* then acts based on whether the request was forwarded (requestForwarded).
\* -----------------------------------------------------------------------
fair process Response = "response"
begin
  r_wait:
    \* Run after the handler goroutine completes (the request is settled).
    await handlerDone;

  r_act:
    \* Scrub credentials from response body and signal workflow -- only if
    \* credentials were injected -- ctx.UserData requestState is non-nil.
    if requestForwarded then
      \* ScrubCredentials (in-memory) + SignalWorkflow("response_complete")
      respSig := "sent";
    end if;
    \* If not forwarded: return response unchanged (no signal).

  r_done:
    skip;
end process;

end algorithm *)
\* BEGIN TRANSLATION (chksum(pcal) = "27b05ab6" /\ chksum(tla) = "9e890576")
VARIABLES reg, decCh, decChWrites, requestForwarded, handlerDone, injected, 
          respSig, pc

(* define statement *)
TypeInvariant ==
  /\ reg              \in {"empty", "exists", "gone"}
  /\ decCh            \in {"empty", "allowed", "denied"}
  /\ decChWrites      \in 0..2
  /\ requestForwarded \in BOOLEAN
  /\ handlerDone      \in BOOLEAN
  /\ injected         \in BOOLEAN
  /\ respSig          \in {"none", "sent"}








NoDoubleDecision == decChWrites <= 1




HandlerEventuallyCompletes == <>(handlerDone = TRUE)




RegistryEventuallyCleanedUp == <>(reg = "gone")

VARIABLE wAllowed

vars == << reg, decCh, decChWrites, requestForwarded, handlerDone, injected, 
           respSig, pc, wAllowed >>

ProcSet == {"handler"} \cup {"workflow"} \cup {"response"}

Init == (* Global variables *)
        /\ reg = "empty"
        /\ decCh = "empty"
        /\ decChWrites = 0
        /\ requestForwarded = FALSE
        /\ handlerDone = FALSE
        /\ injected = FALSE
        /\ respSig = "none"
        (* Process Workflow *)
        /\ wAllowed = FALSE
        /\ pc = [self \in ProcSet |-> CASE self = "handler" -> "h_register"
                                        [] self = "workflow" -> "w_activities"
                                        [] self = "response" -> "r_wait"]

h_register == /\ pc["handler"] = "h_register"
              /\ reg' = "exists"
              /\ pc' = [pc EXCEPT !["handler"] = "h_start_workflow"]
              /\ UNCHANGED << decCh, decChWrites, requestForwarded, 
                              handlerDone, injected, respSig, wAllowed >>

h_start_workflow == /\ pc["handler"] = "h_start_workflow"
                    /\ TRUE
                    /\ pc' = [pc EXCEPT !["handler"] = "h_wait_decision"]
                    /\ UNCHANGED << reg, decCh, decChWrites, requestForwarded, 
                                    handlerDone, injected, respSig, wAllowed >>

h_wait_decision == /\ pc["handler"] = "h_wait_decision"
                   /\ \/ /\ decCh /= "empty"
                         /\ IF decCh = "allowed"
                               THEN /\ requestForwarded' = TRUE
                               ELSE /\ TRUE
                                    /\ UNCHANGED requestForwarded
                      \/ /\ TRUE
                         /\ UNCHANGED requestForwarded
                   /\ pc' = [pc EXCEPT !["handler"] = "h_cleanup"]
                   /\ UNCHANGED << reg, decCh, decChWrites, handlerDone, 
                                   injected, respSig, wAllowed >>

h_cleanup == /\ pc["handler"] = "h_cleanup"
             /\ reg' = "gone"
             /\ handlerDone' = TRUE
             /\ pc' = [pc EXCEPT !["handler"] = "Done"]
             /\ UNCHANGED << decCh, decChWrites, requestForwarded, injected, 
                             respSig, wAllowed >>

Handler == h_register \/ h_start_workflow \/ h_wait_decision \/ h_cleanup

w_activities == /\ pc["workflow"] = "w_activities"
                /\ IF reg = "exists"
                      THEN /\ \/ /\ decCh' = "denied"
                                 /\ decChWrites' = decChWrites + 1
                                 /\ UNCHANGED <<injected, wAllowed>>
                              \/ /\ injected' = TRUE
                                 /\ decCh' = "allowed"
                                 /\ decChWrites' = decChWrites + 1
                                 /\ wAllowed' = TRUE
                      ELSE /\ TRUE
                           /\ UNCHANGED << decCh, decChWrites, injected, 
                                           wAllowed >>
                /\ pc' = [pc EXCEPT !["workflow"] = "w_wait_signal"]
                /\ UNCHANGED << reg, requestForwarded, handlerDone, respSig >>

w_wait_signal == /\ pc["workflow"] = "w_wait_signal"
                 /\ IF wAllowed
                       THEN /\ \/ /\ respSig = "sent"
                               \/ /\ TRUE
                       ELSE /\ TRUE
                 /\ pc' = [pc EXCEPT !["workflow"] = "w_done"]
                 /\ UNCHANGED << reg, decCh, decChWrites, requestForwarded, 
                                 handlerDone, injected, respSig, wAllowed >>

w_done == /\ pc["workflow"] = "w_done"
          /\ TRUE
          /\ pc' = [pc EXCEPT !["workflow"] = "Done"]
          /\ UNCHANGED << reg, decCh, decChWrites, requestForwarded, 
                          handlerDone, injected, respSig, wAllowed >>

Workflow == w_activities \/ w_wait_signal \/ w_done

r_wait == /\ pc["response"] = "r_wait"
          /\ handlerDone
          /\ pc' = [pc EXCEPT !["response"] = "r_act"]
          /\ UNCHANGED << reg, decCh, decChWrites, requestForwarded, 
                          handlerDone, injected, respSig, wAllowed >>

r_act == /\ pc["response"] = "r_act"
         /\ IF requestForwarded
               THEN /\ respSig' = "sent"
               ELSE /\ TRUE
                    /\ UNCHANGED respSig
         /\ pc' = [pc EXCEPT !["response"] = "r_done"]
         /\ UNCHANGED << reg, decCh, decChWrites, requestForwarded, 
                         handlerDone, injected, wAllowed >>

r_done == /\ pc["response"] = "r_done"
          /\ TRUE
          /\ pc' = [pc EXCEPT !["response"] = "Done"]
          /\ UNCHANGED << reg, decCh, decChWrites, requestForwarded, 
                          handlerDone, injected, respSig, wAllowed >>

Response == r_wait \/ r_act \/ r_done

(* Allow infinite stuttering to prevent deadlock on termination. *)
Terminating == /\ \A self \in ProcSet: pc[self] = "Done"
               /\ UNCHANGED vars

Next == Handler \/ Workflow \/ Response
           \/ Terminating

Spec == /\ Init /\ [][Next]_vars
        /\ WF_vars(Handler)
        /\ WF_vars(Workflow)
        /\ WF_vars(Response)

Termination == <>(\A self \in ProcSet: pc[self] = "Done")

\* END TRANSLATION 

\* -----------------------------------------------------------------------
\* TLA+ translation below is auto-generated by `pcal proxy_protocol.tla`.
\* DO NOT EDIT manually -- re-run pcal to regenerate after editing PlusCal.
\* -----------------------------------------------------------------------
=============================================================================
