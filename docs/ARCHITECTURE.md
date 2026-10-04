# Architecture

SAR sits between an agent (any framework, any model) and the tools that cause side
effects. It is a library: no server, no network, one SQLite file.

```
 model / agent framework
        │  proposes {tool, arguments, call id}
        ▼
 ┌─────────────────────────── Runtime ───────────────────────────┐
 │ contracts.parse_input   strict JSON-mode validation, round-trip │
 │ action.Action           canonical, versioned envelope + digest  │
 │ policy.Policy.decide    ALLOW | DENY | REQUIRE_APPROVAL         │
 │ approve()               human approval bound to action digest   │
 │ execute()               last-moment re-check → CAS claim →      │
 │                         observer snapshot → worker thread →     │
 │                         validate output → frame check           │
 │ reconcile()/resolve()   settle effect_unknown before redispatch │
 │ receipt()               Agent Receipt (sar.receipt/v1)          │
 └───────────────┬─────────────────────────────────────────────────┘
                 │ every state change + its audit event, one transaction
                 ▼
 store.Store: calls table (state machine) + events table (hash chain)
```

## Modules

| module | responsibility | trusts |
|---|---|---|
| `contracts.py` | `ToolSpec` (input/output models, `Effect`, version, timeout, reconciler, observer, frame), registry, canonical JSON, validation | operator code |
| `action.py` | `Action` envelope, `sar.action/v1`, digest | — |
| `policy.py` | `Principal`, `Policy.decide`, `approval_refusal` | operator config |
| `store.py` | SQLite persistence, closed transition table, attempt-fenced CAS, hash-chained audit | — |
| `runtime.py` | the governor: propose / approve / reject / cancel / execute / reconcile / resolve / recover / receipt | the above |
| `effects.py` | observers, `FrameSpec`, `check_frame` | operator-declared frames |
| `receipts.py` | build, digest, HMAC-sign and verify receipts | the signing key holder |
| `agent.py` | minimal provider-neutral loop | nothing from the model |
| `examples/` | notes, refund (lost response), version bump (frame) | — |

## Core types

`Action`, `ToolSpec` (the tool contract), `Decision` (authority decision),
the approval record (`{approver, action_digest, approved_at, kind}`), `CallRow` (the
execution record), `Change` / `FrameResult` (effect observations) and the Agent Receipt
dict. None of them mention a model provider or agent framework.

## Design rules

1. **Authority comes only from operator-controlled facts.** `Policy.decide` takes a
   principal, a registered spec and validated arguments, nothing else. Tool descriptions,
   MCP annotations and model text never reach it.
2. **The store is the source of truth.** Every transition is a compare-and-set in the
   same transaction as its audit event. In-memory state (pre-dispatch snapshots, live
   worker handles) is an optimisation and is rebuilt as "unknown" after a restart.
3. **Uncertainty is a state, not an error.** `effect_unknown` is explicit and only
   reconciliation leaves it.
4. **Re-check at the last moment.** `execute` recomputes the action digest from the
   current tool definition and re-runs policy, so approvals can't outlive the facts they
   approved.
5. **Fail closed.** Unknown tools, malformed input, raising constraints, failing frame
   builders and failing observers all stop the action before dispatch.

See [TRANSACTION_SEMANTICS.md](TRANSACTION_SEMANTICS.md) for the state machine and
invariants, [AGENT_RECEIPTS.md](AGENT_RECEIPTS.md), [FRAME_CONDITIONS.md](FRAME_CONDITIONS.md),
[THREAT_MODEL.md](THREAT_MODEL.md) and [INTEGRATIONS.md](INTEGRATIONS.md).
