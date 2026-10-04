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
| `isolation.py` | killable per-attempt worker processes (`spawn`, PDEATHSIG on Linux) | the tool's importable code |
| `auth.py` | `AuthContext`, the `Authenticator` protocol, a demo token authenticator | the host's identity system |
| `effects.py` | observers, `FrameSpec`, `check_frame` | operator-declared frames |
| `receipts.py` | build, digest and verify receipts | the keys it is given |
| `signing.py` | Ed25519 and HMAC-SHA256 signers | key holders |
| `telemetry.py` | optional OpenTelemetry spans and metrics, privacy-safe, failure-contained | – |
| `errors.py` | `SARError`, `StoreError`, `StoreLocked`, `CredentialReused` | – |
| `agent.py` | minimal provider-neutral loop | nothing from the model |
| `examples/` | notes, refund (lost response), version bump (frame) | — |

## Core types

`Action`, `ToolSpec` (the tool contract), `Decision` (authority decision),
`AuthContext` and the approval record (`{approver, action_digest, approved_at, kind,
auth}`), `CallRow` (the execution record), `Change` / `FrameResult` (effect
observations) and the Agent Receipt dict. None of them mention a model provider or
agent framework.

## Design rules

1. **Authority comes only from operator-controlled facts.** `Policy.decide` takes a
   principal, a registered spec and validated arguments, nothing else. Tool descriptions,
   MCP annotations and model text never reach it.
2. **The store is the source of truth, and it has one owner.** Every transition is a
   compare-and-set in the same transaction as its audit event, and the row must agree
   with the log. A file lock and a per-Store owner check give one Runtime per database.
   In-memory state (pre-dispatch snapshots, live worker handles) is guarded by a lock,
   is an optimisation, and is treated as "unknown" after a restart.
3. **Uncertainty is a state, not an error.** `effect_unknown` is explicit and only
   reconciliation leaves it.
4. **Re-check at the last moment.** `execute` recomputes the action digest from the
   current tool definition and re-runs policy, so approvals can't outlive the facts they
   approved.
5. **Fail closed.** Unknown tools, malformed input, raising constraints, failing frame
   builders, failing observers, failing or lying authenticators and unreadable
   receipts all stop the action, or produce a problem, before anything is dispatched
   or verified.
6. **Instrumentation is a bystander.** Telemetry can't change a decision; every call
   into OpenTelemetry is contained.

See [TRANSACTION_SEMANTICS.md](TRANSACTION_SEMANTICS.md) for the state machine and
invariants, [AGENT_RECEIPTS.md](AGENT_RECEIPTS.md), [FRAME_CONDITIONS.md](FRAME_CONDITIONS.md),
[THREAT_MODEL.md](THREAT_MODEL.md), [INTEGRATIONS.md](INTEGRATIONS.md),
[OPERATIONS.md](OPERATIONS.md), [ECOSYSTEM_POSITIONING.md](ECOSYSTEM_POSITIONING.md) and
[REVIEWS.md](REVIEWS.md).
