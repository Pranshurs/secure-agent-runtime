# Secure Agent Runtime: preserved design state (PAUSED 2026-10-04)

Work is paused by owner priority. Resume only after Titanic, VDT, AI Process Consultant and
the EmoNET audit are done. Nothing here is published; the repository is local only.

## State of the code
`src/secure_agent_runtime/` holds three first-draft modules. They are **untested and not
yet wired together**:
- `contracts.py`: `ToolSpec` (pydantic input and output models, a declared `Effect`,
  timeout, idempotent flag, retries allowed only for idempotent tools), a registry, and the
  canonical args hash.
- `policy.py`: a deterministic, default-deny policy over (principal grants, argument
  constraints, effect-based approval). It never reads model text.
- `store.py`: SQLite with compare-and-set call transitions, plus a hash-chained audit log
  appended in the same transaction as each transition. It also persists run state.

## Thesis
The model proposes; the runtime disposes. Policy decisions use only structured facts:
- the principal
- the operator-registered tool spec
- the validated arguments

An injected instruction can therefore make the model *request* a call, but can't make the
call *allowed*.

## Planned call state machine
```
requested -> invalid | denied | pending_approval | approved
pending_approval -> approved | rejected | expired | cancelled
approved -> executing | cancelled
executing -> succeeded | failed | timed_out | output_rejected | outcome_unknown (crash recovery)
```

- **Idempotency key:** `(run_id, model call_id)`. A replayed call with the same key returns
  the stored record. Different args under the same key is a replay-divergence error.
- **Approvals:** bound to `args_hash`. The requester can't approve its own call. Approvals
  can expire.
- **Crash recovery:** a call found in `executing` becomes `outcome_unknown`. It is never
  re-executed automatically.
- **Timeouts:** the tool runs in a worker thread. A timeout CAS-moves the call to
  `timed_out`, and a late result fails its CAS and is discarded, with an audit event.
  Python threads can't be killed, so real isolation needs a subprocess. Document this.

## First vertical slice to build (5D)
A notes agent with three tools:
- `read_note`: allowed
- `write_note`: approval required
- `delete_note`: not granted

Tests must prove:
- a denied call never invokes the tool
- there is no execution path without approval, an approval for args A can't run args B,
  and self-approval is refused
- a replay doesn't re-execute
- a timeout ends in a safe state, and a late result is discarded
- malformed output is rejected
- the audit chain verifies, tampering is detected, and the count of execution events
  equals the count of actual invocations

## Dependency decisions (from research of current official docs, 2026-10-04)

**Adopt**
- **pydantic** for contracts.
- **stdlib sqlite3** for the store.
- **opentelemetry-api only**, optional: it's a documented no-op without an SDK.
  - Current release: 1.45.0.
  - The GenAI semconv is still *Development* status and has moved to
    `open-telemetry/semantic-conventions-genai`.
  - Use `gen_ai.operation.name=execute_tool` and span name `execute_tool {tool}`.
  - Verify the `gen_ai.tool.*` attribute names before hardcoding; they have churned.
  - Don't capture tool arguments or content by default.

**MCP (later slice)**
- Python SDK: `mcp` 2.x, Python ≥3.10. FastMCP was renamed `MCPServer` in v2, which also
  added a first-class `Client`.
- Spec 2026-07-28 is stateless (no initialize handshake).
- The spec says clients **MUST** treat tool annotations as untrusted unless the server is
  trusted. That matches this design: annotations are hints, and the operator's registry
  plus policy are authoritative.
- The spec says a human SHOULD be able to deny tool invocations, but defines no approval
  or idempotency mechanism. The runtime adds both.
- Plan: govern calls *to* MCP servers (client side) through the same policy and call
  ledger.

**Reject as core dependencies**
- **Pydantic AI** (2.54): it already has deferred tools and approvals, plus durable-engine
  integrations. It has no permission policy engine, idempotency ledger or audit log. Offer
  an adapter instead; don't build on it.
- **LangGraph** (1.2.x): `interrupt()` re-runs the node from its start on resume, so side
  effects before the interrupt must be idempotent. That caveat is exactly what this runtime
  enforces. Offer an adapter; don't make it the core.

**Provider adapters**
- Anthropic Messages: `tool_use`/`tool_result`, `strict: true` tools, and
  `output_config.format` structured outputs. Forced `tool_choice` returns a 400 on current
  models, so use `auto`.
- OpenAI Responses: `function_call`/`function_call_output` with `call_id`, and `strict`
  schemas (`additionalProperties: false`, all fields required).

The research came from a sub-agent's summary of official pages. Several release dates were
garbled in fetching, so re-check versions when work resumes.
