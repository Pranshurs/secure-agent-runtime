# Integrations

The core has no dependency on any agent framework or model provider. Integration means
mapping a framework's "the model wants to call a tool" into `Runtime.propose` /
`execute`, and mapping `Outcome.for_model()` back into the framework's tool-result
message. **No adapters are implemented yet.** This page records the plan and the facts
that shape it (checked October 2026; see `docs/DESIGN_NOTES.md`).

## Generic Python (available now)

```python
o = runtime.propose(run_id=run, principal_id=agent, call_id=tool_call.id,
                    tool=tool_call.name, arguments=tool_call.arguments)
o = runtime.execute(o.key)                     # no-op unless approved
if o.state == "effect_unknown":
    o = runtime.reconcile(o.key)
    if o.state == "approved":
        o = runtime.execute(o.key)
send_to_model(tool_call.id, o.for_model())     # pending/denied/etc. are reported, not raised
```

`secure_agent_runtime.Agent` is this loop with pausing for approval.

## Planned adapters, in order

1. **MCP client side.** Wrap calls *to* MCP servers. Tool annotations from a server are
   hints. The MCP spec itself says clients must treat them as untrusted unless the
   server is trusted, and SAR's registry and policy stay authoritative. MCP defines no
   approval or idempotency mechanism; SAR adds both.
2. **OpenAI Agents / Responses.** Map `function_call` (`call_id`) to `propose`, and
   `function_call_output` from `for_model()`.
3. **LangGraph.** `interrupt()` re-runs the node from the start on resume, so side
   effects before the interrupt must be idempotent. SAR's replay ledger is exactly that
   property. The node calls `propose` + `execute` with a stable `call_id`.
4. **Anthropic Messages.** Map `tool_use` (`id`) to `propose`, and `tool_result` from
   `for_model()`.

Each adapter should be a separate optional extra (`pip install secure-agent-runtime[mcp]`)
of a few hundred lines, with its own tests. None should be imported by the core.

## Sandboxes

SAR doesn't isolate processes. Run tool bodies inside whatever sandbox you already
use (containers, seccomp, gVisor, VMs, network policy). SAR decides **whether** and
**how many times** a call runs, and records **what it changed**. The sandbox limits
**what it can touch**. A `FileTreeObserver` pointed at a sandbox's writable mount
gives frame checks over exactly that scope.
