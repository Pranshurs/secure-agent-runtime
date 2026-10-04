# Secure Agent Runtime (SAR)

A small Python library that sits between an LLM agent and its tools and decides, with
plain deterministic code, whether each proposed tool call may run.

**The model proposes; the runtime disposes.** A model (or a prompt injection hiding in a
web page, an email or a note) can make the agent *ask* for any call. Whether that call is
allowed depends only on facts the operator controls: who the agent is acting as, the tool
as the operator registered it, and the arguments after strict validation. Model text never
reaches the policy.

Status: first vertical slice, pre-alpha. It is a research and portfolio project, built
openly with AI coding agents (Claude Code). It has not been used in production.

## What it guarantees (and the tests that show it)

For the bundled notes agent (`read_note` allowed, `write_note` needs approval,
`delete_note` not granted), the test suite shows:

| Property | Where it is tested |
|---|---|
| A denied call never invokes the tool | `tests/test_notes_slice.py` section 1, `tests/test_agent.py::test_injected_instructions_cannot_make_a_call_allowed` |
| No execution without approval; approval for args A cannot run args B; self-approval refused | sections 2–4 |
| Replaying a call never re-executes it, including after a restart and under concurrent `execute` | section 5 |
| A timeout ends in `timed_out`, and a late result is discarded and audited | section 6 |
| Malformed tool output and malformed model output are rejected | section 7, `test_agent.py` |
| The audit hash chain verifies, tampering is detected, execution events = real invocations | section 8 |

## Quick start

```bash
git clone https://github.com/Pranshurs/secure-agent-runtime
cd secure-agent-runtime
pip install -e .
python -m secure_agent_runtime.examples.notes
```

The demo drives the agent with a scripted "model" that reads a note, is talked into
deleting it, and also asks to write it. The output is deterministic:

```
read_note    succeeded
delete_note  denied             grant: notes-agent is not granted delete_note
run: awaiting_approval pending: ['["run-1","c3"]']
alice approves write_note {'body': 'buy milk, eggs', 'title': 'todo'} (args_hash 29695fe6237f...)
write_note   succeeded
run: completed | Done.
notes: {'todo': 'buy milk, eggs'} | invocations: {'read_note': 1, 'write_note': 1}
audit: (True, '13 events verified')
```

## Using it

```python
from pydantic import BaseModel, ConfigDict
from secure_agent_runtime import Effect, Policy, Principal, Runtime, Store, ToolRegistry

class SendIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    to: str
    text: str

class SendOut(BaseModel):
    model_config = ConfigDict(extra="forbid")
    sent: bool

reg = ToolRegistry()

@reg.tool(input=SendIn, output=SendOut, effect=Effect.EXTERNAL, timeout_s=5)
def send_message(args: SendIn) -> SendOut:
    ...  # the real side effect

rt = Runtime(
    registry=reg,
    policy=Policy(),  # WRITE and EXTERNAL need approval by default
    principals=[Principal("support-bot", grants=frozenset({"send_message"})),
                Principal("alice", can_approve=True)],
    store=Store("sar.db"),
)

o = rt.propose(run_id="r1", principal_id="support-bot", call_id="call_1",
               tool="send_message", arguments={"to": "bob", "text": "hi"})
# o.state == "pending_approval"; show the human o.tool, the stored args and o.args_hash
rt.approve(o.key, approver_id="alice", args_hash=o.args_hash)
print(rt.execute(o.key).state)  # "succeeded"
```

`secure_agent_runtime.Agent` wraps this in a loop for any model object with
`respond(messages, tools) -> {"text": ..., "tool_calls": [{"id", "name", "arguments"}]}`.
Provider adapters (Anthropic, OpenAI) are not written yet.

## How it works

Every proposed call becomes a row in SQLite and moves through a closed state machine:

```
propose:   -> invalid | denied | pending_approval | approved
approve:   pending_approval -> approved | rejected | expired | cancelled
execute:   approved -> executing -> succeeded | failed | timed_out | output_rejected
recover:   executing -> outcome_unknown          (after a crash; never re-run)
```

- **Validation first.** Arguments are validated in pydantic strict JSON mode against an
  input model that must forbid extra fields. `"1"` is not coerced to `1`. Anything that
  fails is `invalid` and never reaches policy.
- **Policy** (`policy.py`) is default-deny and first-match: tool not granted → deny;
  operator constraint fails *or raises* → deny; effect is WRITE/EXTERNAL (or tool is
  listed) → needs approval; otherwise allow. Its only inputs are the principal, the
  registered `ToolSpec` and the validated args. A tool's description or docstring has no
  effect (`test_tool_description_cannot_lower_the_bar`).
- **Approvals are bound to content.** The approver must present the `args_hash` (SHA-256
  of the canonical JSON of tool name and validated args) of what they were shown. The
  requester cannot approve its own call; approvers come from the operator's directory, and
  approvals expire.
- **Re-checked at the last moment.** Just before running, `execute` recomputes the hash of
  the stored args, checks it against the approval, re-validates against the current schema
  and re-runs policy against the current grants. A grant revoked after approval blocks the
  call.
- **At most once.** The key is `(run_id, call_id)`. A replay returns the stored outcome; a
  replay with different content raises `ReplayDivergence`. The move `approved → executing`
  is a compare-and-set, so two executors cannot both run a call.
- **Timeouts.** The tool runs in a worker thread. On timeout the runtime CAS-moves the call
  to `timed_out` and sets a cancel event the tool may watch. If the tool finishes later, its
  CAS fails and the result is discarded with a `call.late_result_discarded` audit event.
- **Output** is validated against the output model before the model sees it. A failed
  validation is `output_rejected`, and the model gets a fixed message, not the tool's data.
  A tool exception is recorded by type only, so its message cannot leak secrets into the
  log or the transcript.
- **Audit.** Each state change appends an event *in the same SQLite transaction*. Events
  form a SHA-256 hash chain over sequence, time, run, call, kind and data.
  `Store.verify_audit()` recomputes it; pass an earlier `Store.head()` as `anchor` to also
  detect truncation.

## Security model

In scope: a hostile or confused **model**, including one steered by injected content. It
controls tool names, arguments, call ids and its own text, and nothing else.

Trusted: the **operator's code**, meaning the registry, policy, principal directory, the
tools themselves and the code that calls `approve`. `approve(approver_id=...)` trusts the
caller to have authenticated that person. SAR is an in-process library and does no
authentication. The agent loop never calls `approve`, so the model has no path to it.

Partly in scope: someone who can **edit the database**. Edits to a call's arguments or
approval are caught before execution, and edits to past audit events are detected. Someone
with full write access can still rebuild the whole chain, so anchor `head()` somewhere they
can't write.

## Tests

```bash
pip install -e '.[dev]'
pytest                              # TESTS_LINE
python scripts/mutation_test.py     # MUTATION_LINE
```

The tests drive the public API (`Runtime.propose/approve/execute/...` and `Agent`), use a
fake clock for expiry, and count real tool-body invocations so they can compare them with
the audit log.

**Mutation testing.** `scripts/mutation_test.py` holds a hand-written list of mutants,
each disabling or weakening one safety rule (for example "skip the self-approval check" or
"drop the state predicate from the compare-and-set"). It runs the suite against each
mutant on a temporary copy, refuses to start unless the unmutated suite passes, and fails
if any mutant survives. Mutants that can't change behaviour are declared *equivalent*, with
the reason printed. They are still run, and a declared-equivalent mutant that gets killed
is flagged. MUTATION_DETAIL

The list is curated, not generated, so it covers the rules this README claims, not every
line of code. CI runs it on every pull request.

## Limitations

- **Python threads can't be killed.** A timed-out tool keeps running until it returns
  unless it watches its `cancel` event, and its side effect may still happen.
  `timed_out` means "effect unknown". It is never retried. Real isolation needs a
  subprocess or a sandbox, which this slice doesn't have.
- **At most once, not exactly once.** A crash between claiming a call and recording its
  result leaves `outcome_unknown`. SAR won't re-run it, and it can't tell whether the
  effect happened. Tools with external effects should take an idempotency key of their own.
- **Execution events can over-count after a crash.** The `executing` event is committed
  before the tool runs, so a crash in between gives an event with no invocation. The tests
  prove equality only when there was no crash.
- **The audit chain is tamper-evident, not tamper-proof**, and truncation is caught only
  against an external anchor.
- **In-process and single-node.** SQLite with one connection guarded by a lock. Several
  processes on one database file haven't been tested.
- **No authentication** of approvers or principals (see Security model).
- **Transcripts are in memory.** The call ledger and audit log are durable, the `Agent`
  conversation is not.
- **No provider adapters, MCP client, OpenTelemetry or retries yet.** See
  `docs/DESIGN_NOTES.md` for the plan.
- **Policy is only as good as its configuration.** A tool registered with the wrong `Effect`
  is governed as that effect.

## Licence

Apache-2.0. See [LICENSE](LICENSE).
