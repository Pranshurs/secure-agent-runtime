# Secure Agent Runtime

*Transactional execution and verifiable side-effect receipts for AI agents.*

> Models propose actions. SAR decides whether they may execute, makes retries safe,
> reconciles uncertain outcomes, and proves what the agent changed.

Status: **pre-alpha (0.2.0.dev0)**. A research and portfolio project, built openly with
AI coding agents (Claude Code). Not published on PyPI, and not used in production by
anyone yet.

## The failure it is built for

```
agent requests refund ₹4,500
  → payment service processes it
  → the response is lost (network timeout)
  → agent retries
```

`secure-agent-runtime demo refund` (deterministic, local, no API keys):

```
UNSAFE BASELINE (retry on error)
  refunds issued: 2   total refunded: ₹9,000
  -> customer refunded twice

SAR, response lost AFTER the refund
  proposed refund(order=821, amount_inr=4500) -> awaiting_approval
  finance-lead approved action sha256:...
  dispatch 1 -> EFFECT_UNKNOWN (tool raised ConnectionLost)
  agent retries the same call -> EFFECT_UNKNOWN, no dispatch
  reconcile -> SUCCEEDED (reconciled: effect was applied)
  refunds issued: 1   total refunded: ₹4,500   provider calls: 1
  receipt rcpt_...: outcome VERIFIED, dispatches 1, verification OK
```

The same demo covers the request being lost *before* the refund. Reconciliation then
says "not applied", SAR dispatches once more, and the customer still gets one refund.

## …and the one an outcome check misses

Task: bump the version 2.1.0 → 2.1.1. `uv.lock` may change; `tests/**` and `.github/**`
must not. `secure-agent-runtime demo frame`:

```
SLOPPY AGENT
  conventional outcome check:  PASS
  REQUIRED EFFECTS:            PASS
  UNDECLARED CHANGES:          1 ['README.md']
  FORBIDDEN EFFECTS:           1 ['tests/test_pkg.py']
  OUTCOME:                     VIOLATED
```

The sloppy agent did bump the version. It also deleted a failing test. SAR's
**frame condition** catches what it changed beyond the task.

## Quick start (about five minutes)

```bash
git clone https://github.com/Pranshurs/secure-agent-runtime && cd secure-agent-runtime
pip install -e .
secure-agent-runtime demo            # refund, frame and notes demos
```

Python 3.10+. The only runtime dependency is pydantic.

```python
from pydantic import BaseModel, ConfigDict
from secure_agent_runtime import (Applied, Effect, NotApplied, Policy, Principal, Runtime,
                                  Store, ToolRegistry)

class RefundIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    order: int
    amount_inr: int

class RefundOut(BaseModel):
    model_config = ConfigDict(extra="forbid")
    refund_id: str

reg = ToolRegistry()
# `payments` stands for your provider's client; see examples/refund.py for a runnable mock.

@reg.tool(input=RefundIn, output=RefundOut, effect=Effect.EXTERNAL, version="2026-10")
def refund(args, ctx):
    return RefundOut(refund_id=payments.refund(args.order, args.amount_inr,
                                               idempotency_key=ctx.idempotency_key))

@reg.reconciler("refund")
def find_refund(args, ctx):                       # "did this action's effect happen?"
    r = payments.find(idempotency_key=ctx.idempotency_key)
    return Applied(RefundOut(refund_id=r.id)) if r else NotApplied()

rt = Runtime(registry=reg, policy=Policy(), store=Store("sar.db"),
             principals=[Principal("support-agent", grants=frozenset({"refund"})),
                         Principal("finance-lead", can_approve=True)])

o = rt.propose(run_id="ticket-77", principal_id="support-agent", call_id="call_1",
               tool="refund", arguments={"order": 821, "amount_inr": 4500})
rt.approve(o.key, approver_id="finance-lead", action_digest=o.action_digest)
o = rt.execute(o.key)                             # succeeded | effect_unknown | ...
if o.state == "effect_unknown":
    o = rt.reconcile(o.key)                       # never blindly re-dispatched
receipt = rt.receipt(o.key, signing_key=b"...")   # Agent Receipt, sar.receipt/v1
```

## How it works

```
proposal → canonical action → authority → approval (bound to the digest)
        → durable claim (CAS) → tool → outcome / reconciliation
        → frame-condition check → Agent Receipt
```

* **Canonical action.** Validated arguments go into a versioned envelope
  (`sar.action/v1`) with the actor, run, idempotency key, tool name, version and schema
  digest, declared effects and deadline. Its SHA-256 digest is the action's identity.
  Changing any of these fields changes the digest (`tests/test_action.py`).
* **Authority.** A default-deny policy over structured facts only: principal grants,
  operator constraints, and the tool's registered effect. Model text, tool descriptions
  and MCP annotations never reach it.
* **Argument-bound approval.** An approver approves a digest. Approving
  `refund(821, 1000)` can't authorise `refund(821, 10000)`, a new tool version, a changed
  schema or a looser frame. `execute` re-derives the digest from the current tool
  definition just before dispatch.
* **Durable state machine.** SQLite with compare-and-set transitions, a closed
  transition table and attempt fencing. `effect_unknown` is an explicit state for "the
  tool may have acted and we don't know", and only reconciliation leaves it. See
  [docs/TRANSACTION_SEMANTICS.md](docs/TRANSACTION_SEMANTICS.md).
* **Frame conditions.** An observer snapshots the state the tool may touch (a directory,
  a ledger) before and after. The operator declares required, allowed and forbidden
  changes; anything undeclared fails. See [docs/FRAME_CONDITIONS.md](docs/FRAME_CONDITIONS.md).
* **Agent Receipts.** JSON with a published schema. It records the action envelope
  (argument values only as digests), policy decision, approval, execution, result
  digest, observed versus declared effects, and its audit events. It is protected by a
  digest plus an optional HMAC, and can be verified against the store. See
  [docs/AGENT_RECEIPTS.md](docs/AGENT_RECEIPTS.md).
* **Tamper-evident audit.** Every transition appends a hash-chained event in the same
  transaction.

## What SAR is not

It is **not a sandbox.** It doesn't replace containers, seccomp, namespaces, VMs or
network policy, and it doesn't stop a tool from touching what it can reach. SAR's layer
is *authority + transaction semantics + uncertain-effect reconciliation + frame
conditions + receipts*. Run tools inside a sandbox; let SAR decide whether, and how many
times, they run and record what they changed. See [docs/INTEGRATIONS.md](docs/INTEGRATIONS.md).

It is **not exactly-once.** It gives at most one dispatch per approval and never
re-dispatches an unknown outcome. That turns into "exactly one effect" only when the
tool can be reconciled. See [docs/TRANSACTION_SEMANTICS.md](docs/TRANSACTION_SEMANTICS.md).

## Guarantees and their evidence

| guarantee | tests |
|---|---|
| changed args, tool version, schema or frame after approval → blocked | `test_transactions.py::test_approval_for_1000_does_not_authorise_10000`, `test_tool_upgrade_after_approval_blocks_dispatch`, `test_action.py::test_output_schema_change_after_approval_blocks_dispatch`, `test_effects.py::test_declared_frame_is_part_of_what_was_approved` |
| unauthorised action → blocked, tool never invoked | `test_notes_slice.py` §1, `test_agent.py::test_injected_instructions_cannot_make_a_call_allowed` |
| duplicate or concurrent duplicate → one dispatch | `test_transactions.py::test_concurrent_duplicate_dispatch_moves_money_once`, `test_conflicting_reuse_of_an_idempotency_key_fails_closed` |
| response lost after effect → reconciled, not re-run | `test_transactions.py::test_reconciliation_finds_the_refund_and_closes_the_action` |
| stale reconciler or late worker can't decide a later attempt | `test_transactions.py::test_stale_reconciliation_cannot_reopen_a_later_attempt`, `test_late_worker_*` |
| crash at claim or effect boundaries → `effect_unknown`, recoverable | `test_transactions.py::test_crash_after_claim_before_dispatch`, `test_crash_after_effect_before_recording` |
| unrelated or forbidden side effect → receipt `violated` | `test_effects.py::test_sloppy_agent_passes_outcome_check_but_fails_frame`, `test_forbidden_wins_even_over_a_requirement` |
| audit or receipt tampering → detected | `test_notes_slice.py` §8, `test_receipts.py` |

## Tests, mutants, benchmark

```bash
pip install -e '.[dev]'
pytest                                # 314 tests
python scripts/mutation_test.py       # 143 mutants: 139 killed, 0 survived, 4 equivalent
python scripts/bench.py               # per-action overhead on your machine
```

**Mutation testing.** Each mutant in `scripts/mutation_test.py` is a hand-written change
that disables or weakens one invariant. Examples: drop the attempt fence, let a
requirement override a forbidden glob, skip the digest re-check at dispatch. The script
refuses to start unless the unmutated suite passes, runs every mutant on a temporary
copy, and fails if any survives. Mutants that can't change behaviour are declared
*equivalent* and printed with the reason, so they aren't hidden. The four equivalent mutants are:

* `C10`: a no-op flag in error formatting; `C11` covers actually echoing input.
* `S12`: a sequence check made redundant by the hash chain.
* `R13`: a fast-path early return; the compare-and-set claim is the real guard.
* `R48`: the attempt fence on a late worker's result. It is unreachable because
  `reconcile` and `resolve` refuse while that worker is alive. It is kept as defence
  in depth.

The list is curated, not generated: it targets the invariants this README claims, not
every line. CI runs it on every pull request.

**Two independent adversarial reviews** (AI subagents told to break the guarantees
through the public API) found real bugs:
* hostile JSON crashing `propose`;
* stuck `executing` states;
* a stale-reconcile ABA race;
* a late worker completing a later attempt;
* receipts not bound to store state;
* a requirement able to override a forbidden glob.

Each is fixed and has a regression test (`tests/test_hostile_inputs.py` and the tests
named above).

**Overhead** from `python scripts/bench.py -n 1000` on the development container
(Python 3.11, Linux x86_64, 4 CPUs). Your numbers will differ:

| scenario                                       | median µs |    p95 µs |
|------------------------------------------------|-----------|-----------|
| direct tool call (no SAR)                      |       1.9 |       2.1 |
| read: propose + execute, SQLite :memory:       |    1639.6 |    2199.6 |
| read: propose + execute, SQLite file (WAL)     |    2821.1 |    3797.4 |
| write: propose + approve + execute             |    1850.3 |    2234.3 |
| refund: approve + execute + frame check*       |    7561.2 |   11559.6 |
| replay of a completed action                   |     574.4 |     827.6 |
| build receipt                                  |    1107.7 |    1329.5 |

\* The refund observer snapshots the whole mock ledger, which grows from 0 to 1050 refunds during the run, so later iterations cost more.

Most of the cost is one SQLite transaction per state change plus a worker thread per
dispatch. It is fine for consequential actions (payments, deploys, file edits) and too
slow for hot inner loops.

## Limitations

* **Python threads can't be killed.** A timed-out tool keeps running unless it watches
  `ctx.cancel`. SAR marks the action `effect_unknown` and defers reconciliation until
  that thread ends. Real isolation needs a subprocess or a sandbox.
* **At most once per approval, not exactly once.** Without a reconciler an uncertain
  outcome waits for a human (`resolve`).
* **Frame conditions detect, they don't prevent or undo,** and only within what the
  observer snapshots.
* **The audit chain and receipts are tamper-evident, not tamper-proof.** Someone with
  full write access to the database can rebuild everything consistently. Truncation is
  caught only against an external anchor. HMAC is symmetric, so a key holder can forge.
  Asymmetric signing isn't implemented yet.
* **In-process, single node.** One SQLite file per process; multiple processes on one
  file haven't been tested. Transcripts in `Agent` are in memory.
* **No authentication.** The code calling `approve`/`resolve` must authenticate the
  human. SAR trusts the id it's given.
* **No framework adapters yet** (MCP, OpenAI Agents, LangGraph, Anthropic are planned).
* **The receipt schema is v1 but not frozen** before 1.0.

## Documentation

[Architecture](docs/ARCHITECTURE.md) · [Transaction semantics](docs/TRANSACTION_SEMANTICS.md) ·
[Agent Receipts](docs/AGENT_RECEIPTS.md) · [Frame conditions](docs/FRAME_CONDITIONS.md) ·
[Threat model](docs/THREAT_MODEL.md) · [Integrations](docs/INTEGRATIONS.md) ·
[Contributing](CONTRIBUTING.md) · [Design notes](docs/DESIGN_NOTES.md)

## Licence

Apache-2.0. See [LICENSE](LICENSE).
