# Secure Agent Runtime

*Transactional execution and verifiable side-effect receipts for AI agents.*

> Models propose actions. SAR decides whether they may execute, makes retries safe,
> reconciles uncertain outcomes, and proves what the agent changed.

Status: **v0.2.0**, an early (pre-alpha) release. A research and portfolio project, built
openly with AI coding agents (Claude Code). It is not on PyPI, and nobody uses it in production.

SAR is a library that sits between an agent (any framework, any model) and the tools that
change things. It complements agent policy and governance frameworks and durable workflow
engines; it does not replace them (see [docs/ECOSYSTEM_POSITIONING.md](docs/ECOSYSTEM_POSITIONING.md)).

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
  finance-lead approved action sha256:f57d4ff3f9b2c4e8...
  dispatch 1 -> EFFECT_UNKNOWN (tool raised ConnectionLost)
  agent retries the same call -> EFFECT_UNKNOWN, no dispatch
  reconcile -> SUCCEEDED (reconciled: effect was applied)
  refunds issued: 1   total refunded: ₹4,500   provider calls: 1
  receipt rcpt_...: outcome VERIFIED, dispatches 1, Ed25519 signature, verification OK
```

The demo also covers the request being lost *before* the refund. Reconciliation then says
"not applied", SAR dispatches once more, and the customer still gets exactly one refund.
Each refund runs in its own worker process, which SAR can kill.

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

The sloppy agent did bump the version. It also deleted a test and edited the README. SAR's
**frame condition** catches what it changed beyond the task.

## Quick start

```bash
git clone https://github.com/Pranshurs/secure-agent-runtime && cd secure-agent-runtime
pip install -e '.[signing]'      # 'signing' adds Ed25519 receipts (cryptography)
secure-agent-runtime demo        # refund, frame and notes demos
python examples/quickstart.py    # the code below; run it twice
```

Python 3.10–3.13 on Linux or macOS. The only required dependency is pydantic.

```python
reg = ToolRegistry()

@reg.tool(input=RefundIn, output=RefundOut, effect=Effect.EXTERNAL, version="2026-10")
def refund(args, ctx):
    return RefundOut(refund_id=payments.refund(args.order, args.amount_inr,
                                               idempotency_key=ctx.idempotency_key))

@reg.reconciler("refund")
def find_refund(args, ctx):                       # "did this action's effect happen?"
    rid = payments.refunds.get(ctx.idempotency_key)
    return Applied(RefundOut(refund_id=rid)) if rid else NotApplied()

auth = TokenAuthenticator()                       # demo only: use your identity provider
with Store("sar.db") as store:
    rt = Runtime(registry=reg, policy=Policy(), store=store, authenticator=auth,
                 principals=[Principal("support-agent", grants=frozenset({"refund"})),
                             Principal("finance-lead", can_approve=True)])

    o = rt.propose(run_id="ticket-77", principal_id="support-agent", call_id="call_1",
                   tool="refund", arguments={"order": 821, "amount_inr": 4500})
    if o.state == "awaiting_approval":            # a rerun replays the recorded outcome
        credential = auth.issue("finance-lead", scope=o.action_digest)
        rt.approve(o.key, credential=credential, action_digest=o.action_digest)

    o = rt.execute(o.key)                         # succeeded | effect_unknown | failed | ...
    if o.state == "effect_unknown":
        o = rt.reconcile(o.key)                   # asks find_refund; never blindly re-runs
    receipt = rt.receipt(o.key, signer=Ed25519Signer.generate("ops-2026-10"))
```

The full file, with imports and a stand-in payment client, is
[examples/quickstart.py](examples/quickstart.py). A test runs it twice and checks that
the second run replays the first instead of refunding again.

## How it works

```
proposal → canonicalization → authority → exact-argument approval → durable execution
        → consequential effect → safe retry / reconciliation → frame verification
        → Agent Receipt
```

* **Canonical action.** Validated arguments go into a versioned envelope (`sar.action/v1`)
  with the actor, run, idempotency key, tool name, version and schema digest, declared
  effects, deadline and a per-action salt. Its SHA-256 digest is the action's identity.
* **Authority.** A default-deny policy over structured facts only: principal grants,
  operator constraints and the tool's registered effect. Model text, tool descriptions and
  MCP annotations never reach it.
* **Exact-argument approval.** A person approves one digest, through your
  `Authenticator`. The approval records who authenticated, how, and which one-time
  credential was used; a credential can be scoped to a single digest and can't be reused.
  Approving `refund(821, 1000)` can't authorise `refund(821, 10000)`, a new tool
  version, a changed schema or a looser frame. `execute` re-derives the digest from the
  current tool definition and re-runs policy just before dispatch.
* **Durable execution.** SQLite with compare-and-set transitions, a closed transition
  table and attempt fencing, one owner per database file. Every transition and its
  hash-chained audit event commit together. A crash leaves `executing` rows that become
  `effect_unknown` on restart; nothing is re-dispatched automatically.
* **Killable workers.** A tool declared `isolation="process"` runs in a fresh worker
  process per attempt, leading its own process group. The group is killed on timeout, if
  the worker dies, and as soon as its one reply arrives, so neither the worker nor a
  child process or thread it left behind can act after the attempt is decided. Its
  message carries the attempt's token. On Linux a worker also dies with its runtime.
* **Reconciliation.** `effect_unknown` means "the tool may have acted and we don't know".
  Only the tool's reconciler (or an authenticated person, `resolve`) leaves it: applied →
  `succeeded`; not applied → `approved`, so the same approval may dispatch again (within
  its time limit, `approval_ttl_s`).
* **Frame conditions.** An observer snapshots what the tool may touch before and after.
  The operator declares required, allowed and forbidden changes; anything undeclared
  fails. See [docs/FRAME_CONDITIONS.md](docs/FRAME_CONDITIONS.md).
* **Agent Receipts.** JSON with a published schema: the action envelope (argument values
  only as a salted digest), the decision, the authenticated approval, execution, result
  digest, observed versus declared effects and the audit events. Every row field a
  receipt reports is backed by the audit event that set it. Signed with Ed25519 (or
  HMAC), and verifiable against the store. See [docs/AGENT_RECEIPTS.md](docs/AGENT_RECEIPTS.md).
* **Telemetry (optional).** OpenTelemetry spans and metrics without argument values,
  results or credentials. A failing exporter can't change a decision.

State machine and invariants: [docs/TRANSACTION_SEMANTICS.md](docs/TRANSACTION_SEMANTICS.md).

## Security model, in short

SAR trusts the operator's code and configuration (tool contracts, policy, principals,
authenticator, keys) and the host it runs on. It does not trust the model, tool
descriptions, MCP annotations, caller-supplied approver names or anything a tool returns
before validation. The threat model, with an OWASP agentic-risk mapping marked
MITIGATED / PARTIAL / OUT OF SCOPE, is [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## What SAR is not

It is **not a sandbox.** It doesn't replace containers, seccomp, VMs or network policy,
and a process-isolated tool can still touch whatever its process can reach. SAR decides
*whether* and *how many times* a call runs and records *what it changed*. Run tools inside
a sandbox. See [docs/INTEGRATIONS.md](docs/INTEGRATIONS.md).

It is **not exactly-once.** It gives at most one dispatch per approved attempt, starts
another attempt only when the previous one is known to have had no effect, and never
re-dispatches an unknown outcome. That becomes "exactly one effect" only when the tool
can be reconciled truthfully. It is not formally verified, and it is not secure against a
compromised host.

## Guarantees and their evidence

| guarantee | tests |
|---|---|
| changed args, tool version, schema or frame after approval → blocked | `test_transactions.py::test_approval_for_1000_does_not_authorise_10000`, `test_tool_upgrade_after_approval_blocks_dispatch`, `test_action.py::test_output_schema_change_after_approval_blocks_dispatch`, `test_effects.py::test_declared_frame_is_part_of_what_was_approved` |
| approval needs an authenticated approver; scoped, one-time credentials | `test_auth_and_signing.py::test_a_bare_principal_id_is_not_a_credential`, `test_credential_scoped_to_another_action_is_refused`, `test_credential_replay_is_refused`, `test_misbehaving_authenticator_fails_closed` |
| unauthorised action → blocked, tool never invoked | `test_notes_slice.py` §1, `test_agent.py::test_injected_instructions_cannot_make_a_call_allowed` |
| duplicate or concurrent duplicate → one dispatch | `test_transactions.py::test_concurrent_duplicate_dispatch_moves_money_once`, `test_conflicting_reuse_of_an_idempotency_key_fails_closed` |
| response lost after effect → reconciled, not re-run | `test_transactions.py::test_reconciliation_finds_the_refund_and_closes_the_action` |
| stale reconciler or late worker can't decide a later attempt | `test_transactions.py::test_stale_reconciliation_cannot_reopen_a_later_attempt`, `test_late_worker_*` |
| the runtime process killed at each boundary → `effect_unknown`, recovered on restart | `test_process_crashes.py::test_runtime_killed_during_dispatch`, `test_runtime_killed_while_the_effect_is_executing`, `test_runtime_killed_during_reconciliation`, `test_runtime_killed_after_completion_replays_without_redispatch` |
| a timed-out worker is killed and can't act later | `test_process_crashes.py::test_timed_out_worker_is_killed_and_cannot_act_later` |
| unrelated or forbidden side effect → receipt `violated` | `test_effects.py::test_sloppy_agent_passes_outcome_check_but_fails_frame`, `test_forbidden_wins_even_over_a_requirement` |
| audit or receipt tampering → detected; Ed25519 checks | `test_notes_slice.py` §8, `test_receipts.py`, `test_auth_and_signing.py::test_ed25519_*` |

## Tests, mutants, stress, benchmark

```bash
pip install -e '.[dev]'
pytest                                   # 451 tests
python scripts/mutation_test.py          # 210 mutants: 203 killed, 0 survived, 7 equivalent
python scripts/stress.py --seeds 1 2 3 4 5 6 7 8 9 10 --actions 300 --threads 16 --rounds 3
python scripts/bench.py                  # latency and throughput on your machine
```

**Mutation testing.** `scripts/mutation_test.py` holds 210 deliberately
constructed safety mutants. Each is a hand-written change that disables or weakens one
rule: drop the attempt fence, accept a credential twice, let a requirement override a
forbidden glob, skip the digest re-check, never close a store. The script refuses to
start unless the unmutated suite passes, runs every mutant on a temporary copy, and fails
if any survives. Result: **210 mutants, 203 killed, 7 demonstrated
behaviorally equivalent, 0 surviving non-equivalent mutants.** The equivalent ones are
printed with their reasons:

* `C10`: a flag in error formatting whose extra field is never read; `C11` covers echoing input.
* `S12`: a sequence check made redundant by the hash chain.
* `R13`: a fast-path early return; the compare-and-set claim is the real guard.
* `R48`, `D9`: attempt fencing of a late worker's result, and worker eviction. Both are
  unreachable because `reconcile` and `resolve` refuse while the earlier worker is alive.
* `I3`: the token check on worker messages. Each attempt has its own pipe, written only by
  SAR's worker code with that attempt's token, so a foreign token can't arrive.
* `W7`: the explicit "observer root must be a directory" check. `os.walk` already
  reports a failing scan of the root to the error handler, which raises.

`R48`, `D9`, `I3` and `W7` are kept as defence in depth.

The list is curated, not generated: it targets the rules this README claims, not every
line. CI runs it on every pull request.

**Stress.** `scripts/stress.py` runs seeded rounds against a file-backed store and
ledger:
* duplicate proposals racing each other;
* concurrent approve / execute / reconcile / cancel;
* transient faults (lost responses, lost requests, slow and timed-out tools,
  exceptions), with about 10% of actions in killable worker processes;
* forged approvals (wrong digest, wrong scope, replayed credential) racing the real
  approver.

It then checks, against the ledger:
* at most one effect per action, and every action settled;
* no deadlock;
* the audit chain verifies;
* every receipt verifies against the store;
* tampering is detected;
* no forged approval is accepted;
* no false "verified" frame.

The approval, receipt, tampering and frame checks were each shown to fail against a
deliberately broken copy of SAR. One break, disabling only the per-event content hash,
is still caught by the chain link to the next event. The command above, on the final tree, ran 30 rounds (10 seeds × 3) of 300 actions on
16 threads in 23 minutes:

* 9,000 actions and 17,976 proposals; 8,976 duplicates were absorbed.
* 8,792 actions succeeded with exactly one effect each, and 208 were cancelled with none.
* 898 late results were discarded.
* 8,399 forged approvals were refused and **0 accepted**.
* 9,000 of 9,000 receipts verified against the store, and 30 of 30 tampered database
  copies were detected.
* **0 invariant failures, 0 store errors, 0 unexpected exceptions.**

**Reviews.** Independent cold reviews (AI subagents told to break the guarantees through
the public API) found real bugs. Each is fixed with a regression test; see
[docs/REVIEWS.md](docs/REVIEWS.md).

**Overhead.** `python scripts/bench.py` on the development container: CPython 3.11.15,
Linux, an Intel Xeon @ 2.10 GHz with 4 CPUs, SQLite 3.45.1 (WAL, synchronous=FULL), idle
(1-minute load 0.46). Each row times one operation; the script prints exactly what each
row includes. A second run gave medians within about 8%; the process-isolated row's tail
varies more over 30 samples. Your numbers will differ.

| scenario | n | p50 µs | p95 µs | p99 µs | mean µs | ops/s |
|---|--:|--:|--:|--:|--:|--:|
| direct tool call (no SAR) | 2,000 | 2 | 2 | 4 | 2 | 487,791 |
| read: propose + execute, :memory: | 2,000 | 1,971 | 2,538 | 2,951 | 2,031 | 492 |
| replay of a completed action | 2,000 | 705 | 943 | 1,109 | 741 | 1,349 |
| read: propose + execute, SQLite file (WAL) | 2,000 | 3,301 | 4,311 | 5,201 | 3,435 | 291 |
| write: propose + approve + execute, file | 2,000 | 3,817 | 4,881 | 6,392 | 3,929 | 255 |
| refund execute (thread), frame check | 500 | 8,693 | 12,097 | 14,996 | 8,684 | 115 |
| reconcile an effect_unknown refund | 200 | 6,641 | 9,401 | 14,129 | 6,896 | 145 |
| build receipt (unsigned) | 500 | 920 | 1,075 | 1,221 | 928 | 1,077 |
| build receipt + Ed25519 signature | 500 | 939 | 1,147 | 1,562 | 957 | 1,045 |
| verify receipt: Ed25519 + against the store | 500 | 31,281 | 40,327 | 44,508 | 31,897 | 31 |
| refund execute (process-isolated) | 30 | 159,520 | 169,196 | 172,955 | 159,259 | 6 |
| concurrent reads, 8 threads, file | 1,246 | – | – | – | – | 248 |

How to read it:

* **SAR's own cost is milliseconds per action, not microseconds.** A durable read costs
  about 3.3 ms against 2.0 ms with an in-memory store, so committing to disk is a large
  part of it; a replay, which skips the tool and the worker thread, costs 0.7 ms. That is
  fine for consequential actions (payments, deploys, file edits) and too slow for hot
  inner loops.
* **A process-isolated dispatch costs about 150 ms**, mostly starting a fresh interpreter
  with `spawn`. Use it where being able to kill the tool matters.
* **Verifying a receipt against the store re-verifies the whole audit chain**, so its
  cost grows with the database: about 31 ms here, on a store holding roughly 4,000
  events.
* **Threads don't add throughput.** One runtime has one SQLite connection, so writes are
  serialised: 8 threads did 248 reads/s against 291/s sequentially. Shard by database for
  more.

## Platforms

Linux is the primary target. macOS runs the full suite in CI; there, an orphaned worker
process can outlive a killed runtime (Linux uses `PR_SET_PDEATHSIG`), so reconcile again
after a crash. **Windows is not supported** for file-backed stores (no `fcntl` locking).

## Limitations

* **Thread-isolated tools can't be killed.** Python threads can't be stopped. A timed-out
  thread tool keeps running unless it watches `ctx.cancel`; SAR marks the action
  `effect_unknown` and defers reconciliation until the thread ends. Use
  `isolation="process"` for tools that must be stoppable. That costs a process start per
  attempt (see the benchmark) and needs an importable, module-level tool.
* **At most once per approval, not exactly once.** Without a reconciler, an uncertain
  outcome waits for a person (`resolve`).
* **One process per database, on a local file system.** A file lock (on the resolved
  path, so symlinks count) refuses a second owner. Hard links, bind mounts and network
  file systems are not detected. Several processes sharing one store are not supported
  yet; shard by database instead. Close what you open: a `Store` dropped without
  `close()` keeps its lock until the process exits.
* **Process isolation stops the worker's process group,** not work it handed to
  something else (a daemon, another service, another host).
* **Frame conditions detect; they don't prevent or undo,** and only within what the
  observer snapshots, at two instants. Concurrent writers show up as violations.
* **Some digests are unsalted.** The argument digest in a receipt is salted per action;
  the result digest and the observed-state digests are not, so a low-entropy result can
  be guessed from its receipt.
* **Tamper-evident, not tamper-proof.** Someone with full write access to the database
  can rebuild it consistently. Truncation is caught only against a chain head you keep
  elsewhere (`store.head()`). HMAC receipts are symmetric. Key management (rotation,
  revocation) is yours.
* **The demo `TokenAuthenticator` is not for people.** Plug in your identity provider.
* **No framework adapters yet.** MCP, OpenAI Agents, LangGraph and Anthropic adapters are
  planned, MCP last.
* **The receipt schema is v1 but not frozen** before 1.0.

## Documentation

[Architecture](docs/ARCHITECTURE.md) · [Transaction semantics](docs/TRANSACTION_SEMANTICS.md) ·
[Agent Receipts](docs/AGENT_RECEIPTS.md) · [Frame conditions](docs/FRAME_CONDITIONS.md) ·
[Threat model](docs/THREAT_MODEL.md) · [Operations](docs/OPERATIONS.md) ·
[Integrations](docs/INTEGRATIONS.md) · [Ecosystem positioning](docs/ECOSYSTEM_POSITIONING.md) ·
[Reviews](docs/REVIEWS.md) · [Contributing](CONTRIBUTING.md) · [Design notes](docs/DESIGN_NOTES.md)

## Licence

Apache-2.0. See [LICENSE](LICENSE).
