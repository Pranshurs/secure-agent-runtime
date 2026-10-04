# Transaction semantics

## States

```
propose ─┬─> invalid            (unknown tool, malformed or hostile arguments)
         ├─> denied             (policy)
         ├─> awaiting_approval ─┬─> approved      (authenticated, digest-bound approval)
         │                      ├─> rejected
         │                      ├─> expired       (approval window elapsed)
         │                      └─> cancelled
         └─> approved ──────────┬─> cancelled     (revoked, or blocked by the last-moment check)
                                └─> executing ──┬─> succeeded
                                                ├─> failed          (definitely not applied, or a READ tool)
                                                ├─> output_rejected (READ tool returned junk)
                                                └─> effect_unknown ─┬─> succeeded  (reconciled or resolved: applied)
                                                                    ├─> approved   (reconciled not applied, or re-approved by a human)
                                                                    └─> failed     (human: not applied, abandon)
```

The table lives in `store.TRANSITIONS`. Any other move raises `IllegalTransition`
before touching the database. "proposed" and "validated" are not stored states: they
happen inside one `propose()` call and appear in the audit log as `call.requested`
followed by the initial state.

## When is an outcome `effect_unknown`?

Only for tools whose registered `Effect` is WRITE or EXTERNAL, and only when SAR can't
know whether the effect happened:

| what happened | WRITE / EXTERNAL | READ |
|---|---|---|
| tool returned valid output | `succeeded` | `succeeded` |
| tool raised `EffectNotApplied` | `failed` | `failed` |
| tool raised anything else (incl. `SystemExit`) | `effect_unknown` | `failed` |
| tool returned invalid or unserialisable output | `effect_unknown` | `output_rejected` |
| no result within `timeout_s` (process mode: the worker is then killed) | `effect_unknown` | `failed` |
| worker process died mid-call | `effect_unknown` | `failed` |
| the result couldn't be written to the store | `effect_unknown` | `failed` |
| runtime died while `executing` (found at the next start-up) | `effect_unknown` | `failed` |

Killing a worker proves nothing about the external effect, so a kill always leaves the
action `effect_unknown`.

## Isolation

| | `isolation="thread"` (default) | `isolation="process"` |
|---|---|---|
| where the tool runs | a thread of the runtime process | a fresh `spawn`ed process per attempt |
| on timeout | marked `effect_unknown`; the thread **can't be stopped** and may act late (SAR waits for it before reconciling) | marked `effect_unknown`; the worker is **killed** |
| if the runtime dies | the tool dies with it | Linux: the worker gets SIGKILL too (`PR_SET_PDEATHSIG`); macOS: the worker can outlive it |
| requirements | any callable | tool function and models importable by reference (module-level) |
| cost | about 0.2 ms extra | process start-up per dispatch (see the benchmark) |

The worker never touches the store. It sends one message tagged with the action id and
attempt; the runtime records the outcome, fenced by attempt.

## Approvals

* `approve(key, credential=..., action_digest=...)`. The credential is checked by the
  operator's `Authenticator`; the authenticated subject is the approver, never a
  string the caller passes.
* The subject must be a directory principal with `can_approve`, other than the
  requester.
* A credential may be **scoped** to one action digest. It is **consumed** in the same
  transaction as the approval, so it can't be replayed.
* The approver must present the digest they were shown; it must equal the stored
  action's digest.
* The approval window (`approval_ttl_s`) is re-checked inside the compare-and-set.
* A human approval must be **dispatched within `approval_ttl_s`** of being given, or the
  action is cancelled.
* The approval record (subject, method, issuer, scope, digest of the credential id) is
  hashed into the audit log, and dispatch requires the row's approval to match that
  event.

## Invariants

These are what the tests, the property-based state machine and the mutants check.

1. **No dispatch without a matching, audited, unexpired approval.** `execute`
   re-derives the action digest from the stored action and the *current* tool
   definition (version, schema, declared frame). It compares that with the stored
   digest, the approval record and the approval's audit event.
2. **At most one dispatch per approval.** The claim `approved → executing` is a
   compare-and-set on state *and* dispatch count, and increments the count. A second or
   stale executor's claim fails.
3. **`effect_unknown` is never re-dispatched directly.** The only ways back to
   `approved` are a reconciler returning `NotApplied`, or an authenticated approver's
   `resolve(applied=False, redispatch=True)`.
4. **Attempt fencing.** Every transition out of `executing` or `effect_unknown` is
   conditional on the dispatch count of the attempt that produced it. A late worker or
   slow reconciler of attempt N can't decide attempt N+1.
5. **No reconciliation while the last dispatch is alive in this process.**
   `reconcile` defers (audited as `reconcile.deferred`) and `resolve` refuses.
6. **Replay returns the record.** The idempotency key is the primary key. The same key
   with the same request (tool, arguments, deadline, principal) returns the stored
   outcome; a different request raises `ReplayDivergence`.
7. **Every state change has exactly one audit event, in the same transaction.** A
   proposal writes two: `call.requested`, then its initial state.
8. **The row is backed by the log.** The latest state event names the row's state, and
   the latest `call.approved` event carries the digest of the row's approval.
9. **`call.executing` events ≥ real dispatches.** They are equal unless a crash or a
   cooperative cancel happened between the claim and the call.

## Deployment model, and what is *not* claimed

* **One owner per database file**, enforced. A second Store on the same file, in any
  process, gets `StoreLocked`; a second Runtime on the same Store is refused. The
  at-most-once guarantee is established for this model only.
* **Not exactly-once, not distributed.** SAR gives at most one dispatch per approval and
  never re-dispatches an unknown outcome blindly. Exactly one *effect* additionally needs
  a truthful reconciler, or a human, and a provider that honours idempotency keys where
  possible (`ctx.idempotency_key` is passed to every tool).
* **No multi-node operation.** Running SAR on several nodes against one database is
  neither supported nor tested.

## Crash windows (all tested by killing the runtime process with SIGKILL)

| killed at | state after restart | settles as |
|---|---|---|
| after the claim, before the worker started | `effect_unknown` | reconcile → not applied → one dispatch |
| worker started (Linux: worker dies too) | `effect_unknown` | reconcile decides; one effect |
| while the tool runs, before or after its effect | `effect_unknown` | reconcile decides; one effect |
| result received, not yet recorded | `effect_unknown` | reconcile finds the effect |
| inside the completion transaction | `effect_unknown` (rolled back) | reconcile finds the effect |
| during reconciliation, or before its result is recorded | `effect_unknown` | reconcile again |
| after completion | `succeeded` | replay returns it; no dispatch |

Start-up recovery (`recover_on_start=True`, the default) moves orphaned `executing`
rows to `effect_unknown`. That is safe because the store has a single owner.

## Time

Approval windows, approval age and deadlines use the store's clock (`time.time` by
default). A clock that jumps backwards extends them. Tests use a fake clock.
