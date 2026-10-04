# Transaction semantics

## States

```
propose ─┬─> invalid            (unknown tool, malformed or hostile arguments)
         ├─> denied             (policy)
         ├─> awaiting_approval ─┬─> approved
         │                      ├─> rejected
         │                      ├─> expired       (approval window elapsed)
         │                      └─> cancelled
         └─> approved ──────────┬─> cancelled     (revoked, or blocked by the last-moment check)
                                └─> executing ──┬─> succeeded
                                                ├─> failed          (definitely not applied, or a READ tool)
                                                ├─> output_rejected (READ tool returned junk)
                                                └─> effect_unknown ─┬─> succeeded  (reconciled: applied)
                                                                    ├─> approved   (reconciled: not applied)
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
| tool returned invalid output | `effect_unknown` | `output_rejected` |
| no result within `timeout_s` | `effect_unknown` | `failed` |
| process died while `executing` (found by `recover()`) | `effect_unknown` | `failed` |

`EffectNotApplied` is how a tool says "I know for certain nothing happened", for
example a 4xx from a provider that guarantees no side effect on 4xx.

## Invariants

These are what the tests and mutants check.

1. **No dispatch without an approval record naming the current action digest.**
   `execute` re-derives the digest from the stored action and the *current* tool
   definition, and compares it with the stored digest and the approval record.
2. **At most one dispatch per approval.** The claim `approved → executing` is a
   compare-and-set that also increments `dispatches`. A second executor's CAS fails.
3. **`effect_unknown` is never re-dispatched directly.** The only way back to
   `approved` is a reconciler returning `NotApplied`, or an independent approver calling
   `resolve(applied=False, redispatch=True)`.
4. **Attempt fencing.** Every transition out of `executing` or `effect_unknown` is also
   conditional on `dispatches == N` for the attempt that produced it. A late worker or a
   slow reconciler of attempt N can't decide the outcome of attempt N+1.
5. **No reconciliation while the last dispatch is alive in this process.** A timed-out
   tool may still act, so a "not applied" answer could be overtaken by the tool itself.
   `reconcile` defers (audited as `reconcile.deferred`) and `resolve` refuses.
6. **Replay returns the record.** The idempotency key is the primary key. The same key
   with the same request returns the stored outcome. A different request (tool,
   arguments, deadline or principal) raises `ReplayDivergence`.
7. **Every state change has exactly one audit event, in the same transaction.**
8. **`call.executing` events ≥ real dispatches**, with equality unless a crash
   happened between the claim and the call (`test_crash_after_claim_before_dispatch`).

## What this is not

It is **not exactly-once.** SAR gives *at most one dispatch per approval, and no
re-dispatch while the outcome is unknown*. Whether an effect happens exactly once also
depends on the tool:

* With a reconciler that can query the external system by idempotency key, a lost
  response is settled without a second effect (`examples/refund.py`).
* Without one, `effect_unknown` waits for a human (`resolve`).
* Tools should pass `ctx.idempotency_key` to providers that deduplicate (most payment
  APIs do). SAR then has two independent defences.

## Crash recovery

Call `Runtime.recover()` at startup, before any worker runs. Every `executing` row
becomes `effect_unknown` (or `failed` for READ). Nothing is re-dispatched. Fault
injection tests cover crashes after the claim and after the effect
(`tests/test_transactions.py`).

## Time

Approval windows and deadlines use the store's clock (`time.time` by default). A clock
that jumps backwards extends windows. Tests use a fake clock.
