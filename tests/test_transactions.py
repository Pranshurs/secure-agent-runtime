"""Transaction semantics with a consequential tool (the mock refund service).

Every test goes through the public Runtime API. ``service.calls`` counts requests that
reached the provider and ``service.refunds`` is the ground truth of money moved.
"""

from __future__ import annotations

import threading
import time

import pytest

from secure_agent_runtime.contracts import Applied, EffectNotApplied, NotApplied, ToolRegistry, Unknown
from secure_agent_runtime.examples import refund as rf
from secure_agent_runtime.runtime import ApprovalRefused, ReplayDivergence
from secure_agent_runtime.store import Store

from .conftest import cred, execution_events

ARGS = {"order": 821, "amount_inr": 4500}


@pytest.fixture
def service():
    return rf.PaymentService()


@pytest.fixture
def rrt(service, store):
    return rf.build_runtime(service, store)


def approved(rt, args=ARGS, call_id="call_1", **kw):
    o = rt.propose(run_id="t", principal_id=rf.AGENT, call_id=call_id, tool="refund", arguments=args, **kw)
    assert o.state == "awaiting_approval"
    return rt.approve(o.key, credential=cred(rt, rf.APPROVER), action_digest=o.action_digest)


def wait_for(cond, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if cond():
            return True
        time.sleep(0.005)
    return False


# -- the unsafe baseline really is unsafe ---------------------------------------------------- #

def test_naive_retry_double_refunds(service):
    service.fail_next = "after_effect"
    rf.unsafe_retry(service, 821, 4500)
    assert len(service.refunds) == 2 and service.total_refunded(821) == 9000


# -- lost response after the effect ------------------------------------------------------------- #

def test_lost_response_is_effect_unknown_and_retry_does_not_redispatch(rrt, service):
    o = approved(rrt)
    service.fail_next = "after_effect"
    assert rrt.execute(o.key).state == "effect_unknown"
    retry = rrt.propose(run_id="t", principal_id=rf.AGENT, call_id="call_1", tool="refund", arguments=ARGS)
    assert retry.state == "effect_unknown"
    for _ in range(3):
        assert rrt.execute(retry.key).state == "effect_unknown"
    assert service.calls == 1 and len(service.refunds) == 1


def test_reconciliation_finds_the_refund_and_closes_the_action(rrt, service):
    o = approved(rrt)
    service.fail_next = "after_effect"
    rrt.execute(o.key)
    out = rrt.reconcile(o.key)
    assert out.state == "succeeded" and out.result["refund_id"] == "rf_0001"
    assert out.verification == "verified"
    assert rrt.execute(o.key).state == "succeeded" and rrt.reconcile(o.key).state == "succeeded"
    assert service.calls == 1 and service.total_refunded(821) == 4500
    assert execution_events(rrt.store) == service.calls


def test_request_lost_before_effect_is_redispatched_once_after_reconciliation(rrt, service):
    o = approved(rrt)
    service.fail_next = "before_effect"
    assert rrt.execute(o.key).state == "effect_unknown"
    assert rrt.reconcile(o.key).state == "approved"
    out = rrt.execute(o.key)
    assert out.state == "succeeded" and out.verification == "verified"
    assert service.calls == 2 and len(service.refunds) == 1
    assert rrt.store.get_call(o.key).dispatches == 2
    assert execution_events(rrt.store) == service.calls


def test_definite_failure_is_failed_not_unknown(service, store):
    rt = rf.build_runtime(service, store, isolation="thread")

    def refuse(*a, **k):
        raise EffectNotApplied("card declined")

    service.refund = refuse
    o = approved(rt)
    out = rt.execute(o.key)
    assert out.state == "failed" and "not applied" in out.reason
    assert rt.reconcile(o.key).state == "failed" and rt.execute(o.key).state == "failed"


# -- timeouts --------------------------------------------------------------------------------- #

def _slow_refund_runtime(service, store, *, apply_first: bool):
    """A refund tool that outlives its 50 ms timeout, either before or after moving money."""
    rt = rf.build_runtime(service, store, isolation="thread")
    spec = rt.registry.get("refund")
    done = threading.Event()

    def slow(args, ctx):
        try:
            if apply_first:
                rid = service.refund(args.order, args.amount_inr, idempotency_key=ctx.idempotency_key)
                ctx.cancel.wait(5)
                return rf.RefundOut(refund_id=rid, order=args.order, amount_inr=args.amount_inr)
            if ctx.cancel.wait(5):  # a well-behaved tool stops when told
                raise EffectNotApplied("cancelled before sending")
            raise AssertionError("not cancelled")
        finally:
            done.set()

    import dataclasses
    rt.registry.replace(dataclasses.replace(spec, fn=slow, timeout_s=0.05))
    return rt, done


def test_timeout_before_effect_reconciles_to_not_applied_then_one_refund(service, store):
    rt, done = _slow_refund_runtime(service, store, apply_first=False)
    o = approved(rt)
    assert rt.execute(o.key).state == "effect_unknown"
    assert done.wait(5) and wait_for(lambda: store.events(kind="call.late_result_discarded"))
    assert rt.reconcile(o.key).state == "approved"
    with rf.build_runtime(service) as healthy:  # a throwaway runtime, only for its "refund" spec
        rt.registry.replace(healthy.registry.get("refund"))  # provider healthy again
    out = rt.execute(o.key)
    assert out.state == "succeeded" and len(service.refunds) == 1 and service.calls == 1


def test_timeout_after_effect_is_reconciled_without_a_second_refund(service, store):
    rt, done = _slow_refund_runtime(service, store, apply_first=True)
    o = approved(rt)
    assert rt.execute(o.key).state == "effect_unknown"
    assert done.wait(5) and wait_for(lambda: store.events(kind="call.late_result_discarded"))
    out = rt.reconcile(o.key)
    assert out.state == "succeeded" and len(service.refunds) == 1 and service.calls == 1


# -- crashes at execution boundaries ------------------------------------------------------------ #

class Crash:
    """Fault injector: simulate the process dying at one point (SystemExit, like os._exit)."""

    def __init__(self, point):
        self.point, self.armed = point, True

    def __call__(self, point, key):
        if point == self.point and self.armed:
            self.armed = False
            raise SystemExit(f"simulated crash at {point}")


def test_crash_after_claim_before_dispatch(tmp_path, service, clock):
    db = str(tmp_path / "sar.db")
    rt = rf.build_runtime(service, Store(db, now=clock), faults=Crash("after_claim"))
    o = approved(rt)
    with pytest.raises(SystemExit):
        rt.execute(o.key)
    assert rt.store.get_call(o.key).state == "executing" and service.calls == 0
    rt.store.close()

    rt2 = rf.build_runtime(service, Store(db, now=clock))  # restart: recovers automatically
    assert rt2.recovered == [o.key]
    assert rt2.execute(o.key).state == "effect_unknown" and service.calls == 0  # not blindly re-run
    assert rt2.reconcile(o.key).state == "approved"
    assert rt2.execute(o.key).state == "succeeded"
    assert service.calls == 1 and len(service.refunds) == 1
    # Documented over-count: two claims (executing events), one real dispatch.
    assert execution_events(rt2.store) == 2
    assert rt2.store.verify_audit()[0]
    rt2.store.close()


def test_crash_after_effect_before_recording(tmp_path, service, clock):
    db = str(tmp_path / "sar.db")
    rt = rf.build_runtime(service, Store(db, now=clock), faults=Crash("after_effect"), isolation="thread")
    o = approved(rt)
    assert rt.execute(o.key).state == "executing"  # the worker died after the refund
    assert len(service.refunds) == 1
    rt.store.close()

    rt2 = rf.build_runtime(service, Store(db, now=clock))
    assert rt2.recovered == [o.key]
    retry = rt2.propose(run_id="t", principal_id=rf.AGENT, call_id="call_1", tool="refund", arguments=ARGS)
    assert rt2.execute(retry.key).state == "effect_unknown"
    out = rt2.reconcile(o.key)
    assert out.state == "succeeded" and len(service.refunds) == 1 and service.calls == 1
    # The in-memory snapshot died with the process; its persisted digests are enough here
    # because this frame only checks the *after* content (see test_effects for the case
    # where they are not).
    assert out.verification == "verified"
    rt2.store.close()


def test_crash_during_read_recovers_to_failed(rt, app):
    from secure_agent_runtime.examples.notes import AGENT

    o = rt.propose(run_id="r", principal_id=AGENT, call_id="c", tool="read_note", arguments={"title": "todo"})
    rt.store.transition(o.key, "approved", "executing")
    assert rt.recover() == [o.key] and rt.store.get_call(o.key).state == "failed"


# -- reconcilers that can't decide ---------------------------------------------------------------- #

@pytest.mark.parametrize("behaviour", ["unknown", "raises", "hangs", "garbage", "bad_result"])
def test_undecided_reconciliation_keeps_the_action_unknown(service, store, behaviour):
    rt = rf.build_runtime(service, store, isolation="thread")
    import dataclasses

    def recon(args, ctx):
        if behaviour == "unknown":
            return Unknown("provider API down")
        if behaviour == "raises":
            raise RuntimeError("boom")
        if behaviour == "hangs":
            time.sleep(1)
        if behaviour == "bad_result":
            return Applied({"refund_id": 5})
        return "yes it worked"

    spec = dataclasses.replace(rt.registry.get("refund"), reconciler=recon)
    rt.registry.replace(spec)
    o = approved(rt)
    service.fail_next = "after_effect"
    assert rt.execute(o.key).state == "effect_unknown"  # the lost response, with the tool's normal timeout
    # Only now bound the reconciler tightly: with 0.1 s for the dispatch too, a slow runner timed the
    # dispatch out, the worker was still alive, and reconcile (correctly) deferred instead of deciding.
    rt.registry.replace(dataclasses.replace(spec, timeout_s=0.1))
    t0 = time.monotonic()
    assert rt.reconcile(o.key).state == "effect_unknown"
    assert time.monotonic() - t0 < 0.8  # a hanging reconciler is bounded by the tool timeout
    assert rt.execute(o.key).state == "effect_unknown" and service.calls == 1
    kinds = {e.kind for e in store.events()}
    assert {"reconcile.unknown", "reconcile.result_invalid"} & kinds


def test_tool_without_reconciler_needs_a_human_resolution(rt, app):
    from secure_agent_runtime.examples.notes import AGENT, APPROVER

    o = rt.propose(run_id="r", principal_id=AGENT, call_id="w", tool="write_note",
                   arguments={"title": "t", "body": "b"})
    rt.approve(o.key, credential=cred(rt, APPROVER), action_digest=o.action_digest)
    app.write = lambda args: (_ for _ in ()).throw(ConnectionError("lost"))
    assert rt.execute(o.key).state == "effect_unknown"
    assert rt.reconcile(o.key).state == "effect_unknown"
    assert rt.store.events(kind="reconcile.unavailable")
    with pytest.raises(ApprovalRefused):
        # the agent can't vouch for itself
        rt.resolve(o.key, credential=cred(rt, AGENT), applied=False, redispatch=True)
    del app.write
    assert rt.resolve(o.key, credential=cred(rt, APPROVER), applied=False, redispatch=True).state == "approved"
    assert rt.execute(o.key).state == "succeeded" and app.notes["t"] == "b"
    with pytest.raises(ApprovalRefused):
        rt.resolve(o.key, credential=cred(rt, APPROVER), applied=True)


def test_human_resolution_as_applied_and_as_abandoned(rt, app):
    from secure_agent_runtime.examples.notes import AGENT, APPROVER

    for cid, applied in (("a", True), ("b", False)):
        o = rt.propose(run_id="r", principal_id=AGENT, call_id=cid, tool="write_note",
                       arguments={"title": cid, "body": "x"})
        rt.approve(o.key, credential=cred(rt, APPROVER), action_digest=o.action_digest)
        rt.store.transition(o.key, "approved", "executing")
        rt.recover()
        result = {"title": cid, "created": True} if applied else None
        out = rt.resolve(o.key, credential=cred(rt, APPROVER), applied=applied, result=result)
        assert out.state == ("succeeded" if applied else "failed")
        assert rt.execute(o.key).state == out.state
    assert app.invocations["write_note"] == 0


# -- attempt fencing: nothing from attempt N decides attempt N+1 ------------------------------------ #

def test_stale_reconciliation_cannot_reopen_a_later_attempt(service, store):
    """A slow reconciler for attempt 1 answering after attempt 2 was dispatched must not
    flip the action back to approved (which would allow attempt 3 unreconciled)."""
    import dataclasses

    rt = rf.build_runtime(service, store, isolation="thread")
    gate, entered = threading.Event(), threading.Event()
    spec = rt.registry.get("refund")

    def slow_recon(args, ctx):
        if ctx.attempt == 1:
            entered.set()
            gate.wait(5)
        return NotApplied()

    rt.registry.replace(dataclasses.replace(spec, reconciler=slow_recon, timeout_s=5))
    o = approved(rt)
    service.fail_next = "before_effect"
    assert rt.execute(o.key).state == "effect_unknown"                  # attempt 1 lost
    result = {}
    t = threading.Thread(target=lambda: result.setdefault("r", rt.reconcile(o.key)))
    t.start()
    assert entered.wait(5)
    rt.resolve(o.key, credential=cred(rt, rf.APPROVER), applied=False, redispatch=True)   # a human decides first
    service.fail_next = "after_effect"
    assert rt.execute(o.key).state == "effect_unknown"                  # attempt 2: money moved
    gate.set()
    t.join(5)
    assert result["r"].state == "effect_unknown"                        # the stale answer was refused
    assert store.events(kind="reconcile.stale")
    assert rt.execute(o.key).state == "effect_unknown" and service.calls == 2 and len(service.refunds) == 1


def test_late_worker_of_attempt_one_cannot_complete_attempt_two(service, store):
    import dataclasses

    rt = rf.build_runtime(service, store, isolation="thread")
    release1, release2, done1 = threading.Event(), threading.Event(), threading.Event()
    spec = rt.registry.get("refund")

    def tool(args, ctx):
        if ctx.attempt == 1:
            release1.wait(5)
            done1.set()
            return rf.RefundOut(refund_id="rf_late", order=args.order, amount_inr=args.amount_inr)
        release2.wait(5)
        rid = service.refund(args.order, args.amount_inr, idempotency_key=ctx.idempotency_key)
        return rf.RefundOut(refund_id=rid, order=args.order, amount_inr=args.amount_inr)

    rt.registry.replace(dataclasses.replace(spec, fn=tool, timeout_s=0.05))
    o = approved(rt)
    assert rt.execute(o.key).state == "effect_unknown"
    release1.set()
    assert done1.wait(5) and wait_for(lambda: store.events(kind="call.late_result_discarded"))
    rt.resolve(o.key, credential=cred(rt, rf.APPROVER), applied=False, redispatch=True)
    rt.registry.replace(dataclasses.replace(spec, fn=tool, timeout_s=5))
    t = threading.Thread(target=rt.execute, args=(o.key,))
    t.start()
    assert wait_for(lambda: store.get_call(o.key).state == "executing" and store.get_call(o.key).dispatches == 2)
    assert store.get_call(o.key).state == "executing"  # attempt 1's result did not complete attempt 2
    release2.set()
    t.join(5)
    row = store.get_call(o.key)
    assert row.state == "succeeded" and row.result["refund_id"] == "rf_0001"


def test_late_worker_finishing_mid_attempt_two_is_discarded(service, store):
    import dataclasses

    rt = rf.build_runtime(service, store, isolation="thread")
    release1, entered2, release2 = threading.Event(), threading.Event(), threading.Event()
    spec = rt.registry.get("refund")

    def tool(args, ctx):
        if ctx.attempt == 1:
            release1.wait(5)
            return rf.RefundOut(refund_id="rf_late", order=args.order, amount_inr=args.amount_inr)
        entered2.set()
        release2.wait(5)
        rid = service.refund(args.order, args.amount_inr, idempotency_key=ctx.idempotency_key)
        return rf.RefundOut(refund_id=rid, order=args.order, amount_inr=args.amount_inr)

    def recon(args, ctx):
        return NotApplied()

    rt.registry.replace(dataclasses.replace(spec, fn=tool, reconciler=recon, timeout_s=0.05))
    o = approved(rt)
    assert rt.execute(o.key).state == "effect_unknown"
    assert rt.reconcile(o.key).state == "effect_unknown"  # deferred: attempt 1 still running
    assert store.events(kind="reconcile.deferred")
    with pytest.raises(ApprovalRefused, match="still running"):
        rt.resolve(o.key, credential=cred(rt, rf.APPROVER), applied=False, redispatch=True)
    release1.set()
    assert wait_for(lambda: store.events(kind="call.late_result_discarded"))


# -- duplicates and idempotency keys ------------------------------------------------------------ #

def test_concurrent_duplicate_dispatch_moves_money_once(rrt, service):
    o = approved(rrt)
    barrier = threading.Barrier(16)

    def go():
        barrier.wait()
        rrt.execute(o.key)

    threads = [threading.Thread(target=go) for _ in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert service.calls == 1 and len(service.refunds) == 1 and execution_events(rrt.store) == 1


def test_concurrent_duplicate_proposals_are_one_action(rrt, service):
    barrier, states = threading.Barrier(16), []

    def go():
        barrier.wait()
        states.append(rrt.propose(run_id="t", principal_id=rf.AGENT, call_id="call_1", tool="refund",
                                  arguments=ARGS).state)

    threads = [threading.Thread(target=go) for _ in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert states == ["awaiting_approval"] * 16 and len(rrt.store.calls()) == 1


def test_conflicting_reuse_of_an_idempotency_key_fails_closed(rrt, service):
    o = approved(rrt, idempotency_key="refund-821")
    with pytest.raises(ReplayDivergence):
        rrt.propose(run_id="t2", principal_id=rf.AGENT, call_id="x", tool="refund",
                    arguments={"order": 821, "amount_inr": 45000}, idempotency_key="refund-821")
    assert rrt.store.get_call(o.key).action["args"]["amount_inr"] == 4500
    rrt.execute(o.key)
    assert service.total_refunded(821) == 4500


def test_replay_of_a_completed_refund_returns_the_stored_result(rrt, service):
    o = approved(rrt)
    first = rrt.execute(o.key)
    again = rrt.propose(run_id="t", principal_id=rf.AGENT, call_id="call_1", tool="refund", arguments=ARGS)
    assert again.state == "succeeded" and again.result == first.result
    assert rrt.execute(again.key).result == first.result and service.calls == 1


# -- approvals bound to the exact action -------------------------------------------------------- #

def test_approval_for_1000_does_not_authorise_10000(rrt, service):
    small = approved(rrt, {"order": 821, "amount_inr": 1000}, call_id="a")
    big = rrt.propose(run_id="t", principal_id=rf.AGENT, call_id="b", tool="refund",
                      arguments={"order": 821, "amount_inr": 10000})
    assert big.state == "awaiting_approval"
    with pytest.raises(ApprovalRefused, match="different action"):
        rrt.approve(big.key, credential=cred(rrt, rf.APPROVER), action_digest=small.action_digest)
    assert rrt.execute(big.key).state == "awaiting_approval"
    rrt.execute(small.key)
    assert service.total_refunded(821) == 1000


def test_an_approval_cannot_be_reused_for_an_identical_second_action(rrt, service):
    first = approved(rrt, call_id="a")
    second = rrt.propose(run_id="t", principal_id=rf.AGENT, call_id="b", tool="refund", arguments=ARGS)
    assert second.action_digest != first.action_digest  # same content, different action
    with pytest.raises(ApprovalRefused):
        rrt.approve(second.key, credential=cred(rrt, rf.APPROVER), action_digest=first.action_digest)


def test_tool_upgrade_after_approval_blocks_dispatch(rrt, service):
    import dataclasses

    o = approved(rrt)
    rrt.registry.replace(dataclasses.replace(rrt.registry.get("refund"), version="2026-11"))
    out = rrt.execute(o.key)
    assert out.state == "cancelled" and "changed since approval" in out.reason and service.calls == 0


@pytest.mark.parametrize("deadline", ["tomorrow", float("nan"), float("inf"), True])
def test_malformed_deadline_is_refused_at_proposal(rrt, deadline):
    with pytest.raises(ValueError):
        rrt.propose(run_id="t", principal_id=rf.AGENT, call_id="c", tool="refund", arguments=ARGS,
                    deadline=deadline)
    assert rrt.store.calls() == []


def test_replay_with_a_different_deadline_is_divergence(rrt):
    rrt.propose(run_id="t", principal_id=rf.AGENT, call_id="c", tool="refund", arguments=ARGS, deadline=1e10)
    with pytest.raises(ReplayDivergence):
        rrt.propose(run_id="t", principal_id=rf.AGENT, call_id="c", tool="refund", arguments=ARGS)


def test_human_resolution_still_checks_the_frame(rrt, service):
    o = approved(rrt)
    service.fail_next = "after_effect"
    rrt.execute(o.key)
    out = rrt.resolve(o.key, credential=cred(rrt, rf.APPROVER), applied=True,
                      result={"refund_id": "rf_0001", "order": 821, "amount_inr": 4500})
    assert out.state == "succeeded" and out.verification == "verified"
    assert rrt.receipt(o.key)["outcome"] == "verified"


def test_deadline_passed_blocks_dispatch(rrt, service, clock):
    o = approved(rrt, deadline=clock() + 60)
    clock.advance(61)
    out = rrt.execute(o.key)
    assert out.state == "cancelled" and "deadline" in out.reason and service.calls == 0


def test_revoked_approval_blocks_dispatch(rrt, service):
    o = approved(rrt)
    assert rrt.cancel(o.key, reason="customer withdrew request").state == "cancelled"
    assert rrt.execute(o.key).state == "cancelled" and service.calls == 0


def test_expired_approval_window(rrt, service, clock):
    o = rrt.propose(run_id="t", principal_id=rf.AGENT, call_id="c", tool="refund", arguments=ARGS)
    clock.advance(3601)
    with pytest.raises(ApprovalRefused, match="window"):
        rrt.approve(o.key, credential=cred(rrt, rf.APPROVER), action_digest=o.action_digest)
    assert rrt.execute(o.key).state == "expired" and service.calls == 0


def test_reconciler_cannot_be_attached_to_a_read_tool():
    from pydantic import BaseModel, ConfigDict

    from secure_agent_runtime.contracts import ContractError, Effect

    class M(BaseModel):
        model_config = ConfigDict(extra="forbid")

    reg = ToolRegistry()
    reg.tool(name="r", input=M, output=M, effect=Effect.READ)(lambda a: M())
    with pytest.raises(ContractError):
        reg.reconciler("r")(lambda a, c: NotApplied())


# -- through the agent loop ---------------------------------------------------------------------- #

def test_agent_reconciles_a_lost_response_instead_of_refunding_twice(service, store):
    from secure_agent_runtime.agent import Agent
    from secure_agent_runtime.examples.notes import ScriptedModel

    rt = rf.build_runtime(service, store, isolation="thread")
    model = ScriptedModel([{"tool_calls": [{"id": "c1", "name": "refund", "arguments": ARGS}]},
                           {"text": "Refunded."}])
    agent = Agent(rt, model, rf.AGENT)
    res = agent.start("ticket", "refund my order")
    row = store.get_call(res.pending[0])
    rt.approve(row.key, credential=cred(rt, rf.APPROVER), action_digest=row.action_digest)
    service.fail_next = "after_effect"
    done = agent.resume("ticket")
    assert done.status == "completed" and [o.state for o in done.outcomes] == ["succeeded"]
    assert len(service.refunds) == 1 and service.calls == 1
