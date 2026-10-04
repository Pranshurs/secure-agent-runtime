"""The safety properties of the first vertical slice, one section per property."""

from __future__ import annotations

import dataclasses
import threading
import time

import pytest

from secure_agent_runtime.action import sha256_text
from secure_agent_runtime.auth import TokenAuthenticator
from secure_agent_runtime.contracts import canonical_json
from secure_agent_runtime.examples.notes import AGENT, APPROVER, NotesApp, WriteOut, build_runtime
from secure_agent_runtime.policy import Principal
from secure_agent_runtime.runtime import ApprovalRefused, MalformedProposal, ReplayDivergence, Runtime
from secure_agent_runtime.store import IllegalTransition, Store

from .conftest import cred, execution_events


def propose(rt, call_id, tool, arguments, run_id="r1", principal_id=AGENT):
    return rt.propose(run_id=run_id, principal_id=principal_id, call_id=call_id, tool=tool,
                      arguments=arguments)


def wait_for(cond, timeout=5.0):
    """Poll until cond() is truthy; the late worker records its discard asynchronously."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if cond():
            return True
        time.sleep(0.005)
    return False


def tamper(store, key, *, action=None, digest=None, approval=None, state=None):
    """Edit a call row behind the runtime's back (an attacker with database access)."""
    sets, vals = [], []
    for col, v in (("action_json", action), ("action_digest", digest), ("approval_json", approval),
                   ("state", state)):
        if v is not None:
            sets.append(f"{col}=?")
            vals.append(canonical_json(v) if isinstance(v, dict) else v)
    with store.tx() as db:
        db.execute(f"UPDATE calls SET {', '.join(sets)} WHERE key=?", (*vals, key))


def with_args(row, **args):
    body = dict(row.action)
    body["args"] = {**body["args"], **args}
    body["args_digest"] = sha256_text(body["salt"] + canonical_json(body["args"]))
    return body


def digest_of(body):
    return sha256_text(canonical_json(body))


def write(rt, call_id="w1", title="todo", body="buy eggs", **kw):
    return propose(rt, call_id, "write_note", {"title": title, "body": body}, **kw)


# -- 1. a denied call never invokes the tool ----------------------------------------- #

def test_ungranted_tool_is_denied_and_never_invoked(rt, app):
    o = propose(rt, "d1", "delete_note", {"title": "todo"})
    assert o.state == "denied" and "not granted" in o.reason
    assert rt.execute(o.key).state == "denied"
    assert app.invocations["delete_note"] == 0 and app.notes == {"todo": "buy milk"}
    assert execution_events(rt.store) == 0


def test_denied_call_cannot_be_approved_into_execution(rt, app):
    o = propose(rt, "d1", "delete_note", {"title": "todo"})
    with pytest.raises(ApprovalRefused):
        rt.approve(o.key, credential=cred(rt, APPROVER), action_digest=o.action_digest)
    assert rt.execute(o.key).state == "denied" and app.invocations["delete_note"] == 0


@pytest.mark.parametrize("tool,arguments", [
    ("no_such_tool", {}),
    (None, {}),
    ("read_note", "title=todo"),
    ("read_note", {"title": "todo", "admin": True}),
    ("write_note", {"title": "todo"}),
])
def test_invalid_proposals_never_invoke(rt, app, tool, arguments):
    o = propose(rt, "x", tool, arguments)
    assert o.state == "invalid"
    assert rt.execute(o.key).state == "invalid"
    assert sum(app.invocations.values()) == 0


def test_policy_constraint_denial_never_invokes(store, app):
    rt, _ = build_runtime(store, app)
    rt.policy.constrain("read_note", lambda a: "secret notes are off limits"
                        if a["title"].startswith("secret") else None)
    o = propose(rt, "c1", "read_note", {"title": "secret plans"})
    assert o.state == "denied" and rt.execute(o.key).state == "denied"
    assert app.invocations["read_note"] == 0


def test_revoked_grant_blocks_already_approved_call(store, app):
    rt, _ = build_runtime(store, app)
    o = write(rt)
    rt.approve(o.key, credential=cred(rt, APPROVER), action_digest=o.action_digest)
    rt._principals[AGENT] = Principal(AGENT, grants=frozenset({"read_note"}))
    out = rt.execute(o.key)
    assert out.state == "cancelled" and "policy now denies" in out.reason
    assert app.invocations["write_note"] == 0


# -- 2. no execution without approval --------------------------------------------------- #

def test_write_requires_approval_and_does_not_run_while_pending(rt, app):
    o = write(rt)
    assert o.state == "awaiting_approval"
    for _ in range(3):
        assert rt.execute(o.key).state == "awaiting_approval"
    assert app.invocations["write_note"] == 0 and app.notes["todo"] == "buy milk"


def test_rejected_and_expired_and_cancelled_calls_never_run(rt, app, clock):
    rej = write(rt, "w1")
    rt.reject(rej.key, credential=cred(rt, APPROVER), reason="no")
    exp = write(rt, "w2")
    can = write(rt, "w3")
    rt.cancel(can.key)
    clock.advance(601)
    with pytest.raises(ApprovalRefused, match="window"):
        rt.approve(exp.key, credential=cred(rt, APPROVER), action_digest=exp.action_digest)
    assert [rt.execute(k.key).state for k in (rej, exp, can)] == ["rejected", "expired", "cancelled"]
    assert app.invocations["write_note"] == 0


def test_approval_window_boundary_is_exclusive(rt, clock):
    o = write(rt)
    clock.advance(600)
    with pytest.raises(ApprovalRefused, match="window"):
        rt.approve(o.key, credential=cred(rt, APPROVER), action_digest=o.action_digest)
    assert rt.store.get_call(o.key).state == "expired"


def test_approval_just_inside_window_succeeds(rt, clock):
    o = write(rt)
    clock.advance(599.9)
    assert rt.approve(o.key, credential=cred(rt, APPROVER), action_digest=o.action_digest).state == "approved"


def test_expire_pending_sweeps_only_elapsed(rt, clock):
    a = write(rt, "w1")
    clock.advance(300)
    b = write(rt, "w2")
    clock.advance(301)
    assert rt.expire_pending() == [a.key]
    assert rt.store.get_call(b.key).state == "awaiting_approval"


def test_state_machine_has_no_shortcut_to_execution(rt):
    o = write(rt)
    for target in ("executing", "succeeded"):
        with pytest.raises(IllegalTransition):
            rt.store.transition(o.key, "awaiting_approval", target)
    with pytest.raises(IllegalTransition):
        rt.store.insert_call(key="k", run_id="r", call_id="c", principal=AGENT, tool="write_note",
                             args={}, action=None, action_digest=None, request_hash="h",
                             state="executing", reason="", expires_at=None, created_at=0, event={})


def test_row_marked_approved_without_approval_record_is_blocked(rt, app):
    o = write(rt)
    with rt.store.tx() as db:  # someone flips the state behind the runtime's back
        db.execute("UPDATE calls SET state='approved' WHERE key=?", (o.key,))
    out = rt.execute(o.key)
    assert out.state == "cancelled" and app.invocations["write_note"] == 0


def test_policy_auto_approval_does_not_survive_policy_tightening(store, app):
    rt, _ = build_runtime(store, app)
    o = propose(rt, "c1", "read_note", {"title": "todo"})
    assert o.state == "approved"
    rt.policy.require_approval_for_tools = frozenset({"read_note"})
    assert rt.execute(o.key).state == "cancelled" and app.invocations["read_note"] == 0


# -- 3. approval for args A cannot run args B --------------------------------------------- #

def test_approval_is_bound_to_the_action_digest(rt, app):
    a = write(rt, "wA", body="A")
    b = write(rt, "wB", body="B")
    assert a.action_digest != b.action_digest
    with pytest.raises(ApprovalRefused, match="different action"):
        rt.approve(b.key, credential=cred(rt, APPROVER), action_digest=a.action_digest)
    rt.approve(a.key, credential=cred(rt, APPROVER), action_digest=a.action_digest)
    assert rt.execute(b.key).state == "awaiting_approval"
    assert rt.execute(a.key).state == "succeeded"
    assert app.notes["todo"] == "A" and app.invocations["write_note"] == 1


def test_approver_must_present_the_exact_hash(rt):
    o = write(rt)
    with pytest.raises(ApprovalRefused):
        rt.approve(o.key, credential=cred(rt, APPROVER), action_digest="")
    with pytest.raises(ApprovalRefused):
        rt.approve(o.key, credential=cred(rt, APPROVER), action_digest=o.action_digest.upper())
    assert rt.store.get_call(o.key).state == "awaiting_approval"


def test_args_swapped_in_storage_after_approval_do_not_run(rt, app):
    o = write(rt, body="A")
    rt.approve(o.key, credential=cred(rt, APPROVER), action_digest=o.action_digest)
    tamper(rt.store, o.key, action=with_args(rt.store.get_call(o.key), body="B"))
    out = rt.execute(o.key)
    assert out.state == "cancelled" and "does not match its digest" in out.reason
    assert app.invocations["write_note"] == 0 and app.notes["todo"] == "buy milk"


def test_args_and_hash_swapped_together_still_do_not_run(rt, app):
    o = write(rt, body="A")
    rt.approve(o.key, credential=cred(rt, APPROVER), action_digest=o.action_digest)
    forged = with_args(rt.store.get_call(o.key), body="B")
    tamper(rt.store, o.key, action=forged, digest=digest_of(forged))
    out = rt.execute(o.key)
    assert out.state == "cancelled" and "approval does not match" in out.reason
    assert app.invocations["write_note"] == 0


def test_approval_recorded_for_other_args_does_not_run(rt, app):
    o = write(rt, body="A")
    other = digest_of(with_args(rt.store.get_call(o.key), body="B"))
    tamper(rt.store, o.key, state="approved",
           approval={"approver": APPROVER, "action_digest": other, "approved_at": 0, "kind": "human"})
    out = rt.execute(o.key)
    assert out.state == "cancelled" and "approval does not match" in out.reason
    assert app.invocations["write_note"] == 0


def test_schema_tightened_after_approval_blocks_execution(rt, app):
    from pydantic import BaseModel, ConfigDict, Field

    o = write(rt, body="a long body")
    rt.approve(o.key, credential=cred(rt, APPROVER), action_digest=o.action_digest)

    class ShortWrite(BaseModel):
        model_config = ConfigDict(extra="forbid")
        title: str
        body: str = Field(max_length=3)

    old = rt.registry.get("write_note")
    rt.registry._tools["write_note"] = dataclasses.replace(old, input_model=ShortWrite)
    out = rt.execute(o.key)
    assert out.state == "cancelled" and "no longer validate" in out.reason
    assert app.invocations["write_note"] == 0 and execution_events(rt.store) == 0


def test_execution_claim_is_compare_and_set(rt, app):
    """Two executors that both read 'approved' cannot both run the tool."""
    o = propose(rt, "c1", "read_note", {"title": "todo"})
    stale = rt.store.get_call(o.key)
    assert rt.execute(o.key).state == "succeeded"
    rt.store.get_call = lambda key: stale if key == o.key else None  # executor 2's stale read
    rt.execute(o.key)
    assert app.invocations["read_note"] == 1 and execution_events(rt.store) == 1


# -- 4. self-approval refused ---------------------------------------------------------------- #

def test_requester_cannot_approve_itself(rt, app):
    o = write(rt)
    with pytest.raises(ApprovalRefused, match="not an approver"):
        rt.approve(o.key, credential=cred(rt, AGENT), action_digest=o.action_digest)
    assert rt.store.get_call(o.key).state == "awaiting_approval"
    assert app.invocations["write_note"] == 0


def test_approver_principal_cannot_approve_its_own_request(store, app):
    from secure_agent_runtime.examples.notes import build_registry
    from secure_agent_runtime.policy import Policy

    boss = Principal("boss", grants=frozenset({"write_note"}), can_approve=True)
    rt = Runtime(authenticator=TokenAuthenticator(), registry=build_registry(app), policy=Policy(), store=store,
                 principals=[boss, Principal(APPROVER, can_approve=True)])
    o = write(rt, principal_id="boss")
    with pytest.raises(ApprovalRefused, match="self-approval"):
        rt.approve(o.key, credential=cred(rt, "boss"), action_digest=o.action_digest)
    with pytest.raises(ApprovalRefused, match="self-approval"):
        rt.reject(o.key, credential=cred(rt, "boss"))
    rt.approve(o.key, credential=cred(rt, APPROVER), action_digest=o.action_digest)
    assert rt.execute(o.key).state == "succeeded"


def test_self_approval_written_into_storage_is_blocked(rt, app):
    o = write(rt)
    tamper(rt.store, o.key, state="approved",
           approval={"approver": AGENT, "action_digest": o.action_digest, "approved_at": 0, "kind": "human"})
    assert rt.execute(o.key).state == "cancelled" and app.invocations["write_note"] == 0


def test_unknown_or_unprivileged_approvers_refused(rt):
    o = write(rt)
    for credential in (cred(rt, "mallory"), cred(rt, "policy:allow"), "forged", None, 7):
        with pytest.raises(ApprovalRefused):
            rt.approve(o.key, credential=credential, action_digest=o.action_digest)
    refusals = rt.store.events(kind="approval.refused")
    assert len(refusals) == 5


def test_reserved_principal_id_rejected(store, app):
    from secure_agent_runtime.examples.notes import build_registry
    from secure_agent_runtime.policy import Policy

    with pytest.raises(ValueError):
        Runtime(authenticator=TokenAuthenticator(), registry=build_registry(app), policy=Policy(), store=store,
                principals=[Principal("policy:allow", can_approve=True)])


def test_double_approval_refused(rt):
    o = write(rt)
    rt.approve(o.key, credential=cred(rt, APPROVER), action_digest=o.action_digest)
    with pytest.raises(ApprovalRefused, match="not awaiting"):
        rt.approve(o.key, credential=cred(rt, APPROVER), action_digest=o.action_digest)
    refusal = rt.store.events(kind="approval.refused")[-1]
    assert refusal.data["reason"] == "action is approved, not awaiting approval"


# -- 5. replay does not re-execute ------------------------------------------------------------- #

def test_replayed_proposal_returns_stored_outcome(rt, app):
    o = propose(rt, "c1", "read_note", {"title": "todo"})
    assert rt.execute(o.key).state == "succeeded"
    again = propose(rt, "c1", "read_note", {"title": "todo"})
    assert again.state == "succeeded" and again.result["body"] == "buy milk"
    assert rt.execute(again.key).state == "succeeded"
    assert app.invocations["read_note"] == 1
    assert len(rt.store.events(kind="call.replayed")) == 1


def test_replayed_approved_write_runs_once(rt, app):
    o = write(rt)
    rt.approve(o.key, credential=cred(rt, APPROVER), action_digest=o.action_digest)
    for _ in range(3):
        rt.execute(write(rt).key)
    assert app.invocations["write_note"] == 1


def test_replay_with_different_args_is_divergence(rt, app):
    write(rt, body="A")
    with pytest.raises(ReplayDivergence):
        write(rt, body="B")
    assert len(rt.store.events(kind="call.replay_divergence")) == 1
    assert rt.store.get_call(rt.store.calls()[0].key).args["body"] == "A"


def test_replay_by_another_principal_is_divergence(rt):
    write(rt)
    with pytest.raises(ReplayDivergence):
        write(rt, principal_id=APPROVER)


def test_same_call_id_in_different_runs_is_independent(rt, app):
    for run in ("r1", "r2"):
        rt.execute(propose(rt, "c1", "read_note", {"title": "todo"}, run_id=run).key)
    assert app.invocations["read_note"] == 2


def test_concurrent_identical_proposals_share_one_record(rt):
    barrier, results, errors = threading.Barrier(8), [], []

    def go():
        barrier.wait()
        try:
            results.append(write(rt).state)
        except Exception as exc:  # pragma: no cover - failure path
            errors.append(exc)

    threads = [threading.Thread(target=go) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors and results == ["awaiting_approval"] * 8
    assert len(rt.store.calls()) == 1 and len(rt.store.events(kind="call.requested")) == 1


def test_key_encoding_does_not_collide():
    from secure_agent_runtime.runtime import call_key

    assert call_key("a:b", "c") != call_key("a", "b:c")


def test_concurrent_execution_runs_once(rt, app):
    o = propose(rt, "c1", "read_note", {"title": "todo"})
    barrier = threading.Barrier(8)

    def go():
        barrier.wait()
        rt.execute(o.key)

    threads = [threading.Thread(target=go) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert app.invocations["read_note"] == 1 and execution_events(rt.store) == 1


def test_replay_after_restart_does_not_re_execute(tmp_path, clock):
    db = str(tmp_path / "sar.db")
    app = NotesApp()
    rt, _ = build_runtime(Store(db, now=clock), app)
    o = write(rt)
    rt.approve(o.key, credential=cred(rt, APPROVER), action_digest=o.action_digest)
    rt.execute(o.key)
    rt.store.close()

    rt2, _ = build_runtime(Store(db, now=clock), app)
    again = write(rt2)
    assert again.state == "succeeded" and rt2.execute(again.key).state == "succeeded"
    assert app.invocations["write_note"] == 1
    assert rt2.store.verify_audit()[0]
    rt2.store.close()


def test_malformed_call_ids_rejected(rt):
    for cid in (None, "", 7):
        with pytest.raises(MalformedProposal):
            propose(rt, cid, "read_note", {"title": "todo"})
    with pytest.raises(KeyError):
        propose(rt, "c", "read_note", {"title": "todo"}, principal_id="ghost")


# -- 6. timeout ends safe; late result discarded ------------------------------------------------ #

def test_timeout_ends_safe_and_late_result_is_discarded(store, app):
    rt, _ = build_runtime(store, app, timeout_s=0.05)
    release, finished = threading.Event(), threading.Event()
    real = app.read

    def slow(args):
        release.wait(5)
        try:
            return real(args)
        finally:
            finished.set()

    app.read = slow
    o = propose(rt, "c1", "read_note", {"title": "todo"})
    out = rt.execute(o.key)
    assert out.state == "failed" and "no result within" in out.reason and out.result is None
    assert "result" not in out.for_model()

    release.set()
    assert finished.wait(5)
    assert wait_for(lambda: store.events(kind="call.late_result_discarded"))
    row = store.get_call(o.key)
    assert row.state == "failed" and row.result is None
    late = store.events(kind="call.late_result_discarded")
    assert len(late) == 1 and late[0].data == {"would_have_been": "succeeded"}
    assert rt.execute(o.key).state == "failed" and app.invocations["read_note"] == 1


def test_timed_out_tool_is_told_to_cancel(store, app):
    from pydantic import BaseModel, ConfigDict

    from secure_agent_runtime.contracts import Effect, ToolRegistry
    from secure_agent_runtime.policy import Policy

    class In(BaseModel):
        model_config = ConfigDict(extra="forbid")

    seen = threading.Event()
    reg = ToolRegistry()

    @reg.tool(input=In, output=In, effect=Effect.READ, timeout_s=0.05)
    def waits(args, ctx):
        if ctx.cancel.wait(5):
            seen.set()
        return In()

    rt = Runtime(authenticator=TokenAuthenticator(), registry=reg, policy=Policy(), store=store,
                 principals=[Principal("p", grants=frozenset({"waits"}))])
    o = rt.propose(run_id="r", principal_id="p", call_id="c", tool="waits", arguments={})
    assert rt.execute(o.key).state == "failed"
    assert seen.wait(5)
    assert wait_for(lambda: store.events(kind="call.late_result_discarded"))


def test_crash_during_execution_recovers_to_effect_unknown(tmp_path, clock):
    db = str(tmp_path / "sar.db")
    app = NotesApp()
    rt, _ = build_runtime(Store(db, now=clock), app)
    o = write(rt)
    rt.approve(o.key, credential=cred(rt, APPROVER), action_digest=o.action_digest)
    rt.store.transition(o.key, "approved", "executing")  # crash right after claiming the call
    rt.store.close()

    rt2, _ = build_runtime(Store(db, now=clock), app)
    assert rt2.recovered == [o.key]  # recovered automatically at start-up
    assert rt2.execute(o.key).state == "effect_unknown"
    assert write(rt2).state == "effect_unknown"
    assert app.invocations["write_note"] == 0
    rt2.store.close()


# -- 7. malformed output rejected --------------------------------------------------------------- #

@pytest.mark.parametrize("bad", [
    None, "ok", {"title": "todo"}, {"title": "todo", "created": "yes"},
    {"title": "todo", "created": True, "leak": "secret"}, object(),
])
def test_malformed_output_of_a_write_tool_leaves_the_effect_unknown(rt, app, bad):
    """The write ran, but its result can't be trusted: neither 'succeeded' nor 'failed' is
    honest, so the action is held for reconciliation and its output never reaches the model."""
    app.write = lambda args: bad
    o = write(rt)
    rt.approve(o.key, credential=cred(rt, APPROVER), action_digest=o.action_digest)
    out = rt.execute(o.key)
    assert out.state == "effect_unknown" and out.result is None and "invalid output" in out.reason
    assert out.for_model() == {"status": "effect_unknown", "error": "outcome uncertain; held for reconciliation"}
    assert "secret" not in str([e.data for e in rt.store.events()])
    assert app.invocations["write_note"] == 1
    assert rt.execute(o.key).state == "effect_unknown" and app.invocations["write_note"] == 1


@pytest.mark.parametrize("bad", [
    None, {"title": "todo"}, {"title": "todo", "found": "yes", "body": None},
    {"title": "todo", "found": True, "body": None, "leak": "secret"}, object(),
])
def test_malformed_output_of_a_read_tool_is_rejected(rt, app, bad):
    app.read = lambda args: bad
    out = rt.execute(propose(rt, "c1", "read_note", {"title": "todo"}).key)
    assert out.state == "output_rejected" and out.result is None
    assert out.for_model() == {"status": "output_rejected", "error": "tool output failed validation"}
    assert "secret" not in str([e.data for e in rt.store.events()])


def test_output_of_another_model_class_is_judged_by_its_content(rt, app):
    app.read = lambda args: WriteOut(title="x", created=True)
    o = propose(rt, "c1", "read_note", {"title": "todo"})
    assert rt.execute(o.key).state == "output_rejected"


def test_tool_exception_fails_without_leaking_message(rt, app):
    def boom(args):
        raise RuntimeError("db password is hunter2")

    app.read = boom
    out = rt.execute(propose(rt, "c1", "read_note", {"title": "todo"}).key)
    assert out.state == "failed" and "hunter2" not in out.reason
    assert "hunter2" not in str([e.data for e in rt.store.events()])


# -- 8. audit ------------------------------------------------------------------------------------ #

def _busy_history(rt, app, store):
    """Exercise every path once; return the number of real tool invocations."""
    rt.execute(propose(rt, "c1", "read_note", {"title": "todo"}).key)        # succeeded
    rt.execute(propose(rt, "c2", "delete_note", {"title": "todo"}).key)      # denied
    rt.execute(propose(rt, "c3", "nope", {}).key)                            # invalid
    w = write(rt, "c4", body="new")
    rt.approve(w.key, credential=cred(rt, APPROVER), action_digest=w.action_digest)
    rt.execute(w.key)                                                        # succeeded
    rt.execute(w.key)                                                        # replay: no-op
    rej = write(rt, "c5")
    rt.reject(rej.key, credential=cred(rt, APPROVER))
    real_read = app.read
    app.read = lambda a: {"bad": 1}
    rt.execute(propose(rt, "c6", "read_note", {"title": "todo"}).key)        # output_rejected
    app.read = lambda a: 1 / 0
    rt.execute(propose(rt, "c7", "read_note", {"title": "todo"}).key)        # failed
    app.read = real_read
    with pytest.raises(ApprovalRefused):
        rt.approve(rej.key, credential=cred(rt, AGENT), action_digest=rej.action_digest)
    return sum(app.invocations.values())


def test_audit_chain_verifies_and_execution_events_equal_invocations(rt, app, store):
    invocations = _busy_history(rt, app, store)
    ok, msg = store.verify_audit(anchor=store.head())
    assert ok, msg
    assert invocations == 4
    assert execution_events(store) == invocations
    # every executing event names a call that really reached the tool
    assert {e.call_key for e in store.events(kind="call.executing")} == {
        c.key for c in store.calls() if c.state in ("succeeded", "failed", "output_rejected")}


def test_every_state_change_is_audited(rt, app, store):
    _busy_history(rt, app, store)
    for c in store.calls():
        kinds = [e.kind for e in store.events() if e.call_key == c.key and e.kind.startswith("call.")
                 and e.kind not in ("call.requested", "call.replayed")]
        assert kinds[-1] == f"call.{c.state}", (c.key, kinds)


@pytest.mark.parametrize("sql,params", [
    ("UPDATE events SET data_json=? WHERE seq=3", ('{"reason":"forged"}',)),
    ("UPDATE events SET kind='call.approved' WHERE seq=4", ()),
    ("UPDATE events SET ts=ts+1 WHERE seq=2", ()),
    ("UPDATE events SET run_id='other' WHERE seq=5", ()),
    ("UPDATE events SET call_key=NULL WHERE seq=5", ()),
    ("DELETE FROM events WHERE seq=4", ()),
    ("UPDATE events SET seq=seq+1000 WHERE seq=2", ()),
])
def test_audit_tampering_is_detected(rt, app, store, sql, params):
    _busy_history(rt, app, store)
    with store.tx() as db:
        db.execute(sql, params)
    ok, msg = store.verify_audit()
    assert not ok, msg


def test_rehashed_forgery_is_detected_downstream(rt, app, store):
    """Editing an event and fixing its own hash still breaks the next event's prev_hash."""
    from secure_agent_runtime.store import _event_hash

    _busy_history(rt, app, store)
    with store.tx() as db:
        r = db.execute("SELECT * FROM events WHERE seq=3").fetchone()
        forged = '{"reason":"forged"}'
        h = _event_hash(r["prev_hash"], 3, r["ts"], r["run_id"], r["call_key"], r["kind"], forged)
        db.execute("UPDATE events SET data_json=?, hash=? WHERE seq=3", (forged, h))
    ok, msg = store.verify_audit()
    assert not ok and "event 4" in msg


def test_forgery_that_also_relinks_the_next_event_is_detected(rt, app, store):
    """Rewriting event 3, rehashing it and fixing event 4's prev_hash still fails,
    because event 4's own hash covers its prev_hash."""
    from secure_agent_runtime.store import _event_hash

    _busy_history(rt, app, store)
    with store.tx() as db:
        r = db.execute("SELECT * FROM events WHERE seq=3").fetchone()
        forged = '{"reason":"forged"}'
        h = _event_hash(r["prev_hash"], 3, r["ts"], r["run_id"], r["call_key"], r["kind"], forged)
        db.execute("UPDATE events SET data_json=?, hash=? WHERE seq=3", (forged, h))
        db.execute("UPDATE events SET prev_hash=? WHERE seq=4", (h,))
    ok, msg = store.verify_audit()
    assert not ok and "event 4" in msg


def test_tampered_prev_hash_column_is_detected(rt, app, store):
    _busy_history(rt, app, store)
    with store.tx() as db:
        db.execute("UPDATE events SET prev_hash=? WHERE seq=5", ("f" * 64,))
    assert not store.verify_audit()[0]


def test_tampering_with_the_latest_event_is_detected(rt, app, store):
    _busy_history(rt, app, store)
    with store.tx() as db:
        db.execute("UPDATE events SET data_json='{}' WHERE seq=(SELECT MAX(seq) FROM events)")
    assert not store.verify_audit()[0]


def test_store_refuses_unknown_fields_and_illegal_moves(rt):
    o = write(rt)
    with pytest.raises(ValueError):
        rt.store.transition(o.key, "awaiting_approval", "approved", action_json="{}")
    with pytest.raises(IllegalTransition):
        rt.store.transition(o.key, "succeeded", "approved")
    for target in ("executing", "cancelled", "awaiting_approval"):  # only reconciliation leaves effect_unknown
        with pytest.raises(IllegalTransition):
            rt.store.transition(o.key, "effect_unknown", target)
    assert rt.store.get_call(o.key).state == "awaiting_approval"


def test_truncation_detected_only_with_anchor(rt, app, store):
    _busy_history(rt, app, store)
    anchor = store.head()
    with store.tx() as db:
        db.execute("DELETE FROM events WHERE seq=?", (anchor[0],))
    assert store.verify_audit()[0]  # documented limitation without an anchor
    assert not store.verify_audit(anchor=anchor)[0]


def test_empty_audit_verifies(store):
    assert store.verify_audit() == (True, "0 events verified")
    assert store.verify_audit(anchor=store.head())[0]
