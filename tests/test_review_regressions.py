"""Regression tests for findings of the independent reviews (ids as in docs/REVIEWS.md).

Each test reproduces the reviewer's attack against the public API and asserts it now
fails closed.
"""

from __future__ import annotations

import dataclasses
import os
import threading

import pytest

from secure_agent_runtime.contracts import canonical_json
from secure_agent_runtime.effects import FrameSpec, check_frame, compile_glob
from secure_agent_runtime.examples import refund as rf
from secure_agent_runtime.examples import version_bump as vb
from secure_agent_runtime.examples.notes import AGENT, APPROVER, build_runtime
from secure_agent_runtime.receipts import receipt_digest, verify_receipt
from secure_agent_runtime.store import Store

from .conftest import cred, execution_events

# -- A1: a newline in a path must not escape a forbidden '**' ------------------------------ #

def test_a1_forbidden_double_star_matches_paths_with_newlines():
    assert compile_glob("**/.env").match("x\ny/.env")
    entries = {"x\ny/.env": "sha256:a"}
    from secure_agent_runtime.effects import Entry
    r = check_frame(FrameSpec(allowed=("*/*",), forbidden=("**/.env",)), {},
                    {k: Entry(v, b"") for k, v in entries.items()})
    assert r.forbidden == ["x\ny/.env"] and r.verdict == "violated"


# -- A2: a result that can't be stored must not wedge the action ------------------------------ #

def test_a2_unstorable_frame_result_does_not_leave_the_action_executing(tmp_path):
    try:  # APFS (macOS) refuses names that aren't valid UTF-8; ext4 and most others accept the bytes
        (tmp_path / "probe\udcff").write_bytes(b"")
    except OSError as exc:
        pytest.skip(f"this filesystem refuses non-UTF-8 file names ({exc.strerror})")
    (tmp_path / "probe\udcff").unlink()

    def evil(root, args):
        vb.careful_agent(root, args)
        (root / "bad\udcff").write_bytes(b"x")  # surrogateescape'd non-UTF-8 name
        return []

    rt = vb.build_runtime(vb.make_workspace(tmp_path), evil)
    o = rt.propose(run_id="r", principal_id=vb.AGENT, call_id="c", tool="bump_version",
                   arguments={"from_version": "2.1.0", "to_version": "2.1.1"})
    rt.approve(o.key, credential=cred(rt, vb.APPROVER), action_digest=o.action_digest)
    out = rt.execute(o.key)
    assert out.state == "succeeded" and out.verification == "unverifiable"  # can't observe: never "verified"
    assert rt.store.verify_audit()[0]


def test_a2_store_failure_while_recording_falls_back_to_effect_unknown(rt, app):
    o = rt.propose(run_id="r", principal_id=AGENT, call_id="w", tool="write_note",
                   arguments={"title": "t", "body": "b"})
    rt.approve(o.key, credential=cred(rt, APPROVER), action_digest=o.action_digest)
    real = rt.store.transition
    calls = {"n": 0}

    def flaky(key, frm, to, **kw):
        if frm == "executing" and to == "succeeded":
            calls["n"] += 1
            raise ValueError("cannot bind result")
        return real(key, frm, to, **kw)

    rt.store.transition = flaky
    out = rt.execute(o.key)
    assert calls["n"] == 1 and out.state == "effect_unknown" and "could not be recorded" in out.reason


# -- A3: a stale executor's claim must be fenced on the dispatch count ------------------------- #

def test_a3_stale_executor_cannot_claim_a_reapproved_action(service_store):
    service, store = service_store
    rt = rf.build_runtime(service, store, isolation="thread")
    o = rt.propose(run_id="t", principal_id=rf.AGENT, call_id="c", tool="refund",
                   arguments={"order": 1, "amount_inr": 10})
    rf.approve_as_finance(rt, o)
    stale = store.get_call(o.key)                 # executor B reads the row, then stalls
    service.fail_next = "before_effect"
    assert rt.execute(o.key).state == "effect_unknown"
    assert rt.reconcile(o.key).state == "approved"   # back to approved, dispatches == 1
    real_get = store.get_call
    store.get_call = lambda key: stale if key == o.key else real_get(key)
    rt.execute(o.key)                              # B wakes with dispatches == 0
    store.get_call = real_get
    assert store.get_call(o.key).state == "approved"  # B's claim lost the fence
    assert service.calls == 1 and execution_events(store) == 1


@pytest.fixture
def service_store(store):
    return rf.PaymentService(), store


# -- A4: the call row must be backed by the audit chain ------------------------------------------ #

def test_a4_forged_approval_in_the_row_does_not_dispatch(rt, app):
    o = rt.propose(run_id="r", principal_id=AGENT, call_id="w", tool="write_note",
                   arguments={"title": "t", "body": "b"})
    forged = {"approver": APPROVER, "action_digest": o.action_digest, "approved_at": rt.store.now(),
              "kind": "human"}
    with rt.store.tx() as db:
        db.execute("UPDATE calls SET state='approved', approval_json=? WHERE key=?", (canonical_json(forged), o.key))
    out = rt.execute(o.key)
    assert out.state == "cancelled" and "not backed by the audit log" in out.reason
    assert app.invocations["write_note"] == 0


def test_a4_receipt_for_a_forged_row_fails_against_the_store(rt, app):
    o = rt.propose(run_id="r", principal_id=AGENT, call_id="w", tool="write_note",
                   arguments={"title": "t", "body": "b"})
    with rt.store.tx() as db:
        db.execute("UPDATE calls SET state='succeeded' WHERE key=?", (o.key,))
    r = rt.receipt(o.key)
    assert "stored state is not backed by the audit log" in verify_receipt(r, store=rt.store)


# -- A5: the signature authenticates alg and key id ------------------------------------------------- #

def test_a5_changing_the_key_id_breaks_the_hmac(rt):
    key = os.urandom(32)
    o = rt.propose(run_id="r", principal_id=AGENT, call_id="c", tool="read_note", arguments={"title": "todo"})
    rt.execute(o.key)
    r = rt.receipt(o.key, signing_key=key, key_id="ops-1")
    r["signature"]["key_id"] = "attacker-chosen"
    assert verify_receipt(r, signing_key=key) == ["signature does not verify"]


# -- A6: a discarded late result must not consume the pre-dispatch snapshot ------------------------- #

def test_a6_late_discarded_result_keeps_the_snapshot_for_reconciliation(tmp_path):
    release = threading.Event()

    def slow(root, args):
        release.wait(5)
        return vb.careful_agent(root, args)

    rt = vb.build_runtime(vb.make_workspace(tmp_path), slow)
    rt.registry.replace(dataclasses.replace(rt.registry.get("bump_version"), timeout_s=0.05))
    o = rt.propose(run_id="r", principal_id=vb.AGENT, call_id="c", tool="bump_version",
                   arguments={"from_version": "2.1.0", "to_version": "2.1.1"})
    rt.approve(o.key, credential=cred(rt, vb.APPROVER), action_digest=o.action_digest)
    assert rt.execute(o.key).state == "effect_unknown"
    release.set()
    from .test_notes_slice import wait_for
    assert wait_for(lambda: rt.store.events(kind="call.late_result_discarded"))
    out = rt.resolve(o.key, credential=cred(rt, vb.APPROVER), applied=True,
                     result={"files_written": ["pyproject.toml", "uv.lock"]})
    assert out.verification == "verified"  # before-content still available: content checks ran


# -- speculative A: approval window re-checked inside the CAS; custom keys namespaced -------------- #

def test_approval_cas_rechecks_the_window(rt, clock):
    o = rt.propose(run_id="r", principal_id=AGENT, call_id="w", tool="write_note",
                   arguments={"title": "t", "body": "b"})
    row = rt.store.get_call(o.key)
    clock.advance(10_000)  # past the window, but the row hasn't been swept
    assert not rt.store.transition(o.key, "awaiting_approval", "approved", unexpired_at=clock(),
                                   approval={"approver": APPROVER}, reason="late")
    assert rt.store.get_call(o.key).state == row.state


def test_custom_idempotency_key_cannot_collide_with_a_default_key(rt):
    a = rt.propose(run_id="r", principal_id=AGENT, call_id="c", tool="read_note", arguments={"title": "todo"})
    b = rt.propose(run_id="x", principal_id=AGENT, call_id="y", tool="read_note", arguments={"title": "todo"},
                   idempotency_key=a.key)
    assert a.key != b.key and len(rt.store.calls()) == 2


# -- B1: one owner per database ---------------------------------------------------------------------- #

def test_b1_second_store_on_the_same_file_is_refused(tmp_path):
    from secure_agent_runtime.errors import StoreLocked

    s1 = Store(str(tmp_path / "sar.db"))
    with pytest.raises(StoreLocked):
        Store(str(tmp_path / "sar.db"))
    s1.close()
    Store(str(tmp_path / "sar.db")).close()  # released on close


def test_b1_second_runtime_on_the_same_store_is_refused(store):
    from secure_agent_runtime.errors import StoreLocked

    rt1, _ = build_runtime(store)
    with pytest.raises(StoreLocked):
        build_runtime(store)
    rt1.close()
    build_runtime(store)


def test_b1_second_process_is_refused(tmp_path):
    import subprocess
    import sys

    s1 = Store(str(tmp_path / "sar.db"))
    code = ("import sys\nfrom secure_agent_runtime.store import Store\nfrom secure_agent_runtime.errors import "
            "StoreLocked\ntry:\n    Store(sys.argv[1])\nexcept StoreLocked:\n    sys.exit(3)\n")
    p = subprocess.run([sys.executable, "-c", code, str(tmp_path / "sar.db")], capture_output=True, timeout=30)
    assert p.returncode == 3, p.stderr
    s1.close()


# -- B2: an approval expires if it is not dispatched in time ---------------------------------------- #

def test_b2_stale_human_approval_is_not_dispatched(rt, app, clock):
    o = rt.propose(run_id="r", principal_id=AGENT, call_id="w", tool="write_note",
                   arguments={"title": "t", "body": "b"})
    rt.approve(o.key, credential=cred(rt, APPROVER), action_digest=o.action_digest)
    clock.advance(601)  # the rt fixture's approval_ttl_s
    out = rt.execute(o.key)
    assert out.state == "cancelled" and "approval expired before dispatch" in out.reason
    assert app.invocations["write_note"] == 0


# -- B3: orphaned executing actions are recovered at start-up ---------------------------------------- #

def test_b3_runtime_start_recovers_orphans(tmp_path, clock):
    s = Store(str(tmp_path / "sar.db"), now=clock)
    rt, app = build_runtime(s)
    o = rt.propose(run_id="r", principal_id=AGENT, call_id="w", tool="write_note",
                   arguments={"title": "t", "body": "b"})
    rt.approve(o.key, credential=cred(rt, APPROVER), action_digest=o.action_digest)
    s.transition(o.key, "approved", "executing", dispatches=1)
    s.close()
    rt2, _ = build_runtime(Store(str(tmp_path / "sar.db"), now=clock), app)
    assert rt2.recovered == [o.key] and rt2.store.get_call(o.key).state == "effect_unknown"


def test_b3_resolve_on_executing_explains_recover(rt):
    from secure_agent_runtime.runtime import ApprovalRefused

    o = rt.propose(run_id="r", principal_id=AGENT, call_id="w", tool="write_note",
                   arguments={"title": "t", "body": "b"})
    rt.approve(o.key, credential=cred(rt, APPROVER), action_digest=o.action_digest)
    rt.store.transition(o.key, "approved", "executing", dispatches=1)
    with pytest.raises(ApprovalRefused, match="recover"):
        rt.resolve(o.key, credential=cred(rt, APPROVER), applied=True)


# -- B4: secrets in validator messages; file permissions; salted digests ---------------------------- #

def test_b4a_validator_messages_are_never_echoed(store):
    from pydantic import BaseModel, ConfigDict, field_validator

    from secure_agent_runtime.contracts import Effect, ToolRegistry
    from secure_agent_runtime.policy import Policy, Principal
    from secure_agent_runtime.runtime import Runtime

    class Pay(BaseModel):
        model_config = ConfigDict(extra="forbid")
        card: str

        @field_validator("card")
        @classmethod
        def luhn(cls, v):
            raise ValueError(f"bad card {v}")

    reg = ToolRegistry()
    reg.tool(name="pay", input=Pay, output=Pay, effect=Effect.READ)(lambda a: a)
    rt = Runtime(registry=reg, policy=Policy(), store=store, principals=[Principal("p", grants=frozenset({"pay"}))])
    o = rt.propose(run_id="r", principal_id="p", call_id="c", tool="pay", arguments={"card": "4111111111111111"})
    assert o.state == "invalid" and "4111" not in o.reason
    assert "4111" not in str([e.data for e in store.events()])


def test_b4c_database_and_lock_files_are_owner_only(tmp_path):
    s = Store(str(tmp_path / "sar.db"))
    s.record("r", "x", {})
    for name in ("sar.db", "sar.db.lock"):
        assert oct(os.stat(tmp_path / name).st_mode & 0o777) == "0o600", name
    s.close()


# -- B5: the CLI separates "failed verification" from "could not check" ------------------------------ #

@pytest.mark.parametrize("content", [b"\xff\xfe", b"", b"[" * 200_000, b"1" * 100_000, b'{"schema": 1}'],
                         ids=["not-utf8", "empty", "deep", "huge-int", "not-a-receipt"])
def test_b5_verify_receipt_cli_errors_are_exit_2_or_fail(tmp_path, content):
    import subprocess
    import sys

    f = tmp_path / "r.json"
    f.write_bytes(content)
    p = subprocess.run([sys.executable, "-m", "secure_agent_runtime", "verify-receipt", str(f)],
                       capture_output=True, text=True, timeout=60)
    assert p.returncode in (1, 2) and "Traceback" not in p.stderr
    if content == b'{"schema": 1}':
        assert p.returncode == 1  # readable, but not a receipt: a verification failure
    else:
        assert p.returncode == 2


def test_b5_verify_receipt_cli_refuses_non_regular_files(tmp_path):
    import subprocess
    import sys

    fifo = tmp_path / "pipe"
    os.mkfifo(fifo)
    p = subprocess.run([sys.executable, "-m", "secure_agent_runtime", "verify-receipt", str(fifo)],
                       capture_output=True, text=True, timeout=30)
    assert p.returncode == 2 and "not a regular file" in p.stderr


# -- B6, B9: configuration footguns fail loudly -------------------------------------------------------- #

def test_b6_empty_store_path_is_refused():
    with pytest.raises(ValueError):
        Store("")


@pytest.mark.parametrize("key", [b"", b"short", "a-str-key-0123456789"])
def test_b9_weak_or_wrong_type_hmac_keys_are_refused(rt, key):
    o = rt.propose(run_id="r", principal_id=AGENT, call_id="c", tool="read_note", arguments={"title": "todo"})
    with pytest.raises((ValueError, TypeError)):
        rt.receipt(o.key, signing_key=key)


# -- B7: hung threads are capped ----------------------------------------------------------------------- #

def test_b7_dispatch_is_throttled_when_too_many_workers_are_stuck(store):
    from pydantic import BaseModel, ConfigDict

    from secure_agent_runtime.contracts import Effect, ToolRegistry
    from secure_agent_runtime.policy import Policy, Principal
    from secure_agent_runtime.runtime import Runtime

    class M(BaseModel):
        model_config = ConfigDict(extra="forbid")
        n: int

    gate = threading.Event()
    reg = ToolRegistry()
    reg.tool(name="hang", input=M, output=M, effect=Effect.READ, timeout_s=0.01)(lambda a: gate.wait(5) and a)
    rt = Runtime(registry=reg, policy=Policy(), store=store, max_stuck_workers=2,
                 principals=[Principal("p", grants=frozenset({"hang"}))])
    try:
        states = [rt.execute(rt.propose(run_id="r", principal_id="p", call_id=f"c{i}", tool="hang",
                                        arguments={"n": i}).key).state for i in range(3)]
        assert states == ["failed", "failed", "approved"]  # the third is held, not dispatched
        assert store.events(kind="dispatch.throttled")
    finally:
        gate.set()


def test_b7_finished_workers_are_released(rt):
    for i in range(20):
        rt.execute(rt.propose(run_id="r", principal_id=AGENT, call_id=f"c{i}", tool="read_note",
                              arguments={"title": "todo"}).key)
    assert rt._live == {}


# -- B8: database errors surface as SAR errors ------------------------------------------------------- #

def test_b8_corrupt_database_is_a_store_error(tmp_path):
    from secure_agent_runtime.errors import StoreError

    (tmp_path / "sar.db").write_bytes(b"this is not sqlite" * 100)
    with pytest.raises(StoreError, match="cannot open"):
        Store(str(tmp_path / "sar.db"))


def test_b8_unknown_schema_version_is_refused(tmp_path):
    import sqlite3

    from secure_agent_runtime.errors import StoreError

    s = Store(str(tmp_path / "sar.db"))
    s.close()
    db = sqlite3.connect(str(tmp_path / "sar.db"))
    db.execute("PRAGMA user_version=99")
    db.close()
    with pytest.raises(StoreError, match="schema version 99"):
        Store(str(tmp_path / "sar.db"))


def test_a_store_that_fails_to_open_closes_its_connection_and_lock(tmp_path, monkeypatch):
    import sqlite3

    from secure_agent_runtime.errors import StoreError

    path = str(tmp_path / "sar.db")
    Store(path).close()
    db = sqlite3.connect(path)
    db.execute("PRAGMA user_version=99")
    db.close()
    opened: list[sqlite3.Connection] = []
    real_connect = sqlite3.connect

    def spy(*a, **kw):
        opened.append(real_connect(*a, **kw))
        return opened[-1]

    monkeypatch.setattr(sqlite3, "connect", spy)
    with pytest.raises(StoreError):
        Store(path)
    assert len(opened) == 1
    with pytest.raises(sqlite3.ProgrammingError):  # "Cannot operate on a closed database."
        opened[0].execute("SELECT 1")
    monkeypatch.undo()
    db = sqlite3.connect(path)
    db.execute("PRAGMA user_version=1")
    db.close()
    Store(path).close()  # the file lock was released too


def test_b8_closed_store_raises_a_store_error(store):
    from secure_agent_runtime.errors import StoreError

    store.close()
    with pytest.raises(StoreError):
        store.get_call("x")


def test_receipt_digest_helper_is_stable(rt):
    o = rt.propose(run_id="r", principal_id=AGENT, call_id="c", tool="read_note", arguments={"title": "todo"})
    r = rt.receipt(o.key)
    assert receipt_digest(r) == r["digest"]


def test_lock_contention_fails_closed_with_a_store_error(tmp_path, clock):
    """Someone else holds a write lock on the file (e.g. a backup tool): the dispatch
    claim fails with a StoreError, nothing is half-applied, and the tool never runs."""
    import sqlite3

    from secure_agent_runtime.errors import StoreError

    s = Store(str(tmp_path / "sar.db"), now=clock, busy_timeout_ms=100)
    rt, app = build_runtime(s)
    o = rt.propose(run_id="r", principal_id=AGENT, call_id="c", tool="read_note", arguments={"title": "todo"})
    other = sqlite3.connect(str(tmp_path / "sar.db"), isolation_level=None)
    other.execute("BEGIN IMMEDIATE")
    try:
        with pytest.raises(StoreError, match="locked"):
            rt.execute(o.key)
    finally:
        other.execute("ROLLBACK")
        other.close()
    assert s.get_call(o.key).state == "approved" and app.invocations["read_note"] == 0
    assert rt.execute(o.key).state == "succeeded" and s.verify_audit()[0]


# -- S1 (stress harness): the in-memory worker map is shared by every calling thread ----------------- #

def test_s1_worker_map_survives_concurrent_release_during_iteration(rt):
    """Deterministic version of the race: while execute() walks the map of running workers,
    another thread releases one of them. Without the lock this raised
    'dictionary changed size during iteration' out of execute()."""
    release = getattr(rt, "_release_worker", None)

    class Finished:
        def is_alive(self):
            return False

    class Racing:
        def is_alive(self):
            def other_thread():
                if release is not None:
                    release("k2", finished)
                else:  # pre-fix code had no release helper
                    rt._live.pop("k2", None)
            t = threading.Thread(target=other_thread)
            t.start()
            t.join(0.2)  # with the lock held by execute(), this thread waits; that's the fix
            return True

    finished = Finished()
    rt._live.update({"k1": Racing(), "k2": finished, "k3": Finished()})
    o = rt.propose(run_id="r", principal_id=AGENT, call_id="c", tool="read_note", arguments={"title": "todo"})
    assert rt.execute(o.key).state == "succeeded"


def test_s1_concurrent_executes_never_raise(store):
    from pydantic import BaseModel, ConfigDict

    from secure_agent_runtime.contracts import Effect, ToolRegistry
    from secure_agent_runtime.policy import Policy, Principal
    from secure_agent_runtime.runtime import Runtime

    class M(BaseModel):
        model_config = ConfigDict(extra="forbid")
        n: int

    def slowish(args):  # outlives its timeout, so workers stay registered while others come and go
        threading.Event().wait(0.02)
        return args

    reg = ToolRegistry()
    reg.tool(name="t", input=M, output=M, effect=Effect.READ, timeout_s=0.005)(slowish)
    rt = Runtime(registry=reg, policy=Policy(), store=store, max_stuck_workers=10_000,
                 principals=[Principal("p", grants=frozenset({"t"}))])
    keys = [rt.propose(run_id="r", principal_id="p", call_id=f"c{i}", tool="t", arguments={"n": i}).key
            for i in range(400)]
    errors: list[BaseException] = []

    def go(chunk):
        for k in chunk:
            try:
                rt.execute(k)
            except BaseException as exc:  # noqa: BLE001 - any exception here is the bug
                errors.append(exc)

    threads = [threading.Thread(target=go, args=(keys[i::16],)) for i in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(60)
    assert errors == []
    assert {store.get_call(k).state for k in keys} <= {"succeeded", "failed"}
