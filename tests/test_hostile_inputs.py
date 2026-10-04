"""Regression tests from an adversarial review: hostile inputs and misbehaving tools must
end in a recorded, safe state, never in an exception or a call stuck in ``executing``."""

from __future__ import annotations

import sqlite3
import threading
import time

import pytest
from pydantic import BaseModel, ConfigDict, field_validator

from secure_agent_runtime.agent import Agent
from secure_agent_runtime.contracts import MAX_JSON_BYTES, Effect, ToolRegistry
from secure_agent_runtime.examples.notes import AGENT, APPROVER, ScriptedModel, build_runtime
from secure_agent_runtime.policy import Policy, Principal
from secure_agent_runtime.runtime import MalformedProposal, Runtime

from .conftest import execution_events


def deep(n):
    d: list = []
    for _ in range(n):
        d = [d]
    return d


HOSTILE_ARGS = [
    {"title": "\ud800"},                       # lone surrogate: not encodable as UTF-8
    {"title": "todo", "n": 10 ** 5000},        # beyond the int-to-str digit limit
    {"title": deep(5000)},                     # beyond the recursion limit
    {"title": "todo", "pad": "x" * MAX_JSON_BYTES},
    {"\ud800": 1},
]
HOSTILE_IDS = ["surrogate", "bigint", "deep", "huge", "surrogate-key"]


@pytest.mark.parametrize("arguments", HOSTILE_ARGS, ids=HOSTILE_IDS)
def test_hostile_arguments_become_invalid_calls(rt, app, arguments):
    o = rt.propose(run_id="r", principal_id=AGENT, call_id="c", tool="read_note", arguments=arguments)
    assert o.state == "invalid"
    assert rt.execute(o.key).state == "invalid" and sum(app.invocations.values()) == 0
    again = rt.propose(run_id="r", principal_id=AGENT, call_id="c", tool="read_note", arguments=arguments)
    assert again.state == "invalid"  # replay of a hostile proposal is still answered from the store
    assert rt.store.verify_audit()[0]


@pytest.mark.parametrize("tool", ["\ud800", deep(5000), "x" * 10_000], ids=["surrogate", "deep", "long"])
def test_hostile_tool_names_become_invalid_calls(rt, tool):
    o = rt.propose(run_id="r", principal_id=AGENT, call_id="c", tool=tool, arguments={})
    assert o.state == "invalid" and len(o.tool) < 100


@pytest.mark.parametrize("call_id", ["\ud800", "x" * 257], ids=["surrogate", "long"])
def test_hostile_call_ids_are_malformed(rt, call_id):
    with pytest.raises(MalformedProposal):
        rt.propose(run_id="r", principal_id=AGENT, call_id=call_id, tool="read_note",
                   arguments={"title": "todo"})
    assert rt.store.calls() == []


@pytest.mark.parametrize("arguments", HOSTILE_ARGS, ids=HOSTILE_IDS)
def test_agent_survives_hostile_arguments(store, arguments):
    rt, app = build_runtime(store)
    model = ScriptedModel([{"tool_calls": [{"id": "c", "name": "read_note", "arguments": arguments}]},
                           {"text": "ok"}])
    res = Agent(rt, model, AGENT).start("r", "x")
    assert res.status == "completed" and [o.state for o in res.outcomes] == ["invalid"]
    assert sum(app.invocations.values()) == 0


def test_agent_survives_hostile_call_id(store):
    rt, app = build_runtime(store)
    call = {"id": "\ud800", "name": "read_note", "arguments": {"title": "a"}}
    model = ScriptedModel([{"tool_calls": [call]}])
    assert Agent(rt, model, AGENT).start("r", "x").status == "malformed_model_output"


# -- misbehaving tools ------------------------------------------------------------------ #

def _single_tool_runtime(store, fn, output=None, timeout_s=2.0, effect=Effect.READ):
    class In(BaseModel):
        model_config = ConfigDict(extra="forbid")
        v: str = "x"

    class Out(BaseModel):
        model_config = ConfigDict(extra="forbid")
        v: object = None

    reg = ToolRegistry()
    reg.tool(name="t", input=In, output=output or Out, effect=effect, timeout_s=timeout_s)(fn)
    return Runtime(registry=reg, policy=Policy(), store=store,
                   principals=[Principal("p", grants=frozenset({"t"})),
                               Principal(APPROVER, can_approve=True)])


def _run(rt, arguments=None):
    o = rt.propose(run_id="r", principal_id="p", call_id="c", tool="t", arguments=arguments or {})
    return rt.execute(o.key)


def test_tool_raising_systemexit_is_failed_not_stuck(store):
    def bye(args):
        raise SystemExit(3)

    rt = _single_tool_runtime(store, bye)
    out = _run(rt)
    assert out.state == "failed" and out.reason == "tool raised SystemExit"
    assert store.calls(state="executing") == []


@pytest.mark.parametrize("value,label", [(deep(5000), "deep"), ("x" * (MAX_JSON_BYTES + 1), "huge"),
                                         ("\ud800", "surrogate"), (10 ** 5000, "bigint")],
                         ids=["deep", "huge", "surrogate", "bigint"])
def test_unserialisable_tool_output_is_rejected_not_stuck(store, value, label):
    rt = _single_tool_runtime(store, lambda args: {"v": value})
    out = _run(rt)
    assert out.state == "output_rejected", label
    assert store.calls(state="executing") == []


def test_output_model_validator_that_raises_is_rejected(store):
    class Out(BaseModel):
        model_config = ConfigDict(extra="forbid")
        v: str

        @field_validator("v")
        @classmethod
        def boom(cls, v):
            raise RuntimeError("not a ValueError")

    rt = _single_tool_runtime(store, lambda args: {"v": "a"}, output=Out)
    assert _run(rt).state == "output_rejected"


def test_unstable_input_validator_is_refused_before_hashing(store):
    """A validator that rewrites its value on every pass would let the tool see args other
    than the approved ones; such input is refused at proposal time."""

    class In(BaseModel):
        model_config = ConfigDict(extra="forbid")
        v: str

        @field_validator("v")
        @classmethod
        def prefix(cls, v):
            return "pfx:" + v

    class Out(BaseModel):
        model_config = ConfigDict(extra="forbid")

    seen = []
    reg = ToolRegistry()

    @reg.tool(input=In, output=Out, effect=Effect.READ)
    def t(args):
        seen.append(args.v)
        return Out()

    rt = Runtime(registry=reg, policy=Policy(), store=store,
                 principals=[Principal("p", grants=frozenset({"t"}))])
    o = rt.propose(run_id="r", principal_id="p", call_id="c", tool="t", arguments={"v": "x"})
    assert o.state == "invalid" and "round-trip" in o.reason
    assert rt.execute(o.key).state == "invalid" and seen == []


def test_tool_receives_exactly_the_approved_arguments(store):
    """A stable normalising validator is fine: the tool sees the normalised, approved value."""

    class In(BaseModel):
        model_config = ConfigDict(extra="forbid")
        v: str

        @field_validator("v")
        @classmethod
        def lower(cls, v):
            return v.lower()

    class Out(BaseModel):
        model_config = ConfigDict(extra="forbid")

    seen = []
    reg = ToolRegistry()

    @reg.tool(input=In, output=Out, effect=Effect.WRITE)
    def t(args):
        seen.append(args.model_dump())
        return Out()

    rt = Runtime(registry=reg, policy=Policy(), store=store,
                 principals=[Principal("p", grants=frozenset({"t"})), Principal(APPROVER, can_approve=True)])
    o = rt.propose(run_id="r", principal_id="p", call_id="c", tool="t", arguments={"v": "HeLLo"})
    row = store.get_call(o.key)
    assert row.args == {"v": "hello"}
    rt.approve(o.key, approver_id=APPROVER, args_hash=o.args_hash)
    assert rt.execute(o.key).state == "succeeded" and seen == [row.args]


def test_schema_default_added_after_approval_blocks_execution(rt, app):
    """If the current schema would hand the tool fields the approver never saw, block."""
    import dataclasses

    from pydantic import Field

    o = rt.propose(run_id="r", principal_id=AGENT, call_id="c", tool="write_note",
                   arguments={"title": "todo", "body": "b"})
    rt.approve(o.key, approver_id=APPROVER, args_hash=o.args_hash)

    class WriteV2(BaseModel):
        model_config = ConfigDict(extra="forbid")
        title: str
        body: str
        overwrite: bool = Field(default=True)

    spec = rt.registry.get("write_note")
    rt.registry._tools["write_note"] = dataclasses.replace(spec, input_model=WriteV2)
    out = rt.execute(o.key)
    assert out.state == "cancelled" and "no longer validate" in out.reason
    assert app.invocations["write_note"] == 0


def test_late_result_after_store_close_does_not_raise_in_worker(clock, caplog):
    from secure_agent_runtime.store import Store

    store = Store(now=clock)
    release, done = threading.Event(), threading.Event()
    errors = []
    old_hook = threading.excepthook
    threading.excepthook = lambda a: errors.append(a)
    try:
        def slow(args):
            release.wait(5)
            done.set()
            return {"v": None}

        rt = _single_tool_runtime(store, slow, timeout_s=0.05)
        assert _run(rt).state == "timed_out"
        store.close()
        release.set()
        assert done.wait(5)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and not caplog.records:
            time.sleep(0.005)
    finally:
        threading.excepthook = old_hook
    assert errors == []
    assert any("could not record the result" in r.getMessage() for r in caplog.records)


def test_failed_commit_rolls_back_and_store_stays_usable(rt, app):
    o = rt.propose(run_id="r", principal_id=AGENT, call_id="c", tool="write_note",
                   arguments={"title": "todo", "body": "b"})
    real = rt.store._db

    class FailingCommit:
        armed = True

        def __getattr__(self, name):
            return getattr(real, name)

        def execute(self, sql, *a):
            if sql == "COMMIT" and FailingCommit.armed:
                FailingCommit.armed = False
                raise sqlite3.OperationalError("disk I/O error")
            return real.execute(sql, *a)

    rt.store._db = FailingCommit()
    with pytest.raises(sqlite3.OperationalError):
        rt.approve(o.key, approver_id=APPROVER, args_hash=o.args_hash)
    assert rt.store.get_call(o.key).state == "pending_approval"  # rolled back
    assert rt.approve(o.key, approver_id=APPROVER, args_hash=o.args_hash).state == "approved"
    assert rt.store.verify_audit()[0]
    assert rt.execute(o.key).state == "succeeded" and execution_events(rt.store) == 1


# -- agent loop ---------------------------------------------------------------------------- #

def test_model_reusing_a_call_id_for_a_different_call_is_malformed(store):
    rt, app = build_runtime(store)
    model = ScriptedModel([
        {"tool_calls": [{"id": "c1", "name": "read_note", "arguments": {"title": "todo"}}]},
        {"tool_calls": [{"id": "c1", "name": "read_note", "arguments": {"title": "other"}}]},
    ])
    res = Agent(rt, model, AGENT).start("r", "x")
    assert res.status == "malformed_model_output" and app.invocations["read_note"] == 1
    assert rt.store.events(kind="model.malformed_output")[0].data["error"] == "ReplayDivergence"


def test_too_many_calls_in_one_turn_is_malformed(store):
    rt, app = build_runtime(store)
    calls = [{"id": f"c{i}", "name": "read_note", "arguments": {"title": "todo"}} for i in range(17)]
    res = Agent(rt, ScriptedModel([{"tool_calls": calls}]), AGENT).start("r", "x")
    assert res.status == "malformed_model_output" and sum(app.invocations.values()) == 0


def test_resume_reports_expired_approvals_and_finishes(store, clock):
    rt, app = build_runtime(store, approval_ttl_s=60)
    model = ScriptedModel([
        {"tool_calls": [{"id": "c1", "name": "write_note", "arguments": {"title": "t", "body": "b"}}]},
        {"text": "gave up"},
    ])
    agent = Agent(rt, model, AGENT)
    assert agent.start("r", "x").status == "awaiting_approval"
    clock.advance(61)
    res = agent.resume("r")
    assert res.status == "completed" and [o.state for o in res.outcomes] == ["expired"]
    assert app.invocations["write_note"] == 0


def test_finished_run_cannot_be_resumed(store):
    rt, _ = build_runtime(store)
    model = ScriptedModel([{"text": "hi"}])
    agent = Agent(rt, model, AGENT)
    agent.start("r", "x")
    with pytest.raises(ValueError, match="already finished"):
        agent.resume("r")
    assert len(model.seen) == 1
