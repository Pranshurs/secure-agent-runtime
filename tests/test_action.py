"""Canonical action identity: equivalent proposals agree, any meaningful change disagrees."""

from __future__ import annotations

import dataclasses

import pytest

from secure_agent_runtime.action import Action
from secure_agent_runtime.examples.notes import AGENT, APPROVER


def prop(rt, call_id="c", args=None, tool="write_note", run_id="r", **kw):
    return rt.propose(run_id=run_id, principal_id=AGENT, call_id=call_id, tool=tool,
                      arguments={"title": "t", "body": "b"} if args is None else args, **kw)


def digest_of(rt, call_id, args, run_id="r", **kw):
    return rt.propose(run_id=run_id, principal_id=AGENT, call_id=call_id, tool="write_note",
                      arguments=args, **kw).action_digest


def test_reordered_arguments_give_the_same_args_digest(rt):
    a = rt.propose(run_id="r", principal_id=AGENT, call_id="c1", tool="write_note",
                   arguments={"title": "t", "body": "b"})
    b = rt.propose(run_id="r", principal_id=AGENT, call_id="c2", tool="write_note",
                   arguments={"body": "b", "title": "t"})
    ra, rb = rt.store.get_call(a.key), rt.store.get_call(b.key)
    assert ra.action["args_digest"] == rb.action["args_digest"]
    assert ra.action["args"] == rb.action["args"] == {"body": "b", "title": "t"}


def test_identical_proposals_under_one_key_are_one_action(rt):
    a = prop(rt, "c", {"title": "t", "body": "b"})
    b = prop(rt, "c", {"body": "b", "title": "t"})
    assert a.action_digest == b.action_digest and len(rt.store.calls()) == 1


@pytest.mark.parametrize("change", [
    {"body": "B"}, {"title": "u"}, {"body": "b "}, {"body": "b́"}, {"body": "é"},
])
def test_any_argument_change_changes_the_digest(rt, change):
    base = {"title": "t", "body": "b"}
    assert digest_of(rt, "c1", base) != digest_of(rt, "c2", {**base, **change})


def test_unicode_is_not_normalised_so_lookalikes_differ(rt):
    """NFC "é" and NFD "é" render alike but are different actions; nothing is folded."""
    assert digest_of(rt, "c1", {"title": "t", "body": "é"}) != digest_of(rt, "c2", {"title": "t", "body": "é"})


@pytest.mark.parametrize("value", [1, 1.0, True, None, ["b"], {"b": 1}])
def test_type_confusion_is_rejected_not_coerced(rt, value):
    o = rt.propose(run_id="r", principal_id=AGENT, call_id="c", tool="write_note",
                   arguments={"title": "t", "body": value})
    assert o.state == "invalid" and o.action_digest is None


def test_digest_covers_every_envelope_field(rt):
    o = prop(rt)
    a = Action.from_body(rt.store.get_call(o.key).action)
    assert a.digest == o.action_digest
    changes = {"action_id": "act_" + "0" * 24, "idempotency_key": "other", "actor": APPROVER, "run_id": "r2",
               "tool": "read_note", "tool_version": "2", "schema_digest": "sha256:" + "0" * 64,
               "args": {"title": "t", "body": "B"}, "authority": "external", "frame": {"required": []},
               "created_at": a.created_at + 1, "deadline": 1e10}
    assert set(changes) == {f.name for f in dataclasses.fields(Action)}  # nothing left uncovered
    for field, value in changes.items():
        assert dataclasses.replace(a, **{field: value}).digest != a.digest, field


def test_action_round_trips_through_its_body(rt):
    o = prop(rt)
    row = rt.store.get_call(o.key)
    a = Action.from_body(row.action)
    assert a.digest == o.action_digest == row.action_digest
    assert "args" not in a.public() and a.public()["digest"] == a.digest


def test_unknown_action_schema_is_refused(rt):
    o = prop(rt)
    body = dict(rt.store.get_call(o.key).action, schema="sar.action/v0")
    with pytest.raises(ValueError):
        Action.from_body(body)


def test_custom_idempotency_key_dedupes_across_runs(rt, app):
    for run in ("r1", "r2"):
        o = rt.propose(run_id=run, principal_id=AGENT, call_id="c", tool="read_note",
                       arguments={"title": "todo"}, idempotency_key="order-821-lookup")
        rt.execute(o.key)
    assert app.invocations["read_note"] == 1


def test_bad_idempotency_keys_are_malformed(rt):
    from secure_agent_runtime.runtime import MalformedProposal

    for key in ("", "\ud800", 5):
        with pytest.raises(MalformedProposal):
            rt.propose(run_id="r", principal_id=AGENT, call_id="c", tool="read_note",
                       arguments={"title": "todo"}, idempotency_key=key)
