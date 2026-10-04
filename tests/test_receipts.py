"""Agent Receipts: schema-valid, self-verifying, bound to the audit chain."""

from __future__ import annotations

import copy
import json

import jsonschema
import pytest

from secure_agent_runtime.examples import refund as rf
from secure_agent_runtime.examples import version_bump as vb
from secure_agent_runtime.examples.notes import AGENT
from secure_agent_runtime.receipts import receipt_json_schema, verify_receipt

from .conftest import cred

KEY = b"operator-secret-0123456789abcdef"
SCHEMA = receipt_json_schema()


def validate(receipt):
    jsonschema.validate(receipt, SCHEMA, format_checker=jsonschema.FormatChecker())


@pytest.fixture
def refunded(store):
    service = rf.PaymentService()
    rt = rf.build_runtime(service, store)
    o = rt.propose(run_id="t", principal_id=rf.AGENT, call_id="c", tool="refund",
                   arguments={"order": 821, "amount_inr": 4500})
    rt.approve(o.key, credential=cred(rt, rf.APPROVER), action_digest=o.action_digest)
    service.fail_next = "after_effect"
    rt.execute(o.key)
    rt.reconcile(o.key)
    return rt, o.key


def test_schema_itself_is_valid():
    jsonschema.Draft202012Validator.check_schema(SCHEMA)


def test_reconciled_refund_receipt(refunded):
    rt, key = refunded
    r = rt.receipt(key, signing_key=KEY, key_id="k1")
    validate(r)
    assert r["outcome"] == "verified" and r["execution"]["state"] == "succeeded"
    assert r["execution"]["dispatches"] == 1
    assert [x["data"].get("reconciled") for x in r["execution"]["reconciliation"]] == ["applied"]
    assert r["approval"]["approver"] == rf.APPROVER and r["approval"]["action_digest"] == r["action"]["digest"]
    assert r["action"]["tool"] == {"name": "refund", "version": "2026-10",
                                   "schema_digest": rt.registry.get("refund").schema_digest}
    assert [e["kind"] for e in r["audit"]["events"]] == [
        "call.requested", "call.awaiting_approval", "call.approved", "call.executing", "call.effect_unknown",
        "call.succeeded"]
    assert verify_receipt(r, signing_key=KEY, store=rt.store) == []


def test_receipts_carry_digests_not_argument_or_result_values(refunded):
    rt, key = refunded
    r = rt.receipt(key)
    assert "args" not in r["action"] and r["action"]["args_digest"].startswith("sha256:")
    # The effects section names observed resources (paths, ids) and quotes the operator's
    # declared frame, which may contain argument values; everything else holds digests only.
    assert "4500" in json.dumps(r["effects"]["declared"]) and "rf_0001" in json.dumps(r["effects"]["check"])
    rest = {k: v for k, v in r.items() if k != "effects"}
    rest["action"] = {k: v for k, v in r["action"].items() if k != "frame"}
    assert "4500" not in json.dumps(rest) and "rf_0001" not in json.dumps(rest)


@pytest.mark.parametrize("path,value", [
    (("outcome",), "violated"), (("execution", "dispatches"), 0), (("approval", "approver"), "mallory"),
    (("action", "tool", "version"), "2026-11"), (("effects", "check", "undeclared"), ["x"]),
    (("result", "digest"), "sha256:" + "0" * 64),
])
def test_editing_any_field_breaks_the_digest(refunded, path, value):
    rt, key = refunded
    r = rt.receipt(key)
    forged = copy.deepcopy(r)
    target = forged
    for p in path[:-1]:
        target = target[p]
    target[path[-1]] = value
    assert verify_receipt(r) == []
    assert "digest does not match the receipt's content" in verify_receipt(forged)


def test_recomputed_digest_without_the_key_fails_the_signature(refunded):
    from secure_agent_runtime.receipts import receipt_digest

    rt, key = refunded
    forged = rt.receipt(key, signing_key=KEY)
    forged["outcome"] = "violated"
    forged["digest"] = receipt_digest(forged)
    assert verify_receipt(forged) == []  # a digest alone proves integrity, not authorship
    assert verify_receipt(forged, signing_key=KEY) == ["signature does not verify"]
    assert verify_receipt(forged, signing_key=b"other-key-0123456789") == ["signature does not verify"]


def test_unsigned_receipt_fails_when_a_signature_is_required(refunded):
    rt, key = refunded
    assert verify_receipt(rt.receipt(key), signing_key=KEY) == ["receipt is not signed"]


def test_receipt_is_bound_to_the_audit_chain(refunded):
    rt, key = refunded
    r = rt.receipt(key)
    with rt.store.tx() as db:
        db.execute("UPDATE events SET data_json='{}' WHERE seq=?", (r["audit"]["events"][2]["seq"],))
    problems = verify_receipt(r, store=rt.store)
    assert any(p.startswith("audit chain") for p in problems)


def test_receipt_naming_other_audit_events_fails_against_the_store(refunded):
    from secure_agent_runtime.receipts import receipt_digest

    rt, key = refunded
    r = rt.receipt(key)
    r["audit"]["events"][-1]["hash"] = "0" * 64  # claims an event the chain doesn't contain
    r["digest"] = receipt_digest(r)
    assert verify_receipt(r) == []
    assert verify_receipt(r, store=rt.store) == [f"audit event {r['audit']['events'][-1]['seq']} is missing or differs"]


def test_receipt_detects_a_rewritten_stored_action(refunded):
    rt, key = refunded
    r = rt.receipt(key)
    with rt.store.tx() as db:
        db.execute("UPDATE calls SET action_digest='sha256:' || hex(randomblob(32)) WHERE key=?", (key,))
    assert "stored action digest differs from the receipt" in verify_receipt(r, store=rt.store)


def test_receipt_still_verifies_after_later_activity(refunded):
    rt, key = refunded
    r = rt.receipt(key)
    rt.propose(run_id="t", principal_id=rf.AGENT, call_id="later", tool="refund",
               arguments={"order": 1, "amount_inr": 1})
    assert verify_receipt(r, store=rt.store) == []


def test_frame_violation_receipt(tmp_path, store):
    rt, key = vb.run(vb.sloppy_agent, tmp_path, store)
    r = rt.receipt(key)
    validate(r)
    assert r["outcome"] == "violated" and r["effects"]["declared"]["forbidden"] == ["tests/**", ".github/**"]
    assert {c["path"] for c in r["effects"]["check"]["observed"]} == {"pyproject.toml", "uv.lock", "README.md",
                                                                     "tests/test_pkg.py"}


@pytest.mark.parametrize("make,outcome", [
    (lambda rt: rt.propose(run_id="r", principal_id=AGENT, call_id="c", tool="nope", arguments={}), "not_executed"),
    (lambda rt: rt.propose(run_id="r", principal_id=AGENT, call_id="c", tool="delete_note",
                           arguments={"title": "t"}), "not_executed"),
    (lambda rt: rt.propose(run_id="r", principal_id=AGENT, call_id="c", tool="write_note",
                           arguments={"title": "t", "body": "b"}), "pending"),
    (lambda rt: rt.execute(rt.propose(run_id="r", principal_id=AGENT, call_id="c", tool="read_note",
                                      arguments={"title": "todo"}).key), "completed"),
])
def test_receipts_for_every_kind_of_ending_are_schema_valid(rt, make, outcome):
    o = make(rt)
    r = rt.receipt(o.key)
    validate(r)
    assert r["outcome"] == outcome and verify_receipt(r, store=rt.store) == []


def test_not_a_receipt():
    assert verify_receipt({"schema": "something/else"}) == ["not a sar.receipt/v1 receipt"]
    assert verify_receipt([]) == ["not a sar.receipt/v1 receipt"]


@pytest.mark.parametrize("path,value", [
    (("execution", "state"), "cancelled"), (("outcome",), "completed"), (("execution", "dispatches"), 2),
    (("result", "digest"), "sha256:" + "1" * 64), (("approval",), None), (("effects", "check"), None),
])
def test_forged_receipt_with_recomputed_digest_fails_against_the_store(refunded, path, value):
    from secure_agent_runtime.receipts import receipt_digest

    rt, key = refunded
    forged = rt.receipt(key)
    target = forged
    for p in path[:-1]:
        target = target[p]
    target[path[-1]] = value
    forged["digest"] = receipt_digest(forged)
    assert verify_receipt(forged) == []  # self-consistent...
    assert f"{path[0]} differs from the store" in verify_receipt(forged, store=rt.store)  # ...but not true


def test_receipt_listing_no_audit_events_fails_against_the_store(refunded):
    from secure_agent_runtime.receipts import receipt_digest

    rt, key = refunded
    r = rt.receipt(key)
    r["audit"]["events"] = []
    r["digest"] = receipt_digest(r)
    assert "receipt does not list exactly this action's audit events" in verify_receipt(r, store=rt.store)


def test_stale_receipt_is_reported(store):
    service = rf.PaymentService()
    rt = rf.build_runtime(service, store)
    o = rt.propose(run_id="t", principal_id=rf.AGENT, call_id="c", tool="refund",
                   arguments={"order": 1, "amount_inr": 1})
    early = rt.receipt(o.key)
    assert early["outcome"] == "pending" and verify_receipt(early, store=store) == []
    rt.approve(o.key, credential=cred(rt, rf.APPROVER), action_digest=o.action_digest)
    assert verify_receipt(early, store=store) == ["stale receipt: the action changed after it was issued"]


@pytest.mark.parametrize("mangle", [
    lambda r: r.__setitem__("signature", {"alg": "HMAC-SHA256", "key_id": "k", "value": "é" * 64}),
    lambda r: r.__setitem__("audit", "nope"),
    lambda r: r["audit"].__setitem__("events", [1, 2]),
    lambda r: r.__setitem__("idempotency_key", None),
])
def test_malformed_receipts_get_a_verdict_not_a_crash(refunded, mangle):
    rt, key = refunded
    r = rt.receipt(key, signing_key=KEY)
    mangle(r)
    assert verify_receipt(r, signing_key=KEY, store=rt.store)  # some problem, and no exception
