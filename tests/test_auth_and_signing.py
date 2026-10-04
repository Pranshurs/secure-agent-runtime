"""Authenticated, principal-bound approvals and Ed25519-signed receipts."""

from __future__ import annotations

import copy
import os

import pytest

from secure_agent_runtime.auth import AuthContext, TokenAuthenticator
from secure_agent_runtime.examples import refund as rf
from secure_agent_runtime.examples.notes import AGENT, APPROVER, build_runtime
from secure_agent_runtime.receipts import receipt_digest, verify_receipt
from secure_agent_runtime.runtime import ApprovalRefused
from secure_agent_runtime.signing import Ed25519Signer, HmacSigner

from .conftest import cred


def pending(rt, call_id="w", body="b"):
    return rt.propose(run_id="r", principal_id=AGENT, call_id=call_id, tool="write_note",
                      arguments={"title": "t", "body": body})


# -- approvals are bound to an authenticated principal --------------------------------------------- #

def test_runtime_without_an_authenticator_refuses_all_approvals(store):
    from secure_agent_runtime.examples.notes import NotesApp, build_registry, principals
    from secure_agent_runtime.policy import Policy
    from secure_agent_runtime.runtime import Runtime

    rt = Runtime(registry=build_registry(NotesApp()), policy=Policy(), principals=principals(), store=store)
    o = pending(rt)
    with pytest.raises(ApprovalRefused, match="no authenticator"):
        rt.approve(o.key, credential="anything", action_digest=o.action_digest)


def test_a_bare_principal_id_is_not_a_credential(rt):
    o = pending(rt)
    with pytest.raises(ApprovalRefused, match="authentication failed"):
        rt.approve(o.key, credential=APPROVER, action_digest=o.action_digest)


def test_approval_records_the_authenticated_context_not_the_credential(rt):
    o = pending(rt)
    token = cred(rt, APPROVER)
    rt.approve(o.key, credential=token, action_digest=o.action_digest)
    approval = rt.store.get_call(o.key).approval
    assert approval["approver"] == APPROVER and approval["auth"]["method"] == "demo-token"
    assert token not in str(approval) and token not in str([e.data for e in rt.store.events()])


def test_credential_scoped_to_another_action_is_refused(rt, app):
    a, b = pending(rt, "a", "A"), pending(rt, "b", "B")
    token = cred(rt, APPROVER, scope=a.action_digest)   # the approver was shown action A
    with pytest.raises(ApprovalRefused, match="scoped to a different action"):
        rt.approve(b.key, credential=token, action_digest=b.action_digest)
    rt.approve(a.key, credential=token, action_digest=a.action_digest)
    assert rt.execute(b.key).state == "awaiting_approval"


def test_an_approval_that_loses_a_race_does_not_burn_the_credential(rt):
    """The action is cancelled between reading it and the approval's compare-and-set
    (forced here inside authentication). The approval is refused and the credential stays
    unused, so the approver can still use it."""
    a, b = pending(rt, "a", "A"), pending(rt, "b", "B")
    token = cred(rt, APPROVER)
    real = rt.authenticator.authenticate

    def cancel_first(credential):
        rt.authenticator.authenticate = real
        rt.cancel(a.key)  # a concurrent caller wins the race
        return real(credential)

    rt.authenticator.authenticate = cancel_first
    with pytest.raises(ApprovalRefused, match="no longer awaiting approval"):
        rt.approve(a.key, credential=token, action_digest=a.action_digest)
    assert rt.store.get_call(a.key).state == "cancelled"
    assert rt.approve(b.key, credential=token, action_digest=b.action_digest).state == "approved"


def test_credential_replay_is_refused(rt):
    a, b = pending(rt, "a", "A"), pending(rt, "b", "B")
    token = cred(rt, APPROVER)
    rt.approve(a.key, credential=token, action_digest=a.action_digest)
    with pytest.raises(ApprovalRefused, match="already been used"):
        rt.approve(b.key, credential=token, action_digest=b.action_digest)
    assert rt.store.get_call(b.key).state == "awaiting_approval"


def test_expired_credential_is_refused(rt, clock):
    o = pending(rt)
    token = cred(rt, APPROVER)
    clock.advance(rt.authenticator.ttl_s + 1)
    with pytest.raises(ApprovalRefused, match="expired"):
        rt.approve(o.key, credential=token, action_digest=o.action_digest)


def test_authenticated_subject_must_be_an_approver_and_not_the_requester(rt):
    o = pending(rt)
    for who, why in ((AGENT, "not an approver"), ("mallory", "unknown approver")):
        with pytest.raises(ApprovalRefused, match=why):
            rt.approve(o.key, credential=cred(rt, who), action_digest=o.action_digest)


class Broken:
    def authenticate(self, credential):
        raise RuntimeError("idp down")


class Lies:
    def authenticate(self, credential):
        return {"subject": APPROVER}  # not an AuthContext


@pytest.mark.parametrize("authenticator", [Broken(), Lies()])
def test_misbehaving_authenticator_fails_closed(store, authenticator):
    rt, app = build_runtime(store)
    rt.authenticator = authenticator
    o = pending(rt)
    with pytest.raises(ApprovalRefused):
        rt.approve(o.key, credential="x", action_digest=o.action_digest)
    assert rt.execute(o.key).state == "awaiting_approval" and app.invocations["write_note"] == 0


def test_approval_substitution_in_storage_is_caught(rt, app):
    """Approve A, then swap in an approval record naming another approver: the audit
    event no longer matches, so dispatch is blocked."""
    from secure_agent_runtime.contracts import canonical_json

    o = pending(rt)
    rt.approve(o.key, credential=cred(rt, APPROVER), action_digest=o.action_digest)
    approval = dict(rt.store.get_call(o.key).approval, approver="someone-else")
    with rt.store.tx() as db:
        db.execute("UPDATE calls SET approval_json=? WHERE key=?", (canonical_json(approval), o.key))
    out = rt.execute(o.key)
    assert out.state == "cancelled" and app.invocations["write_note"] == 0


def test_auth_context_rejects_empty_fields():
    with pytest.raises(ValueError):
        AuthContext(subject="", method="m", issuer="i", credential_id="c")


def test_token_authenticator_ignores_non_string_credentials():
    assert TokenAuthenticator().authenticate(None) is None
    assert TokenAuthenticator().authenticate(b"x") is None


def test_reject_and_resolve_also_require_authentication(rt):
    o = pending(rt)
    with pytest.raises(ApprovalRefused):
        rt.reject(o.key, credential="forged")
    assert rt.reject(o.key, credential=cred(rt, APPROVER)).state == "rejected"


# -- Ed25519 receipts ---------------------------------------------------------------------------------- #

@pytest.fixture
def signed(store):
    service = rf.PaymentService()
    rt = rf.build_runtime(service, store, isolation="thread")
    o = rt.propose(run_id="t", principal_id=rf.AGENT, call_id="c", tool="refund",
                   arguments={"order": 821, "amount_inr": 4500})
    rf.approve_as_finance(rt, o)
    rt.execute(o.key)
    signer = Ed25519Signer.generate("ops-2026-10")
    keys = {signer.key_id: signer.public_key_bytes()}
    return rt, o, signer, keys, rt.receipt(o.key, signer=signer)


def test_ed25519_receipt_verifies_with_only_the_public_key(signed):
    rt, o, signer, keys, r = signed
    assert r["signature"]["alg"] == "Ed25519" and len(r["signature"]["value"]) == 128
    assert verify_receipt(r, public_keys=keys) == []
    assert verify_receipt(r, public_keys=keys, store=rt.store, expect_action_digest=o.action_digest,
                          expect_key=o.key) == []


def test_ed25519_body_tamper_with_recomputed_digest_fails(signed):
    rt, o, signer, keys, r = signed
    forged = copy.deepcopy(r)
    forged["outcome"] = "violated"
    forged["digest"] = receipt_digest(forged)
    assert verify_receipt(forged) == []  # self-consistent...
    assert verify_receipt(forged, public_keys=keys) == ["signature does not verify"]  # ...but not signed


def test_ed25519_signature_tamper_fails(signed):
    rt, o, signer, keys, r = signed
    forged = copy.deepcopy(r)
    v = forged["signature"]["value"]
    forged["signature"]["value"] = ("0" if v[0] != "0" else "1") + v[1:]
    assert verify_receipt(forged, public_keys=keys) == ["signature does not verify"]


def test_ed25519_wrong_public_key_fails(signed):
    rt, o, signer, keys, r = signed
    other = Ed25519Signer.generate("ops-2026-10")
    assert verify_receipt(r, public_keys={"ops-2026-10": other.public_key_bytes()}) == ["signature does not verify"]


def test_ed25519_unknown_or_changed_key_id_fails(signed):
    rt, o, signer, keys, r = signed
    assert verify_receipt(r, public_keys={"other": keys["ops-2026-10"]}) == ["unknown signing key id 'ops-2026-10'"]
    forged = copy.deepcopy(r)
    forged["signature"]["key_id"] = "other"
    assert verify_receipt(forged, public_keys={"other": keys["ops-2026-10"]}) == ["signature does not verify"]


def test_ed25519_algorithm_confusion_fails(signed):
    rt, o, signer, keys, r = signed
    forged = copy.deepcopy(r)
    forged["signature"]["alg"] = "HMAC-SHA256"
    assert verify_receipt(forged, signing_key=keys["ops-2026-10"] * 2) == ["signature does not verify"]
    forged["signature"]["alg"] = "none"
    assert verify_receipt(forged, public_keys=keys) == ["unsupported signature algorithm 'none'"]


def test_old_receipt_after_state_change_is_stale(store):
    service = rf.PaymentService()
    rt = rf.build_runtime(service, store, isolation="thread")
    o = rt.propose(run_id="t", principal_id=rf.AGENT, call_id="c", tool="refund",
                   arguments={"order": 1, "amount_inr": 1})
    signer = Ed25519Signer.generate("k")
    early = rt.receipt(o.key, signer=signer)
    rf.approve_as_finance(rt, o)
    problems = verify_receipt(early, public_keys={"k": signer.public_key_bytes()}, store=rt.store)
    assert problems == ["stale receipt: the action changed after it was issued"]


def test_events_that_change_nothing_do_not_make_a_receipt_stale(store):
    """Anyone who can call the API can replay a call or attempt an approval. Those append
    audit events but change nothing, so they must not invalidate receipts already issued."""
    service = rf.PaymentService()
    rt = rf.build_runtime(service, store, isolation="thread")
    o = rt.propose(run_id="t", principal_id=rf.AGENT, call_id="c", tool="refund",
                   arguments={"order": 1, "amount_inr": 1})
    receipt = rt.receipt(o.key)
    rt.propose(run_id="t", principal_id=rf.AGENT, call_id="c", tool="refund", arguments={"order": 1, "amount_inr": 1})
    with pytest.raises(ApprovalRefused):
        rt.approve(o.key, credential="not-a-credential", action_digest=o.action_digest)
    assert {"call.replayed", "approval.refused"} <= {e.kind for e in store.events(call_key=o.key)}
    assert verify_receipt(receipt, expect_key=o.key, store=store) == []
    rf.approve_as_finance(rt, o)  # a real change still makes it stale
    assert verify_receipt(receipt, expect_key=o.key, store=store) == [
        "stale receipt: the action changed after it was issued"]


def test_receipt_copied_to_another_action_fails(signed):
    rt, o, signer, keys, r = signed
    other = rt.propose(run_id="t", principal_id=rf.AGENT, call_id="c2", tool="refund",
                       arguments={"order": 821, "amount_inr": 4500})
    assert verify_receipt(r, public_keys=keys, expect_action_digest=other.action_digest) == [
        "receipt is for a different action"]
    assert verify_receipt(r, public_keys=keys, expect_key=other.key) == [
        "receipt is for a different idempotency key"]
    moved = copy.deepcopy(r)
    moved["idempotency_key"] = other.key
    moved["digest"] = receipt_digest(moved)
    assert verify_receipt(moved, public_keys=keys) == ["signature does not verify"]


def test_signed_receipts_are_schema_valid(signed):
    import jsonschema

    from secure_agent_runtime.receipts import receipt_json_schema

    rt, o, signer, keys, r = signed
    jsonschema.validate(r, receipt_json_schema())
    hm = rt.receipt(o.key, signer=HmacSigner(os.urandom(32), "hm"))
    jsonschema.validate(hm, receipt_json_schema())


def test_signer_input_validation():
    with pytest.raises(TypeError):
        Ed25519Signer(object(), "k")
    with pytest.raises(ValueError):
        Ed25519Signer.generate("")
    with pytest.raises(ValueError):
        HmacSigner(b"x" * 32, "k" * 129)
