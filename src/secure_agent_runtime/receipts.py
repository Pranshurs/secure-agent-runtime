"""Agent Receipts: a machine-verifiable record of one action.

A receipt says what was proposed (the action envelope, without argument values), who
authorised it and how (policy decision, approval and its digest), what happened (state,
number of dispatches, reconciliation), what it returned (result digest), what it changed
compared with what it was allowed to change (frame-condition result), and where all of
that sits in the tamper-evident audit chain (event hashes plus the chain head).

Integrity has two layers:

* ``digest`` is SHA-256 over the canonical JSON of the receipt without ``digest`` and
  ``signature``, so any edit to the receipt is detectable.
* ``signature`` (optional) covers ``{alg, key_id, digest}``. ``Ed25519`` lets anyone
  holding the public key verify, and only the private-key holder sign; ``HMAC-SHA256``
  is symmetric (see :mod:`.signing`).

:func:`verify_receipt` checks the digest, the signature against the keys it is given,
optionally that the receipt is for an expected action, and, given the store, that the
receipt matches the store and the store's state is backed by its audit log.

The schema is ``sar.receipt/v1``; its JSON Schema ships as
``secure_agent_runtime/schemas/agent-receipt-v1.schema.json``.
"""

from __future__ import annotations

import hashlib
import json
from importlib import resources
from typing import Any

from .action import sha256_text
from .contracts import canonical_json
from .signing import HmacSigner, verify_ed25519
from .store import Store, approval_digest

RECEIPT_SCHEMA = "sar.receipt/v1"

_NOT_EXECUTED = {"invalid", "denied", "rejected", "expired", "cancelled"}


def receipt_json_schema() -> dict[str, Any]:
    text = resources.files("secure_agent_runtime").joinpath("schemas/agent-receipt-v1.schema.json").read_text()
    return json.loads(text)


def _outcome(state: str, frame: dict[str, Any] | None, dispatches: int) -> str:
    if state == "succeeded":
        return frame["verdict"] if frame else "completed"
    if state == "effect_unknown":
        return "unknown"
    if state in ("failed", "output_rejected"):
        return "failed" if dispatches else "not_executed"
    if state in _NOT_EXECUTED:
        return "not_executed"
    return "pending"  # awaiting_approval, approved, executing


def build_receipt(store: Store, key: str, *, signer: Any = None, signing_key: bytes | None = None,
                  key_id: str = "default") -> dict[str, Any]:
    """``signer`` is an :class:`~.signing.Ed25519Signer` or :class:`~.signing.HmacSigner`;
    ``signing_key`` is shorthand for an HMAC signer."""
    if signer is None and signing_key is not None:
        signer = HmacSigner(signing_key, key_id)
    row = store.get_call(key)
    if row is None:
        raise KeyError(f"no action {key!r}")
    events = store.events(call_key=key)
    seq, head = store.head()
    initial = next((e for e in events if e.kind != "call.requested"), None)
    reconciliation = [{"kind": e.kind, "data": e.data, "at": e.ts} for e in events
                      if e.kind.startswith("reconcile.") or "reconciled" in e.data or "resolved_by" in e.data]
    timestamps = {"proposed_at": row.created_at, "updated_at": row.updated_at,
                  "first_dispatch_at": next((e.ts for e in events if e.kind == "call.executing"), None)}

    body: dict[str, Any] = {
        "schema": RECEIPT_SCHEMA,
        "receipt_id": f"rcpt_{hashlib.sha256(f'{key}|{seq}'.encode()).hexdigest()[:24]}",
        "issued_at": store.now(),
        "idempotency_key": key,
        "action": None,
        "decision": {"initial_state": initial.kind.removeprefix("call.") if initial else None,
                     "reason": initial.data.get("reason", "") if initial else ""},
        "approval": None,
        "execution": {"state": row.state, "reason": row.reason, "dispatches": row.dispatches,
                      "reconciliation": reconciliation},
        "result": {"digest": row.result_digest},
        "effects": {"declared": None, "before": row.before, "check": row.frame_result},
        "outcome": _outcome(row.state, row.frame_result, row.dispatches),
        "timestamps": timestamps,
        "audit": {"events": [{"seq": e.seq, "kind": e.kind, "hash": e.hash} for e in events],
                  "chain_head": {"seq": seq, "hash": head}},
    }
    if row.action is not None:
        from .action import Action

        action = Action.from_body(row.action)
        body["action"] = action.public()
        body["effects"]["declared"] = action.frame
    if row.approval is not None:
        body["approval"] = {**row.approval, "digest": sha256_text(canonical_json(row.approval))}
    body["digest"] = receipt_digest(body)
    if signer is not None:
        body["signature"] = {"alg": signer.alg, "key_id": signer.key_id, "value": signer.sign(body["digest"])}
    return body


def receipt_digest(receipt: dict[str, Any]) -> str:
    unsigned = {k: v for k, v in receipt.items() if k not in ("digest", "signature")}
    return sha256_text(canonical_json(unsigned))


_NOT_SEMANTIC = frozenset({"issued_at", "receipt_id", "digest", "signature", "audit"})


def verify_receipt(receipt: Any, *, signing_key: bytes | None = None,
                   public_keys: dict[str, bytes] | None = None, store: Store | None = None,
                   expect_action_digest: str | None = None, expect_key: str | None = None) -> list[str]:
    """Problems found; an empty list means the receipt verified at every level requested.

    * Always: the digest matches the content (integrity, not authorship).
    * ``public_keys`` (``{key_id: raw 32-byte Ed25519 public key}``) or ``signing_key``
      (HMAC): a signature is required, made with a key the verifier trusts for that
      ``key_id`` and that algorithm.
    * ``expect_action_digest`` / ``expect_key``: the receipt is about that action, so a
      valid receipt for another action can't be passed off as this one's.
    * ``store``: the audit chain verifies up to the receipt's chain head, the receipt
      lists exactly the store's events for this action, the stored state and approval
      are backed by those events, and every other field equals what the store says
      now. A receipt issued before the action changed again is reported as stale.

    Without any key, a receipt whose signature was stripped or left stale still passes
    the digest check: only a key (or the store) says who issued it.
    """
    try:
        return _verify(receipt, signing_key, public_keys, store, expect_action_digest, expect_key)
    except Exception as exc:  # malformed input must give a verdict, not a crash
        return [f"malformed receipt: {type(exc).__name__}"]


def _verify(receipt: Any, signing_key: bytes | None, public_keys: dict[str, bytes] | None, store: Store | None,
            expect_action_digest: str | None, expect_key: str | None) -> list[str]:
    problems: list[str] = []
    if not isinstance(receipt, dict) or receipt.get("schema") != RECEIPT_SCHEMA:
        return [f"not a {RECEIPT_SCHEMA} receipt"]
    try:
        digest = receipt_digest(receipt)
    except (TypeError, ValueError):
        return ["receipt is not plain JSON"]
    if receipt.get("digest") != digest:
        problems.append("digest does not match the receipt's content")
    if signing_key is not None or public_keys is not None:
        problems += _signature_problems(receipt, signing_key, public_keys)
    action = receipt.get("action") or {}
    if expect_action_digest is not None and action.get("digest") != expect_action_digest:
        problems.append("receipt is for a different action")
    if expect_key is not None and receipt.get("idempotency_key") != expect_key:
        problems.append("receipt is for a different idempotency key")
    if store is None:
        return problems

    audit = receipt["audit"]
    head = audit["chain_head"]
    ok, msg = store.verify_audit(anchor=(head["seq"], head["hash"]))
    if not ok:
        problems.append(f"audit chain: {msg}")
    key = receipt["idempotency_key"]
    row = store.get_call(key)
    if row is None:
        return problems + ["action not found in store"]
    if action and row.action_digest != action.get("digest"):
        problems.append("stored action digest differs from the receipt")
    stored = store.events(call_key=key)
    listed = audit["events"]
    upto = [e for e in stored if e.seq <= head["seq"]]
    if not listed or [(e.seq, e.kind, e.hash) for e in upto] != [(e["seq"], e["kind"], e["hash"]) for e in listed]:
        for ev in listed:
            match = next((e for e in stored if e.seq == ev.get("seq")), None)
            if match is None or match.hash != ev.get("hash") or match.kind != ev.get("kind"):
                problems.append(f"audit event {ev.get('seq')} is missing or differs")
        if not any(p.startswith("audit event") for p in problems):
            problems.append("receipt does not list exactly this action's audit events")
    problems += _row_backed_by_events(row, stored)
    if len(stored) > len(upto):
        problems.append("stale receipt: the action changed after it was issued")
        return problems
    fresh = build_receipt(store, key)
    for field in sorted(set(fresh) | set(receipt)):
        if field not in _NOT_SEMANTIC and fresh.get(field) != receipt.get(field):
            problems.append(f"{field} differs from the store")
    return problems


_NON_STATE_EVENTS = frozenset({"call.requested", "call.replayed", "call.replay_divergence",
                               "call.late_result_discarded"})


def _row_backed_by_events(row: Any, events: list[Any]) -> list[str]:
    """The call row isn't hash-chained; its state and approval must agree with events that are."""
    problems = []
    states = [e for e in events if e.kind.startswith("call.") and e.kind not in _NON_STATE_EVENTS]
    if not states or states[-1].kind != f"call.{row.state}":
        problems.append("stored state is not backed by the audit log")
    if row.approval is not None:
        approved = [e for e in events if e.kind == "call.approved"]
        if not approved or approved[-1].data.get("approval_digest") != approval_digest(row.approval):
            problems.append("stored approval is not backed by the audit log")
    return problems


def _signature_problems(receipt: dict[str, Any], signing_key: bytes | None,
                        public_keys: dict[str, bytes] | None) -> list[str]:
    sig = receipt.get("signature")
    if not isinstance(sig, dict) or not all(isinstance(sig.get(k), str) for k in ("alg", "key_id", "value")):
        return ["receipt is not signed"]
    alg, kid, value, digest = sig["alg"], sig["key_id"], sig["value"], str(receipt.get("digest"))
    if alg == "Ed25519":
        if public_keys is None:
            return ["receipt is signed with Ed25519 but no public keys were given"]
        if kid not in public_keys:
            return [f"unknown signing key id {kid!r}"]
        return [] if verify_ed25519(public_keys[kid], digest, kid, value) else ["signature does not verify"]
    if alg == "HMAC-SHA256":
        if signing_key is None:
            return ["receipt is signed with HMAC-SHA256 but no HMAC key was given"]
        return [] if HmacSigner(signing_key, kid).verify(digest, kid, value) else ["signature does not verify"]
    return [f"unsupported signature algorithm {alg!r}"]
