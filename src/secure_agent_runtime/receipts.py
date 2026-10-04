"""Agent Receipts: a machine-verifiable record of one action.

A receipt says what was proposed (the action envelope, without argument values), who
authorised it and how (policy decision, approval and its digest), what happened (state,
number of dispatches, reconciliation), what it returned (result digest), what it changed
compared with what it was allowed to change (frame-condition result), and where all of
that sits in the tamper-evident audit chain (event hashes plus the chain head).

Integrity has two layers:

* ``digest`` is SHA-256 over the canonical JSON of the receipt without ``digest`` and
  ``signature``, so any edit to the receipt is detectable.
* ``signature`` (optional) is HMAC-SHA256 over the digest with an operator key. HMAC is
  symmetric: whoever can verify can also forge. Use it inside one trust domain; a public
  verifier needs an asymmetric signature, which is not implemented yet.

:func:`verify_receipt` checks both, and, given the store, that the audit events the
receipt names are still in a valid chain with the same hashes.

The schema is ``sar.receipt/v1``; its JSON Schema ships as
``secure_agent_runtime/schemas/agent-receipt-v1.schema.json``.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from importlib import resources
from typing import Any

from .action import sha256_text
from .contracts import canonical_json
from .store import Store

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


def build_receipt(store: Store, key: str, *, signing_key: bytes | None = None,
                  key_id: str = "default") -> dict[str, Any]:
    row = store.get_call(key)
    if row is None:
        raise KeyError(f"no action {key!r}")
    events = [e for e in store.events(run_id=row.run_id) if e.call_key == key]
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
    if signing_key is not None:
        body["signature"] = {"alg": "HMAC-SHA256", "key_id": key_id,
                             "value": hmac.new(signing_key, body["digest"].encode(), hashlib.sha256).hexdigest()}
    return body


def receipt_digest(receipt: dict[str, Any]) -> str:
    unsigned = {k: v for k, v in receipt.items() if k not in ("digest", "signature")}
    return sha256_text(canonical_json(unsigned))


def verify_receipt(receipt: dict[str, Any], *, signing_key: bytes | None = None,
                   store: Store | None = None) -> list[str]:
    """Problems found; an empty list means the receipt verified at every level requested."""
    problems: list[str] = []
    if not isinstance(receipt, dict) or receipt.get("schema") != RECEIPT_SCHEMA:
        return [f"not a {RECEIPT_SCHEMA} receipt"]
    try:
        digest = receipt_digest(receipt)
    except (TypeError, ValueError):
        return ["receipt is not plain JSON"]
    if receipt.get("digest") != digest:
        problems.append("digest does not match the receipt's content")
    sig = receipt.get("signature")
    if signing_key is not None:
        if not isinstance(sig, dict) or sig.get("alg") != "HMAC-SHA256":
            problems.append("receipt is not signed with HMAC-SHA256")
        else:
            expected = hmac.new(signing_key, str(receipt.get("digest")).encode(), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(expected, str(sig.get("value"))):
                problems.append("signature does not verify")
    if store is not None:
        audit = receipt.get("audit") or {}
        head = audit.get("chain_head") or {}
        ok, msg = store.verify_audit(anchor=(head.get("seq", -1), head.get("hash", "")))
        if not ok:
            problems.append(f"audit chain: {msg}")
        by_seq = {e.seq: e for e in store.events()}
        for ev in audit.get("events", []):
            stored = by_seq.get(ev.get("seq"))
            if stored is None or stored.hash != ev.get("hash") or stored.kind != ev.get("kind"):
                problems.append(f"audit event {ev.get('seq')} is missing or differs")
        row = store.get_call(str(receipt.get("idempotency_key")))
        action = receipt.get("action") or {}
        if row is None:
            problems.append("action not found in store")
        elif action and row.action_digest != action.get("digest"):
            problems.append("stored action digest differs from the receipt")
    return problems
