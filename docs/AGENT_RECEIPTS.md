# Agent Receipts (`sar.receipt/v1`)

An Agent Receipt is a JSON document about **one action**. It covers:

* what was proposed;
* what authorised it;
* what happened when it ran;
* what it changed compared with what it was allowed to change;
* where it sits in the audit chain.

It is meant to be stored, attached to a ticket or PR, and checked later by a
different system.

```python
receipt = runtime.receipt(key, signing_key=b"...", key_id="ops-2026")
problems = verify_receipt(receipt, signing_key=b"...", store=runtime.store)  # [] means OK
```

The CLI does the same: `secure-agent-runtime verify-receipt receipt.json --key-env SAR_KEY`.

## Schema

JSON Schema (draft 2020-12): `src/secure_agent_runtime/schemas/agent-receipt-v1.schema.json`,
also available from `secure_agent_runtime.receipt_json_schema()` and
`secure-agent-runtime schema`. Tests validate every kind of receipt against it.

| field | content |
|---|---|
| `schema` | `"sar.receipt/v1"` |
| `receipt_id`, `issued_at` | identity and issue time |
| `idempotency_key` | the action's key |
| `action` | the `sar.action/v1` envelope **without argument values**: action id, actor, run, tool `{name, version, schema_digest}`, `args_digest`, authority (effect), declared frame, created_at, deadline, `digest`. `null` if the proposal was invalid. |
| `decision` | initial state after policy (`denied`, `awaiting_approval`, ...) and reason |
| `approval` | `{approver, action_digest, approved_at, kind: human/policy, digest}` or null |
| `execution` | final state, reason, number of dispatches, reconciliation events |
| `result` | `{digest}` of the validated tool output (no content) |
| `effects` | `declared` frame, `before` snapshot digests, `check` (frame result: observed changes, required/allowed/undeclared/forbidden, verdict) |
| `outcome` | `verified` · `violated` · `unverifiable` · `completed` (no frame declared) · `failed` · `unknown` · `not_executed` · `pending` |
| `timestamps` | proposed, last updated, first dispatch |
| `audit` | `{events: [{seq, kind, hash}], chain_head: {seq, hash}}` |
| `digest` | `sha256:` over canonical JSON of everything except `digest` and `signature` |
| `signature` | optional `{alg: "HMAC-SHA256", key_id, value}` over `digest` |

## What verification proves

| check | proves | doesn't prove |
|---|---|---|
| digest | the receipt wasn't edited after it was built | who built it |
| HMAC with key | someone holding the key built it | anything to a party without the key (HMAC is symmetric) |
| `store=` | the audit chain verifies up to `chain_head`, the receipt lists exactly this action's events, and every other field equals what the store says now | that the store itself wasn't rebuilt by someone with full write access |

A receipt issued before the action changed again (for example, while it was
`awaiting_approval`) is reported as **stale** when verified against the store.

## Privacy

Argument values and tool output are present only as digests. Two things can still
reveal content:

* The **declared frame** is operator text and may quote argument values. The refund demo
  puts the amount in `after_contains`.
* **Observed resource ids**, such as file paths or `refunds/rf_0001`, appear in
  `effects.check`.

Treat receipts as internal documents.

## Not yet

* Asymmetric signatures (Ed25519), so third parties can verify without the key.
* External anchoring of `chain_head`.
* A stable v1 freeze. The schema may change before 1.0, and the version string will
  change with it.
