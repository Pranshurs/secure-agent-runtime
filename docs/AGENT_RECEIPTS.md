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
from secure_agent_runtime.signing import Ed25519Signer      # pip install 'secure-agent-runtime[signing]'

signer = Ed25519Signer(private_key, key_id="ops-2026-10")   # a cryptography Ed25519PrivateKey
receipt = runtime.receipt(key, signer=signer)
problems = verify_receipt(receipt, public_keys={"ops-2026-10": public_key_bytes},
                          expect_key=key, store=runtime.store)   # [] means OK
```

Anyone holding the public key can verify, and nobody without the private key can sign.
`HmacSigner` (or `signing_key=`) is also available; it is symmetric, so only use it
inside one trust domain.

CLI: `secure-agent-runtime verify-receipt receipt.json --public-key ops-2026-10=<hex>`.
Exit 0 means verified, 1 means verification failed, 2 means the receipt couldn't be
checked (unreadable, too large, not a regular file, key missing).

## Schema

JSON Schema (draft 2020-12): `src/secure_agent_runtime/schemas/agent-receipt-v1.schema.json`,
also available from `secure_agent_runtime.receipt_json_schema()` and
`secure-agent-runtime schema`. Tests validate every kind of receipt against it.

| field | content |
|---|---|
| `schema` | `"sar.receipt/v1"` |
| `receipt_id`, `issued_at` | identity and issue time |
| `idempotency_key` | the action's key |
| `action` | the `sar.action/v1` envelope **without argument values or salt**: action id, actor, run, tool `{name, version, schema_digest}`, `args_digest` (salted per action), authority (effect), declared frame, created_at, deadline, `digest`. `null` if the proposal was invalid. |
| `decision` | initial state after policy (`denied`, `awaiting_approval`, ...) and reason |
| `approval` | `{approver, action_digest, approved_at, kind: human/policy, auth: {subject, method, issuer, scope, credential (digest)}, digest}` or null |
| `execution` | final state, reason, number of dispatches, reconciliation events |
| `result` | `{digest}` of the validated tool output (no content) |
| `effects` | `declared` frame, `before` snapshot digests, `check` (frame result: observed changes, required/allowed/undeclared/forbidden, verdict) |
| `outcome` | `verified` · `violated` · `unverifiable` · `completed` (no frame declared) · `failed` · `unknown` · `not_executed` · `pending` |
| `timestamps` | proposed, last updated, first dispatch |
| `audit` | `{events: [{seq, kind, hash}], chain_head: {seq, hash}}` |
| `digest` | `sha256:` over canonical JSON of everything except `digest` and `signature` |
| `signature` | optional `{alg: "Ed25519" or "HMAC-SHA256", key_id, value}` over canonical `{alg, digest, key_id}` |

## What verification proves

| check | proves | doesn't prove |
|---|---|---|
| digest | the receipt wasn't edited after it was built | who built it |
| Ed25519 with `public_keys` | the holder of that private key issued this receipt, with this algorithm and key id | that the key wasn't stolen; key management is the operator's job |
| HMAC with `signing_key` | someone holding the key built it | anything to a party who also holds the key |
| `expect_action_digest` / `expect_key` | the receipt is about the action you are asking about, not a valid receipt for some other action | – |
| `store=` | the audit chain verifies up to `chain_head`; the receipt lists exactly this action's events; the stored state and approval are backed by those events; every other field equals what the store says now | that the store wasn't rebuilt consistently by someone with full write access |

A receipt issued before the action changed again (for example, while it was
`awaiting_approval`) is reported as **stale** when verified against the store.

## Privacy

Argument values and tool output are present only as digests. The argument digest is
salted per action, so a low-entropy value such as an amount can't be recovered by
trying candidates. The **result digest and the observed-state digests are not salted**,
so a low-entropy result (a balance, a yes/no) can be guessed by hashing candidates. Two
more things can reveal content:

* The **declared frame** is operator text and may quote argument values. The refund demo
  puts the amount in `after_contains`.
* **Observed resource ids**, such as file paths or `refunds/rf_0001`, appear in
  `effects.check`.

Treat receipts as internal documents.

## Not yet

* External anchoring of `chain_head` (a transparency log, or a timestamping service).
* Key rotation and revocation lists (key ids are there; managing keys isn't).
* A stable v1 freeze. The schema may change before 1.0, and the version string will
  change with it.
