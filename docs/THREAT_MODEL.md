# Threat model

**MITIGATED** means a guarantee with tests and mutants behind it. **PARTIAL** means it
helps but has stated gaps. **OUT OF SCOPE** means SAR does nothing about it.

## Actors

| actor | trusted? | can |
|---|---|---|
| model / prompt-injected content | no | choose tool names, arguments, call ids and its own text |
| operator code (registry, policy, tools, reconcilers, observers, the caller of `approve`) | yes | anything |
| approver | yes, once authenticated by the operator's code | approve, reject, resolve |
| someone with write access to the SQLite file | no | edit rows and events |
| host, kernel, Python runtime, dependencies | yes | anything |

## Threats

| # | threat | status | how |
|---|---|---|---|
| 1 | model calls a tool it wasn't granted | **MITIGATED** | default-deny grants; denied actions never reach the tool |
| 2 | injected text talks the policy into allowing a call | **MITIGATED** | policy has no input that carries model text (`test_injected_instructions_cannot_make_a_call_allowed`) |
| 3 | tool description or MCP annotation claims "read-only" | **MITIGATED** | only the registered `Effect` counts |
| 4 | malformed, oversized or hostile arguments | **MITIGATED** | strict JSON mode, extra fields forbidden, 64 KiB cap, surrogates, huge ints and deep nesting refused |
| 5 | approval of A used to run B (args, tool version, schema, frame, deadline) | **MITIGATED** | approval binds the action digest; re-derived at dispatch |
| 6 | self-approval or an unknown approver | **MITIGATED** | directory lookup; requester ≠ approver |
| 7 | duplicate or concurrent dispatch | **MITIGATED** | CAS claim; one dispatch per approval |
| 8 | retry after a lost response causes a second effect | **MITIGATED** with a reconciler, otherwise **PARTIAL** | `effect_unknown` blocks redispatch; without a reconciler a human must `resolve` |
| 9 | late worker or slow reconciler decides a later attempt | **MITIGATED** | attempt-fenced transitions; reconcile waits while the dispatch is alive |
| 10 | crash between claim and result | **MITIGATED** | `recover()` → `effect_unknown`; never re-run blindly |
| 11 | agent changes things outside its task | **PARTIAL** | frame conditions detect and report it within the observed scope; they don't prevent or undo it |
| 12 | editing a stored action or approval to run something else | **MITIGATED** | digest and approval re-checked at dispatch |
| 13 | editing, deleting or reordering audit events | **MITIGATED** | hash chain |
| 14 | truncating the newest audit events | **PARTIAL** | detected only against an external anchor (`head()`) |
| 15 | forging a receipt | **PARTIAL** | the digest detects edits. HMAC detects forgery by anyone without the key, but key holders can forge. `store=` binds it to the store. |
| 16 | someone with full DB write access rebuilds rows, chain and receipts consistently | **OUT OF SCOPE** | needs external anchoring or asymmetric signing |
| 17 | tool code that is malicious or ignores cancellation | **OUT OF SCOPE** | runs in-process with full privileges; a timed-out thread keeps running |
| 18 | filesystem, network or process escape | **OUT OF SCOPE** | use a sandbox (container, seccomp, VM); SAR complements it |
| 19 | malicious kernel, compromised host, hostile admin | **OUT OF SCOPE** | |
| 20 | external system with no idempotency or lookup | **PARTIAL** | SAR won't re-dispatch an unknown outcome, but only a human can settle it |
| 21 | model learns which tools exist from denial reasons | **PARTIAL** | denial reasons name the tool; offered schemas are filtered by grants |
| 22 | approver tricked by what they are shown | **OUT OF SCOPE** | SAR binds approval to what's stored; the UI must show it faithfully |
| 23 | clock manipulation extending approval windows | **OUT OF SCOPE** | uses the host clock |

## Assumptions the guarantees rest on

* The code that calls `approve`, `reject` and `resolve` has authenticated the person.
  SAR is in-process and trusts the `approver_id` it's given. The agent loop never
  calls these.
* Each tool is registered with the right `Effect`. A WRITE tool registered as READ is
  governed as READ.
* `recover()` runs only when no worker for that store is alive.
* One process per database file. Several processes sharing one SQLite file haven't been
  tested.
