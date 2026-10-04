# Threat model

**MITIGATED**: a guarantee backed by tests and mutants. **PARTIAL**: helps, with stated
gaps. **OUT OF SCOPE**: SAR does nothing about it. The guarantees hold under the
deployment model described in the last section.

## Actors and what they control

| actor | trusted? | controls |
|---|---|---|
| model, including one steered by injected content | no | tool names, arguments, call ids, its own text |
| tool or external provider | partly: runs operator code | what the tool does once dispatched; what the provider reports |
| approver (a person) | yes, once the host has authenticated them | approve, reject, resolve |
| host application (operator code: registry, policy, authenticator, observers, reconcilers) | yes | everything SAR is configured with |
| someone who can write the SQLite file | no | rows and events in the database |
| host OS, kernel, Python runtime, installed packages | yes | anything |

## Threats

| # | threat | status | how, and where it's tested |
|---|---|---|---|
| 1 | **malicious model** calls a tool it wasn't granted | MITIGATED | default-deny grants; the tool is never invoked (`test_notes_slice.py` §1) |
| 2 | model text or injected content talks policy into allowing a call | MITIGATED | `Policy.decide` has no input that carries model text (`test_injected_instructions_cannot_make_a_call_allowed`) |
| 3 | malformed, oversized or hostile arguments | MITIGATED | strict JSON-mode validation, extra fields forbidden, 64 KiB cap, surrogates, huge ints and deep nesting refused (`test_hostile_inputs.py`, `test_fuzz.py`) |
| 4 | tool description or annotation claims "read-only" | MITIGATED | only the operator-registered `Effect` counts (`test_tool_description_cannot_lower_the_bar`) |
| 5 | **identity confusion**: a bare string or session id accepted as an approver | MITIGATED | approvals need a credential checked by the host's `Authenticator`; the authenticated subject is the approver (`test_auth_and_signing.py`) |
| 6 | self-approval, or an unknown or unprivileged approver | MITIGATED | directory lookup; requester ≠ approver; also re-checked at dispatch |
| 7 | **replay of an approval credential** | MITIGATED | each credential is consumed in the same transaction as the approval (`test_credential_replay_is_refused`) |
| 8 | approval of A used to run B (args, tool version, schema, frame, deadline) | MITIGATED | approval binds the action digest, re-derived from the current tool definition just before dispatch; credentials can be scoped to one digest |
| 9 | stale approval dispatched long after it was given | MITIGATED | human approvals expire after `approval_ttl_s` if not dispatched |
| 10 | **duplicate effect** from duplicate or concurrent requests | MITIGATED | idempotency key is the primary key; the dispatch claim is a compare-and-set fenced on the dispatch count (`test_concurrent_duplicate_dispatch_moves_money_once`, stress harness) |
| 11 | **response loss** after the effect, then a retry | MITIGATED with a reconciler, otherwise PARTIAL | `effect_unknown` is never re-dispatched until a reconciler (or an authenticated human) says the effect did not happen |
| 12 | **stale worker or stale reconciler** decides a later attempt | MITIGATED | outcome and reconciliation transitions are fenced by attempt; reconcile and resolve wait while the previous worker is alive (`test_stale_reconciliation_cannot_reopen_a_later_attempt`) |
| 13 | timed-out tool keeps acting | MITIGATED for `isolation="process"` (the worker is killed); PARTIAL for thread isolation (the thread can't be killed, so SAR waits for it before reconciling) | `test_timed_out_worker_is_killed_and_cannot_act_later` |
| 14 | runtime crash at any execution boundary | MITIGATED | real SIGKILL at claim, spawn, effect, commit and reconciliation boundaries; recovery leaves `effect_unknown`, never a blind re-run (`test_process_crashes.py`) |
| 15 | **orphaned worker** acts after its runtime died | MITIGATED on Linux (`PR_SET_PDEATHSIG`); PARTIAL on macOS (no equivalent, so an orphan can outlive the runtime) | `test_runtime_killed_while_the_effect_is_executing` |
| 16 | **audit tampering**: editing, deleting or reordering events | MITIGATED | SHA-256 hash chain; truncation of the newest events is caught only against an external anchor (`head()`) |
| 17 | tampering with stored rows: state, arguments, approval | MITIGATED for single edits | stored action re-hashed at dispatch; approval and state must match audit events (`test_review_regressions.py` A4) |
| 18 | **receipt forgery** | MITIGATED with Ed25519 for anyone without the private key. PARTIAL with HMAC: any key holder can forge. | signatures cover algorithm, key id and the full receipt digest; verification can require the expected action (`test_auth_and_signing.py`) |
| 19 | **frame-observer blind spot**: a change the observer doesn't see | PARTIAL | frames detect only what the observer snapshots, at two instants. Changes outside the root, or made and reverted between the snapshots, are invisible. Detection, not prevention. |
| 20 | **malicious tool or provider**: lies in its result or reconciler | OUT OF SCOPE | SAR validates the shape, not the truth. A reconciler that lies can cause a second dispatch (shown by the property test's planted "lying reconciler") |
| 21 | **unexpected code execution** inside a tool | OUT OF SCOPE | tools run with SAR's privileges; use a sandbox (container, seccomp, VM) |
| 22 | **denial of service** | PARTIAL | argument size caps, per-turn call cap, hung-thread cap (`max_stuck_workers`), timeouts. Process mode costs one process per dispatch. No rate limiting. |
| 23 | **malicious approver**, or an approver tricked by the UI | OUT OF SCOPE | SAR binds an approval to the stored digest; showing the right thing is the host UI's job |
| 24 | **database compromise**: full write access | OUT OF SCOPE | a consistent rebuild of rows, chain and HMAC receipts is undetectable without an external anchor; Ed25519 receipts held elsewhere still prove what was signed |
| 25 | **compromised host**: kernel, Python, dependencies | OUT OF SCOPE | |
| 26 | **supply-chain compromise** of SAR or its dependencies | PARTIAL | one runtime dependency (pydantic) plus optional extras; CI runs pip-audit, bandit and secret scanning, builds an SBOM, and pins actions by SHA. No signed releases yet. |
| 27 | **privacy**: secrets in logs, receipts or telemetry | MITIGATED for SAR's own outputs | validator messages and exception text aren't echoed; receipts carry salted digests; telemetry has no argument values or keys. The store does hold arguments and results in plaintext (files are 0600). |
| 28 | two runtimes, or two processes, on one database | MITIGATED | exclusive `flock` per file and one Runtime per Store; a second owner gets `StoreLocked` |

## Mapping to the OWASP Top 10 for Agentic Applications (2026)

| OWASP | SAR's position |
|---|---|
| ASI01 Agent Goal Hijack | **PARTIAL.** SAR can't stop a hijacked model from *proposing* harmful actions. It ensures proposals go through default-deny policy and digest-bound human approval, so a hijack can't *authorise* anything. |
| ASI02 Tool Misuse and Exploitation | **MITIGATED** for registered tools: least-privilege grants, strict argument validation, argument constraints, approval gates, idempotency, frame conditions on effects. |
| ASI03 Identity and Privilege Abuse | **PARTIAL.** Approvals need authenticated, one-time, optionally scoped credentials, and grants are per principal. SAR doesn't issue identities or manage the agent's own credentials. |
| ASI04 Agentic Supply Chain Vulnerabilities | **PARTIAL.** Tool versions and schema digests are bound into every action, so a swapped tool definition blocks approved actions. Supply-chain checks run in CI. No signed tool manifests. |
| ASI05 Unexpected Code Execution | **OUT OF SCOPE**, apart from killable process workers. Pair SAR with a sandbox. |
| ASI06 Memory and Context Poisoning | **OUT OF SCOPE.** SAR has no memory component. Poisoned context can only produce proposals (see ASI01). |
| ASI07 Insecure Inter-Agent Communication | **OUT OF SCOPE** (no multi-agent layer). Receipts can be passed between systems and verified with Ed25519. |
| ASI08 Cascading Failures | **PARTIAL.** `effect_unknown` stops blind retries, attempt fencing stops stale outcomes, and hung-worker and per-turn caps bound runaway loops. No circuit breakers across tools. |
| ASI09 Human-Agent Trust Exploitation | **PARTIAL.** Approvals are bound to the exact action digest and can be scoped. What the human is shown is the host's responsibility. |
| ASI10 Rogue Agents | **PARTIAL.** The model has no path to authority. The audit log, receipts and telemetry record every action. Kill switches: revoke grants, `cancel`, stop the runtime. |

The mapping is SAR's own reading of the OWASP categories. It is not an OWASP assessment.

## Deployment model the guarantees assume

* **One owner per database.** A file-backed store is locked to one Store object in one
  process (enforced). "At most one dispatch per approval" is established for that
  model only. SAR makes no distributed or multi-node claim and is **not exactly-once**.
* The host authenticates approvers (through the `Authenticator` it supplies). SAR
  trusts the `AuthContext` it gets back.
* Tools are registered with the right `Effect`. A WRITE tool registered as READ is
  governed as READ.
* Consequential tools use `isolation="process"`, and run on Linux for the
  orphan-worker guarantee.
* The external system offers a way to reconcile (lookup by idempotency key), or a
  human resolves uncertain outcomes.

## Remaining HIGH and MEDIUM risks

* **HIGH (by nature): a reconciler or provider that lies.** SAR's duplicate-effect
  protection is only as good as the reconciler's answer. This is out of scope, but it is
  the single most important integration requirement.
* **MEDIUM: thread-isolated tools that time out.** They can't be stopped. SAR waits for
  them before reconciling, but they hold a thread and may act late. Use process isolation
  for anything consequential.
* **MEDIUM: macOS orphan workers.** If the runtime is killed mid-dispatch, the worker can
  finish its effect after recovery has started. Reconcile again after any crash on macOS.
* **MEDIUM: plaintext store.** Tool arguments and results sit in the SQLite file
  (0600). Encrypting at rest is the host's choice.
