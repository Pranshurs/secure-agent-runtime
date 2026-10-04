# Independent reviews and what they found

SAR was reviewed adversarially several times by AI subagents (Claude Sonnet). Each
subagent was told to violate the documented guarantees through the public API, had no
access to the implementer's notes, and worked on a frozen copy of the code.

The review sessions themselves can't be rerun as a command. What can be rerun is the
regression test each accepted finding produced; every finding below names one. The
counts in the README come from `pytest` and `scripts/mutation_test.py`.

## Round 1: first slice (thread runtime)

| finding | severity | fix | regression test |
|---|---|---|---|
| Hostile arguments (lone surrogate, int > 4300 digits, nesting depth 5000) raised out of `propose()` | MED | `plain_json()` refuses anything that isn't plain, bounded JSON | `test_hostile_inputs.py::test_hostile_arguments_become_invalid_calls` |
| `SystemExit` from a tool, or unserialisable output, left an action stuck in `executing` | MED | worker catches `BaseException`; output validation never raises | `test_tool_raising_systemexit_is_failed_not_stuck`, `test_unserialisable_tool_output_is_rejected_not_stuck` |
| A non-idempotent validator let the tool see different arguments from the approved ones | LOW-MED | input must round-trip; the tool gets the exact validated model | `test_unstable_input_validator_is_refused_before_hashing` |
| Late-result recording raised after the store closed | LOW | contained and logged | `test_late_result_after_store_close_does_not_raise_in_worker` |
| Agent: expired approvals, resume after completion, reused call ids | LOW | fixed in `Agent` | `test_hostile_inputs.py` agent section |

## Round 2: transactional core

| finding | severity | fix | regression test |
|---|---|---|---|
| Stale reconcile result reopened a later attempt (ABA) | HIGH | transitions fenced on the dispatch count | `test_stale_reconciliation_cannot_reopen_a_later_attempt` |
| A late worker from attempt 1 completed attempt 2 | HIGH | attempt fencing; reconcile and resolve wait for a live worker | `test_late_worker_*` |
| `verify_receipt(store=)` didn't bind the receipt body to the store | MED-HIGH | receipt is rebuilt from the store and compared field by field | `test_forged_receipt_with_recomputed_digest_fails_against_the_store` |
| A required glob overrode a forbidden one | MED | forbidden is evaluated first and always fails | `test_forbidden_wins_even_over_a_requirement` |
| A frame was declared but `resolve()` never checked it | MED-LOW | `resolve` runs the frame check | `test_human_resolution_still_checks_the_frame` |
| Permission changes and empty directories invisible; ambiguous mapping ids | LOW | observed and refused | `test_permission_changes_and_empty_directories_are_observed` |
| Non-numeric deadline; deadline missing from replay identity | LOW | validated; part of the request hash | `test_malformed_deadline_is_refused_at_proposal` |

## Round 3: pre-release gate, two cold reviews run in parallel without sharing findings

### Reviewer A (correctness and integrity)

| id | finding | severity | fix | regression test |
|---|---|---|---|---|
| A1 | `**` compiled without `re.DOTALL`: a path with a newline escaped a forbidden glob but matched an allowed `*` | HIGH | DOTALL | `test_review_regressions.py::test_a1_*` |
| A2 | A result the store couldn't encode (surrogate in a frame report) wedged the action in `executing` | MED | non-UTF-8 names are refused by the observer; a failed write falls back to `effect_unknown` | `test_a2_*` |
| A3 | Dispatch claim not fenced on the dispatch count (a stale executor's claim succeeded) | MED | claim compare-and-set includes `dispatches` | `test_a3_*` |
| A4 | Call row not bound to the audit log: a forged approval in the row dispatched | MED | approval must be backed by an audit event; receipt verification checks state against events | `test_a4_*` |
| A5 | HMAC signature didn't cover `alg` or `key_id` | LOW | signatures cover `{alg, key_id, digest}` | `test_a5_*` |
| A6 | A late, discarded result consumed the pre-dispatch snapshot | LOW | snapshot released only on a recorded outcome | `test_a6_*` |
| – | approval window not re-checked inside the CAS; idempotency key colliding with a default key | SPEC | both fixed | `test_approval_cas_rechecks_the_window`, `test_custom_idempotency_key_cannot_collide_with_a_default_key` |

### Reviewer B (API, operations, supply chain)

| id | finding | severity | fix | regression test |
|---|---|---|---|---|
| B1 | Two Runtimes on one database: the second's `recover()` plus reconcile double-dispatched a live action | HIGH | exclusive `flock` per file; one Runtime per Store | `test_b1_*` (incl. a second process) |
| B2 | A human approval never expired once given | MED | approvals must be dispatched within `approval_ttl_s` | `test_b2_*` |
| B3 | Forgetting `recover()` after a crash left actions stuck silently | MED | recovery at start-up (single owner makes it safe); clearer errors | `test_b3_*` |
| B4 | Validator messages echoed (a card number); DB files 0644; unsalted digests enumerable | MED | opaque validator messages; 0600 files; per-action salt | `test_b4a_*`, `test_b4c_*`, `test_args_digest_is_salted_*` |
| B5 | CLI `verify-receipt` tracebacks, exit 1 for I/O errors, no size cap, FIFO hang | MED | exit 2 for "could not check"; 4 MiB cap; regular files only | `test_b5_*` |
| B6 | `Store("")` silently created a temp DB; `:memory:` silent for effectful tools | LOW | refused; warning | `test_b6_*` |
| B7 | `_live` never pruned; hung threads unbounded | LOW | pruning; `max_stuck_workers` throttle | `test_b7_*` |
| B8 | Raw sqlite3 exceptions; corrupt or unknown-version DBs | LOW | `StoreError`; schema version check | `test_b8_*` |
| B9 | Empty HMAC key accepted | LOW | keys of at least 16 bytes | `test_b9_*` |
| B10 | Actions pinned by tag; no sdist, twine or 3.11/3.13 in CI; sdist shipped repo tooling | LOW | SHA pins; package job; matrix; sdist include list | CI |
| B11 | README nits; "exactly one audit event" wrong for proposals | LOW | docs | – |

Reviewer B also confirmed that a build plus `twine check` passes, `pip-audit` finds no
known vulnerabilities, `bandit` raises no real issues, and the README counts reproduce.

## Found by our own harnesses during the gate

| id | finding | severity | how found | fix | regression test |
|---|---|---|---|---|---|
| S1 | In-memory worker map iterated and mutated from many threads without a lock: `execute()` raised `RuntimeError` (11 times in 24 rounds); the store stayed consistent | MED | `scripts/stress.py` | lock; release by identity; pruning; the harness now fails on unexpected exceptions | `test_s1_worker_map_survives_concurrent_release_during_iteration` (deterministic, fails on the pre-fix code) |
| P0 | The first version of the property test never reached a dispatch, so it couldn't fail | test gap | planted a reconciler that always says "not applied"; the test still passed | rules re-weighted; the planted bug is now found with a 3-step counterexample | `test_state_machine_properties.py` |
| M1 | Mutant C15 (catch only `TypeError`/`ValueError` for hostile JSON) survived on Python 3.12, whose JSON encoder accepts 5000 levels of nesting | test gap | CI mutation job | test nesting raised to 100k levels | `test_hostile_inputs.py` |

## Round 4: final cold review against the Level-A contract

One reviewer (an AI subagent, Sonnet), told nothing about earlier findings, attacked each
stage of *proposal → canonicalization → authority → exact-argument approval → durable
execution → consequential effect → safe retry / reconciliation → frame verification →
Agent Receipt* through the public API and reproduced each finding with a script. Every
reproduction was re-run before fixing. Each fix has a test that fails on the pre-fix code
and passes after.

| id | finding | severity | fix | regression test |
|---|---|---|---|---|
| F1 | A refused or raced approval burned its one-time credential (consumed before the compare-and-set, committed on failure) | MED | consume only after the state change succeeds | `test_an_approval_that_loses_a_race_does_not_burn_the_credential` |
| F2 | A symlink to an owned database took a second lock: two runtimes, a double dispatch | MED | lock the resolved path | `test_a_symlink_to_an_owned_database_cannot_open_a_second_store` |
| F3 | "At most one dispatch per approval" overstated: each reconciler "not applied" re-arms the same approval | MED (docs) | wording: one dispatch per approved attempt, a new attempt only after "not applied", within the approval's TTL | – |
| F4 | An exception between claim and result (worker can't start; malformed custom snapshot) left the action stuck in `executing` | MED | `failed` when the tool provably didn't run; `unverifiable` frame; malformed pre-dispatch snapshot blocks | `test_a_worker_*_that_cannot_start_*`, `test_a_malformed_snapshot_*` |
| F5 | A missing or unreadable observer root looked empty, so deleting a forbidden directory read as "verified" | MED | snapshot fails instead | `test_a_mistyped_observer_root_*`, `test_an_observed_root_that_disappears_*`, `test_an_unreadable_directory_*` |
| F6 | One edit to the row's result or frame verdict flipped a receipt, and `verify_receipt(store=)` accepted it | MED | each transition records digests of the fields it set; the store check requires them | `test_one_edit_to_any_reported_row_field_fails_against_the_store` (6 fields) |
| F7 | The dispatch-time policy re-check used an unbound `principal` column | LOW-MED | row principal, tool, run and key must equal the signed action's | `test_editing_the_rows_principal_cannot_dodge_a_revoked_grant` |
| F8 | Process mode killed only the worker: a child process or leftover thread could act after the attempt was decided | LOW-MED | worker leads a process group, killed on timeout, death and after the reply | `test_nothing_the_worker_left_running_acts_after_the_attempt_is_decided` |
| F9 | Any later event (a replay, a refused approval) made receipts "stale" | LOW | only a later state change does | `test_events_that_change_nothing_do_not_make_a_receipt_stale` |
| F10 | Signatures malleable (hex case, whitespace, extra fields); a self-consistent stub passed digest-only | LOW | canonical form only; required fields | `test_a_signature_verifies_only_in_its_one_canonical_form`, `test_verify_receipt_cli_rejects_a_self_consistent_stub` |
| F11 | CLI exit codes: unusable key reported as a failed receipt; a traceback on missing fields | LOW | exit 2 for unusable keys; no traceback | `test_verify_receipt_cli_refuses_unusable_keys_as_could_not_check` |
| F12 | Caller-supplied `action_digest` and reasons went unvalidated into the audit log (non-SAR exceptions; 5 MB events) | LOW | digest form checked first; reasons bounded UTF-8 | `test_a_hostile_action_digest_*`, `test_caller_supplied_reasons_are_bounded_text` |
| F13 | After "not applied", an approval older than its TTL cancels the retry | LOW (docs) | documented (TRANSACTION_SEMANTICS invariant 2) | – |
| F14 | "Salted digests" claim covered only the argument digest | LOW (docs) | result and observed-state digests documented as unsalted | – |
| F15 | A declared frame skipped at resolve/reconcile (tool redeployed without its observer) read as "completed" | LOW | `unverifiable` | `test_a_declared_frame_that_can_no_longer_be_observed_*` |
| F16 | A closed Runtime kept working; `approval_ttl_s=nan` meant approvals never expired; a huge deadline raised `OverflowError` | LOW | closed runtimes refuse; validation | `test_a_closed_runtime_refuses_every_operation`, `test_approval_ttl_*`, `test_a_deadline_too_large_*` |
| F17 | Notes: the schema digest doesn't cover tool code or validators; the requester label is trusted; frame globs from arguments are injectable; host API calls are unauthenticated | INFO | documented (THREAT_MODEL #6, #8, deployment model) | – |

Not changed, deliberately: a `Store` dropped without `close()` keeps its lock fd until the
process exits (F16b). Adding a finalizer would hide an ownership bug; the rule is "close
what you open", enforced in the tests by a fixture that fails any test leaving a store
open.

The reviewer also reported as sound, after checking: concurrent dispatch (60 trials, 6
executors plus cancellers, at most one invocation), idempotency handling, canonicalization,
authority, approval refusals, attempt fencing, the glob engine, file modes, receipts
against the JSON Schema, and Ed25519/HMAC algorithm and key-id binding.
