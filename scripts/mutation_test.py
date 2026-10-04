#!/usr/bin/env python3
"""Break every safety rule on purpose and check that the test suite notices.

Each mutant below is a hand-written, single-site change that disables or weakens one
rule. For each one the script copies ``src/`` and ``tests/`` to a temporary directory,
applies the change, and runs pytest against the copy. A mutant is

* **killed** if pytest fails (or times out),
* **survived** if pytest passes: a test gap, which is a bug,
* **equivalent** if it is listed as such below with a reason; it is still run, and
  reported as a contradiction if it turns out to be killed.

The run aborts unless the unmutated suite passes first, and unless every mutant's
original text occurs exactly once (so a stale mutant cannot silently become a no-op).

This is a curated list, not an exhaustive generator: it covers the rules the README
claims, not every line. Usage: ``python scripts/mutation_test.py [-k substring] [-j N]``.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PKG = "src/secure_agent_runtime"


@dataclass(frozen=True)
class Mutant:
    id: str
    rule: str
    file: str
    old: str
    new: str
    equivalent: str = ""  # reason, if the mutant cannot change observable behaviour


C, P, S, R, A, X, E, V = (f"{PKG}/{m}.py" for m in (
    "contracts", "policy", "store", "runtime", "agent", "action", "effects", "receipts"))
ISO, AU, SIG, CLI, TEL = (f"{PKG}/{m}.py" for m in ("isolation", "auth", "signing", "__main__", "telemetry"))

MUTANTS: list[Mutant] = [
    # -- contracts: input and output validation ---------------------------------------- #
    Mutant("C1", "tool models must forbid extra fields", C,
           "if not _forbids_extra(model):", "if False:"),
    Mutant("C2", "input validated strictly (no type coercion)", C,
           "model = spec.input_model.model_validate_json(text, strict=True)",
           "model = spec.input_model.model_validate_json(text, strict=False)"),
    Mutant("C3", "output validated strictly", C,
           "return spec.output_model.model_validate_json(text, strict=True)",
           "return spec.output_model.model_validate_json(text, strict=False)"),
    Mutant("C5", "canonical JSON rejects NaN/Infinity", C,
           "allow_nan=False)", "allow_nan=True)"),
    Mutant("C6", "canonical JSON never stringifies unknown objects", C,
           "allow_nan=False)", "allow_nan=False, default=str)"),
    Mutant("C7", "canonical JSON is key-order independent", C,
           "sort_keys=True", "sort_keys=False"),
    Mutant("C9", "timeout must be positive", C,
           "and self.timeout_s > 0)", "and self.timeout_s >= 0)"),
    Mutant("C10", "validation errors never echo the offending input", C,
           "for e in exc.errors(include_input=False))[:500]",
           "for e in exc.errors(include_input=True))[:500]",
           equivalent="_short() formats only 'loc' and 'msg'; include_input only adds an "
                      "'input' key that is never read. C11 covers actually echoing input."),
    Mutant("C11", "validation errors never echo the offending input", C,
           "{'rejected by validator' if e['type'] in _OPAQUE else e['msg']}\"\n                     for e in exc.errors(include_input=False))",
           "{e['msg']} {e['input']}\"\n                     for e in exc.errors(include_input=True))"),
    Mutant("C20", "operator validator messages are never echoed (they may quote secrets)", C,
           "'rejected by validator' if e['type'] in _OPAQUE else e['msg']", "e['msg']"),
    Mutant("C12", "arguments must be a JSON object", C,
           "if not isinstance(raw, dict):\n        return None, \"arguments must be a JSON object\"",
           "if raw is None:\n        return None, \"arguments must be a JSON object\""),
    Mutant("C13", "validation errors never echo unknown field names", C,
           'str(p) if _SAFE_LOC.match(str(p)) else "<field>"', "str(p)"),
    Mutant("C14", "input must round-trip (approved args == args the tool receives)", C,
           "if not stable:\n        return None", "if False:\n        return None"),
    Mutant("C15", "hostile JSON (surrogates, huge ints, deep nesting) is refused, not raised", C,
           "        size = len(text.encode(\"utf-8\"))\n    except Exception:\n        return None",
           "        size = len(text.encode(\"utf-8\"))\n    except (TypeError, ValueError):\n        return None"),
    Mutant("C16", "arguments and outputs are size-bounded", C,
           "return text if size <= MAX_JSON_BYTES else None", "return text"),
    Mutant("C17", "a READ tool cannot carry a reconciler", C,
           "if self.reconciler is not None and self.effect is Effect.READ:", "if False:"),
    Mutant("C18", "frame and observer are declared together", C,
           "if (self.frame is None) != (self.observer is None):", "if False:"),
    Mutant("C19", "schema digest covers the output contract", C,
           '"input": self.input_model.model_json_schema(),\n                                                   "output": self.output_model.model_json_schema()',
           '"input": self.input_model.model_json_schema()'),

    # -- action envelope ------------------------------------------------------------------- #
    Mutant("X1", "args digest covers argument values", X,
           "return sha256_text(salt + canonical_json(args))", "return sha256_text(salt + canonical_json(sorted(args)))"),
    Mutant("X10", "args digests are salted per action", R,
           "salt=new_salt() if salt is None else salt)", 'salt="" if salt is None else salt)'),
    Mutant("X2", "action digest covers the tool version", X,
           '"tool": {"name": self.tool, "version": self.tool_version, "schema_digest": self.schema_digest}',
           '"tool": {"name": self.tool, "schema_digest": self.schema_digest}'),
    Mutant("X3", "action digest covers the tool schema", X,
           '"tool": {"name": self.tool, "version": self.tool_version, "schema_digest": self.schema_digest}',
           '"tool": {"name": self.tool, "version": self.tool_version}'),
    Mutant("X4", "action digest covers the declared frame", X,
           '"frame": self.frame, "created_at"', '"created_at"'),
    Mutant("X5", "action digest covers the deadline", X,
           '"created_at": self.created_at, "deadline": self.deadline,', '"created_at": self.created_at,'),
    Mutant("X6", "action digest covers the actor", X,
           '"actor": self.actor, "context"', '"context"'),
    Mutant("X7", "action digest covers the idempotency key", X,
           '"action_id": self.action_id, "idempotency_key": self.idempotency_key,', '"action_id": self.action_id,'),
    Mutant("X8", "action digest covers the authority", X,
           '"authority": self.authority,', ""),
    Mutant("X9", "receipts omit argument values", X,
           '        del b["args"], b["salt"]\n', '        del b["salt"]\n'),
    Mutant("P1", "default deny: ungranted tool denied", P,
           "if spec.name not in principal.grants:", "if False:"),
    Mutant("P2", "a constraint returning any reason (even '') denies", P,
           "if problem is not None:", "if problem:"),
    Mutant("P3", "a raising constraint fails closed", P,
           'return Decision(Verdict.DENY, f"constraint raised', 'return Decision(Verdict.ALLOW, f"constraint raised'),
    Mutant("P4", "constraints see a copy of the args", P,
           "problem = check(dict(args))", "problem = check(args)"),
    Mutant("P5", "effect-based approval", P,
           "if spec.effect in self.require_approval_for_effects or", "if False or"),
    Mutant("P6", "name-based approval", P,
           "or spec.name in self.require_approval_for_tools:", "or False:"),
    Mutant("P7", "WRITE needs approval by default", P,
           "frozenset({Effect.WRITE, Effect.EXTERNAL})", "frozenset({Effect.EXTERNAL})"),
    Mutant("P8", "EXTERNAL needs approval by default", P,
           "frozenset({Effect.WRITE, Effect.EXTERNAL})", "frozenset({Effect.WRITE})"),
    Mutant("P9", "unknown approver refused", P,
           'if approver is None:\n        return "unknown approver"',
           'if approver is None:\n        return None'),
    Mutant("P10", "only approvers can approve", P,
           "if not approver.can_approve:", "if False:"),
    Mutant("P11", "self-approval refused", P,
           "if approver.id == requester_id:", "if False:"),

    # -- store ----------------------------------------------------------------------------- #
    Mutant("S1", "compare-and-set: state predicate", S,
           'WHERE key=? AND state=?{fence}",\n                             (*values, key, from_state, *fence_args))',
           'WHERE key=? AND ?=?{fence}",\n                             (*values, key, from_state, *fence_args))'),
    Mutant("S18", "compare-and-set: attempt fence", S,
           'fence, fence_args = ("", ()) if attempt is None else (" AND dispatches=?", (attempt,))',
           'fence, fence_args = ("", ())'),
    Mutant("S2", "compare-and-set: losers are told they lost", S,
           "if cur.rowcount != 1:\n                return False", "if cur.rowcount < 0:\n                return False"),
    Mutant("S3", "closed state machine", S,
           "if to_state not in TRANSITIONS.get(from_state, frozenset()):", "if False:"),
    Mutant("S4", "calls start only in an initial state", S,
           "if state not in INITIAL_STATES:", "if False:"),
    Mutant("S5", "only whitelisted columns are updatable", S,
           "if unknown:\n            raise", "if False:\n            raise"),
    Mutant("S6", "duplicate key is reported, not raised", S,
           "except sqlite3.IntegrityError:\n                return False",
           "except sqlite3.IntegrityError:\n                raise"),
    Mutant("S7", "every transition is audited in the same transaction", S,
           'self._append(db, run_id, key, f"call.{to_state}", event or {})', "pass"),
    Mutant("S8", "hash chain links to the previous hash", S,
           "hashlib.sha256((prev_hash + body).encode())", "hashlib.sha256((body).encode())"),
    Mutant("S9", "event hash covers the timestamp", S,
           "canonical_json([seq, ts, run_id, call_key, kind, data_json])",
           "canonical_json([seq, run_id, call_key, kind, data_json])"),
    Mutant("S10", "event hash covers the kind", S,
           "canonical_json([seq, ts, run_id, call_key, kind, data_json])",
           "canonical_json([seq, ts, run_id, call_key, data_json])"),
    Mutant("S11", "event hash covers the run and call", S,
           "canonical_json([seq, ts, run_id, call_key, kind, data_json])",
           "canonical_json([seq, ts, kind, data_json])"),
    Mutant("S12", "verify checks the sequence", S,
           'if r["seq"] != expected_seq:', "if False:",
           equivalent="the hash covers seq and each event links to its predecessor, so a "
                      "gap or renumbering already fails the prev_hash or content check; "
                      "this check only gives a clearer message."),
    Mutant("S13", "verify checks prev_hash", S,
           'if r["prev_hash"] != prev:', "if False:"),
    Mutant("S14", "verify checks content hash", S,
           'if h != r["hash"]:', "if False:"),
    Mutant("S15", "verify checks the external anchor", S,
           "if hashes.get(seq) != h:", "if False:"),
    Mutant("S16", "only reconciliation leaves effect_unknown", S,
           '"effect_unknown": frozenset({"succeeded", "approved", "failed"}),',
           '"effect_unknown": frozenset({"succeeded", "approved", "failed", "executing"}),'),
    Mutant("S17", "a failed COMMIT is rolled back", S,
           "if self._db.in_transaction:  # also covers", "if False:  # also covers"),

    # -- runtime: proposals and replay ------------------------------------------------------ #
    Mutant("R1", "policy DENY becomes a denied action", R,
           'if decision.verdict is Verdict.DENY:\n            return "denied"',
           'if decision.verdict is Verdict.DENY:\n            return "approved"'),
    Mutant("R2", "REQUIRE_APPROVAL becomes an action awaiting approval", R,
           'return "awaiting_approval", decision.reason', 'return "approved", decision.reason'),
    Mutant("R3", "replay of a key is answered from the store", R,
           "if not inserted:\n            return self._replay(row, principal_id, rh)", "if False:\n            pass"),
    Mutant("R4", "replay with different content is divergence", R,
           "if row.request_hash != rh or row.principal != principal_id:",
           "if row.principal != principal_id:"),
    Mutant("R5", "replay by another principal is divergence", R,
           "if row.request_hash != rh or row.principal != principal_id:",
           "if row.request_hash != rh:"),
    Mutant("R6", "call keys cannot collide across runs", R,
           "return canonical_json([run_id, call_id])", 'return f"{run_id}:{call_id}"'),
    Mutant("R7", "the policy approver id is reserved", R,
           "if p.id in self._principals or p.id == POLICY_APPROVER:", "if p.id in self._principals:"),

    # -- runtime: approvals ------------------------------------------------------------------- #
    Mutant("R8", "approval is bound to the action digest", R,
           "if refusal is None and action_digest != row.action_digest:", "if False:"),
    Mutant("R9", "only waiting actions can be approved (and refusals are audited)", R,
           'if row.state != "awaiting_approval":\n            return f"action is {row.state}',
           'if False:\n            return f"action is {row.state}'),
    Mutant("R10", "approval window enforced", R,
           "if row.expires_at is not None and self.store.now() >= row.expires_at:\n            self.store",
           "if False:\n            self.store"),
    Mutant("R11", "approval window boundary is exclusive", R,
           "if row.expires_at is not None and self.store.now() >= row.expires_at:\n            self.store",
           "if row.expires_at is not None and self.store.now() > row.expires_at:\n            self.store"),

    # -- runtime: last-moment checks ------------------------------------------------------------ #
    Mutant("R13", "only approved actions take the execution path", R,
           'if row.state != "approved":\n            return Outcome.of(row)\n        problem',
           'if row.state in ("succeeded",):\n            return Outcome.of(row)\n        problem',
           equivalent="for any non-approved row the pre-execution check fails (no matching "
                      "approval record) and its cancel CAS fails; the approved->executing CAS "
                      "is the real guard (S1, S2, R15). This early return is a fast path."),
    Mutant("R14", "pre-execution check blocks execution", R,
           "if problem is not None:\n            self.store.transition(key, \"approved\", \"cancelled\"",
           "if False:\n            self.store.transition(key, \"approved\", \"cancelled\""),
    Mutant("R15", "execution claim is compare-and-set", R,
           'event={"action_digest": row.action_digest, "attempt": attempt}):\n'
           "            return Outcome.of(self._get(key))",
           'event={"action_digest": row.action_digest, "attempt": attempt}):\n'
           "            pass"),
    Mutant("R16", "stored action must match its digest", R,
           "if stored.digest != row.action_digest:", "if False:"),
    Mutant("R17", "approval record must name the stored action", R,
           'if not row.approval or row.approval.get("action_digest") != row.action_digest:',
           "if not row.approval:"),
    Mutant("R18", "stored args must round-trip through the current schema", R,
           'if model is None or model.model_dump(mode="json") != stored.args:', "if model is None:"),
    Mutant("R19", "policy re-checked at execution (revoked grant)", R,
           'if decision.verdict is Verdict.DENY:\n            return (f"policy now denies',
           'if False:\n            return (f"policy now denies'),
    Mutant("R20", "approver re-checked at execution", R,
           "if refusal is not None:\n                return (f\"approval no longer valid",
           "if False:\n                return (f\"approval no longer valid"),
    Mutant("R21", "execution re-check consults the policy, not the stored state", R,
           "if decision.verdict is Verdict.REQUIRE_APPROVAL:\n            # POLICY_APPROVER",
           "if False:\n            # POLICY_APPROVER"),
    Mutant("R30", "tool version, schema or frame changed since approval blocks dispatch", R,
           "if current.digest != row.action_digest:", "if False:"),
    Mutant("R31", "action deadline enforced", R,
           "if stored.deadline is not None and self.store.now() >= stored.deadline:", "if False:"),
    Mutant("R36", "pre-dispatch observer failure blocks dispatch", R,
           "                before = spec.observer.snapshot()\n            except Exception as exc:",
           "                before = spec.observer.snapshot()\n            except ZeroDivisionError as exc:"),

    # -- runtime: outcomes ------------------------------------------------------------------------ #
    Mutant("R22", "timeout ends the dispatch", R,
           "if worker.is_alive():\n            ctx.cancel.set()", "if False:\n            ctx.cancel.set()"),
    Mutant("R23", "timed-out tool is signalled to cancel", R,
           "if worker.is_alive():\n            ctx.cancel.set()", "if worker.is_alive():\n            pass"),
    Mutant("R24", "a late result is discarded with an audit event", R,
           'self.store.record(row.run_id, "call.late_result_discarded"',
           'None and self.store.record(row.run_id, "call.late_result_discarded"'),
    Mutant("R25", "invalid output is never recorded as success", R,
           "if out is None:\n                finish(\"effect_unknown\" if effectful else \"output_rejected\"",
           "if False:\n                finish(\"effect_unknown\" if effectful else \"output_rejected\""),
    Mutant("R26", "tool exception messages are not recorded or shown", R,
           'else "failed", reason=f"tool raised {type(exc).__name__}")',
           'else "failed", reason=f"tool raised {exc}")'),
    Mutant("R27", "rejected output details are not shown to the model", R,
           'if self.state == "output_rejected":\n            return', 'if False:\n            return'),
    Mutant("R28", "only succeeded actions carry a result to the model", R,
           'if self.state == "succeeded":\n            out: dict', 'if True:\n            out: dict'),
    Mutant("R29", "crash recovery: effectful actions become effect_unknown", R,
           'target = "effect_unknown" if _effectful(self.registry.get(row.tool)) else "failed"',
           'target = "failed"'),
    Mutant("R32", "timeout of an effectful tool is effect_unknown, not failed", R,
           'if self.store.transition(key, "executing", "effect_unknown" if effectful else "failed",\n                                     attempt=attempt, reason=f"no result within',
           'if self.store.transition(key, "executing", "failed",\n                                     attempt=attempt, reason=f"no result within'),
    Mutant("R33", "unexpected exception from an effectful tool is effect_unknown", R,
           'finish("effect_unknown" if effectful else "failed", reason=f"tool raised',
           'finish("failed", reason=f"tool raised'),
    Mutant("R34", "unreadable result from an effectful tool is effect_unknown", R,
           'finish("effect_unknown" if effectful else "output_rejected"', 'finish("output_rejected"'),
    Mutant("R35", "EffectNotApplied is a definite failure", R,
           'except EffectNotApplied:\n                finish("failed"',
           'except EffectNotApplied:\n                finish("effect_unknown"'),
    Mutant("R38", "Applied reconciles to succeeded", R,
           "if isinstance(finding, Applied):", "if False:"),
    Mutant("R39", "only NotApplied permits another dispatch", R,
           "elif isinstance(finding, NotApplied):", "elif not isinstance(finding, Applied):"),
    Mutant("R40", "a reconciled result is validated", R,
           'if out is None:\n                self.store.record(row.run_id, "reconcile.result_invalid"',
           'if False:\n                self.store.record(row.run_id, "reconcile.result_invalid"'),
    Mutant("R41", "a human resolution needs an independent approver", R,
           "refusal = ctx if isinstance(ctx, str) else approval_refusal(self._principals.get(ctx.subject), row.principal)",
           "refusal = ctx if isinstance(ctx, str) else None"),
    Mutant("R42", "a reconciler is bounded by the tool timeout", R,
           "    t.join(timeout_s)\n    return box[0]", "    t.join()\n    return box[0]"),
    Mutant("R43", "a reconciler error counts as Unknown", R,
           'box.append(Unknown(f"reconciler raised {type(exc).__name__}"))',
           'box.append(NotApplied())'),

    Mutant("R45", "reconcile waits while the last dispatch is still running", R,
           "if self._worker_alive(key):\n            # The timed-out", "if False:\n            # The timed-out"),
    Mutant("R46", "resolve waits while the last dispatch is still running", R,
           'if self._worker_alive(key):\n            raise ApprovalRefused("the last dispatch',
           'if False:\n            raise ApprovalRefused("the last dispatch'),
    Mutant("R47", "reconcile is fenced to the attempt it examined", R,
           'if not self.store.transition(key, "effect_unknown", "approved", attempt=attempt,',
           'if not self.store.transition(key, "effect_unknown", "approved",'),
    Mutant("R48", "a late worker is fenced to its own attempt", R,
           'ok = self.store.transition(key, "executing", state, attempt=attempt, **fields)',
           'ok = self.store.transition(key, "executing", state, **fields)',
           equivalent="masked by R45/R46: an action can only be re-approved by reconcile or resolve, and "
                      "both refuse while the previous dispatch's worker is alive, so a late worker never "
                      "meets a later attempt in this process. Kept as defence in depth."),
    Mutant("R49", "deadlines are validated at proposal", R,
           "        if deadline is not None and (isinstance(deadline, bool)", "        if False and (isinstance(deadline, bool)"),
    Mutant("R50", "the deadline is part of replay identity", R,
           'rh = request_hash(tool, arguments, {"deadline": deadline})', "rh = request_hash(tool, arguments)"),
    Mutant("R51", "a human resolution runs the frame check", R,
           "                frame = self._frame_result(spec, Action.from_body(row.action), key, attempt)",
           "                frame = None"),
    # -- effects / frame conditions -------------------------------------------------------------------- #
    Mutant("E1", "undeclared changes fail the frame", E,
           "bad = forbidden or undeclared or any(", "bad = forbidden or any("),
    Mutant("E2", "forbidden changes fail the frame", E,
           "bad = forbidden or undeclared or any(", "bad = undeclared or any("),
    Mutant("E3", "an unmet requirement fails the frame", E,
           ' or any(not r["met"] and not _only_unavailable(r) for r in req_results)', ""),
    Mutant("E4", "required count is exact", E,
           "if len(matches) != r.count:", "if len(matches) < r.count:"),
    Mutant("E5", "required content is checked", E,
           "elif not ok:\n                    problems.append", "elif False:\n                    problems.append"),
    Mutant("E6", "missing evidence is unverifiable, never verified", E,
           'elif unverifiable:\n        verdict = "unverifiable"', 'elif False:\n        verdict = "unverifiable"'),
    Mutant("E7", "content unavailable is not treated as a match", E,
           "if entry is None or entry.content is None:\n        return None",
           "if entry is None or entry.content is None:\n        return True"),
    Mutant("E8", "change kind must match the requirement", E,
           "if c.path not in claimed and pat.match(c.path) and c.change == r.change]",
           "if c.path not in claimed and pat.match(c.path)]"),
    Mutant("E16", "one change satisfies at most one requirement", E,
           "if c.path not in claimed and pat.match(c.path) and c.change == r.change]",
           "if pat.match(c.path) and c.change == r.change]"),
    Mutant("E9", "'*' does not cross '/'", E,
           'out.append("[^/]*")', 'out.append(".*")'),
    Mutant("E10", "globs are anchored at the end", E,
           r'return re.compile("".join(out) + r"\Z", re.DOTALL)', 'return re.compile("".join(out), re.DOTALL)'),
    Mutant("E21", "'**' matches every character '*' can, including newlines", E,
           r'return re.compile("".join(out) + r"\Z", re.DOTALL)', r'return re.compile("".join(out) + r"\Z")'),
    Mutant("E22", "observed names that aren't valid UTF-8 are refused, not mangled", E,
           '                try:\n                    rel.encode("utf-8")',
           '                try:\n                    rel.encode("utf-8", "surrogateescape")'),
    Mutant("E11", "forbidden wins over a requirement", E,
           "if c.path in claimed or c.path in forbidden:", "if c.path in forbidden:"),
    Mutant("E17", "forbidden changes are found even when also required", E,
           "forbidden = [c.path for c in changes if any(p.match(c.path) for p in forbidden_pats)]",
           "forbidden = [c.path for c in changes if c.path not in {x.path for x in changes if any(compile_glob(r.path).match(x.path) for r in spec.required)} and any(p.match(c.path) for p in forbidden_pats)]"),
    Mutant("E18", "permission bits are part of a file's digest", E,
           'meta, data = b"file:%o:" % (st.st_mode & 0o7777), full.read_bytes()',
           'meta, data = b"file:", full.read_bytes()'),
    Mutant("E19", "directories are observed", E,
           '                    snap[rel + "/"] = Entry(_digest(b"dir:%o" % (st.st_mode & 0o7777)))\n                    continue',
           '                    continue'),
    Mutant("E20", "ambiguous resource ids are refused", E,
           "if not isinstance(rid, str):\n                raise TypeError", "if False:\n                raise TypeError"),
    Mutant("E12", "modifications are observed", E,
           "elif a is not None and b is not None and a.digest != b.digest:", "elif False:"),
    Mutant("E13", "deletions are observed", E,
           "elif a is None and b is not None:", "elif False:"),
    Mutant("E14", "symlinks are recorded, not skipped", E,
           "if full.is_symlink():", "if False:"),
    Mutant("E15", "literal glob characters are escaped", E,
           "out.append(re.escape(pattern[i]))", "out.append(pattern[i])"),
    Mutant("R44", "the pre-dispatch snapshot is taken before the tool runs", R,
           "                before = spec.observer.snapshot()\n            except Exception",
           "                before = {}\n            except Exception"),

    # -- receipts ------------------------------------------------------------------------------------ #
    Mutant("V1", "receipt digest is checked", V,
           'if receipt.get("digest") != digest:', "if False:"),
    Mutant("V2", "HMAC signature is checked", V,
           'return [] if HmacSigner(signing_key, kid).verify(digest, kid, value) else ["signature does not verify"]',
           "return []"),
    Mutant("V3", "a required signature must be present", V,
           'if not isinstance(sig, dict) or not all(isinstance(sig.get(k), str) for k in ("alg", "key_id", "value")):\n        return ["receipt is not signed"]',
           'if False:\n        return ["receipt is not signed"]'),
    Mutant("V4", "receipt verification re-verifies the audit chain", V,
           'ok, msg = store.verify_audit(anchor=(head["seq"], head["hash"]))', 'ok, msg = True, ""'),
    Mutant("V5", "receipt lists exactly the store's events for the action", V,
           "if not listed or [(e.seq, e.kind, e.hash) for e in upto] != [(e[\"seq\"], e[\"kind\"], e[\"hash\"]) for e in listed]:",
           "if False:"),
    Mutant("V6", "receipt action digest must match the store", V,
           'if action and row.action_digest != action.get("digest"):', "if False:"),
    Mutant("V9", "every semantic receipt field must match the store", V,
           "if field not in _NOT_SEMANTIC and fresh.get(field) != receipt.get(field):", "if False:"),
    Mutant("V10", "stale receipts are reported", V,
           "if len(stored) > len(upto):", "if False:"),
    Mutant("V11", "malformed receipts get a verdict", V,
           "    except Exception as exc:  # malformed input must give a verdict, not a crash\n        return",
           "    except ZeroDivisionError as exc:  # malformed input must give a verdict, not a crash\n        return"),
    Mutant("V7", "receipt digest covers every field but digest and signature", V,
           'if k not in ("digest", "signature")}', 'if k not in ("digest", "signature", "outcome")}'),
    Mutant("V8", "receipt outcome reflects the frame verdict", V,
           'return frame["verdict"] if frame else "completed"', 'return "verified"'),

    # -- process isolation ---------------------------------------------------------------------------- #
    Mutant("I1", "a timed-out worker process is killed", ISO,
           "            if not self._recv.poll(timeout_s):\n                self.kill()",
           "            if not self._recv.poll(timeout_s):\n                pass"),
    Mutant("I2", "the worker dies with the runtime (Linux PDEATHSIG)", ISO,
           "    _die_with_parent(parent_pid)\n", ""),
    Mutant("I3", "a message for another attempt is never accepted", ISO,
           "if token != self.token:", "if False:",
           equivalent="each attempt has its own pipe, written only by SAR's own worker code with that "
                      "attempt's token; no reachable path delivers a foreign token. Kept as defence in depth."),
    Mutant("I4", "a worker that dies mid-call leaves the effect unknown", R,
           'finish(unknown, reason=f"worker process died ({res.payload})")',
           'finish("failed", reason=f"worker process died ({res.payload})")'),
    Mutant("I5", "a worker's EffectNotApplied is a definite failure", R,
           'elif res.kind == "not_applied":\n            finish("failed"',
           'elif res.kind == "not_applied":\n            finish(unknown'),
    Mutant("I6", "a worker exception from an effectful tool is effect_unknown", R,
           'finish(unknown, reason=f"tool raised {res.payload}")', 'finish("failed", reason=f"tool raised {res.payload}")'),
    Mutant("I7", "process isolation requires importable tools", C,
           "                    pickle.dumps(obj)\n", "                    pass\n"),

    # -- authenticated approvals ---------------------------------------------------------------------- #
    Mutant("U1", "a credential scoped to one action can't approve another", R,
           "if ctx.scope is not None and ctx.scope != action_digest:", "if False:"),
    Mutant("U2", "expired credentials are refused", R,
           "if ctx.expires_at is not None and self.store.now() >= ctx.expires_at:", "if False:"),
    Mutant("U3", "an approval credential is consumed (no replay)", R,
           'reason=f"approved by {ctx.subject}", unexpired_at=self.store.now(),\n                                       consume_credential=ctx.record()["credential"],',
           'reason=f"approved by {ctx.subject}", unexpired_at=self.store.now(),'),
    Mutant("U4", "only a real AuthContext authenticates", R,
           "if not isinstance(ctx, AuthContext):", "if ctx is None:"),
    Mutant("U5", "the approval window is re-checked inside the CAS", S,
           "if unexpired_at is not None:  # the approval window", "if False:  # the approval window"),
    Mutant("U6", "an approval must be backed by the audit log", R,
           "if not self._approval_is_audited(row):", "if False:"),
    Mutant("U7", "a human approval expires if not dispatched in time", R,
           'and self.store.now() >= float(row.approval.get("approved_at", 0)) + self.approval_ttl_s):',
           "and False):"),
    Mutant("U8", "the dispatch claim is fenced on the dispatch count", R,
           'attempt=row.dispatches, dispatches=attempt,', 'dispatches=attempt,'),
    Mutant("U9", "the credential record never stores the credential itself", AU,
           '"credential": "sha256:" + hashlib.sha256(self.credential_id.encode()).hexdigest()}',
           '"credential": self.credential_id}'),

    # -- store ownership and robustness ------------------------------------------------------------------ #
    Mutant("D1", "one process owns a database file (flock)", S,
           "            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)\n", "            pass\n"),
    Mutant("D2", "one live Runtime owns a Store", S,
           "if current is not None and current is not owner:", "if False:"),
    Mutant("D3", "orphaned executions are recovered at start-up", R,
           "self.recovered: list[str] = self.recover() if recover_on_start else []",
           "self.recovered: list[str] = []"),
    Mutant("D4", "unknown schema versions are refused", S,
           "elif version != SCHEMA_VERSION:", "elif False:"),
    Mutant("D5", "database and lock files are owner-only", S,
           "os.close(os.open(path, os.O_CREAT | os.O_RDWR, 0o600))", "os.close(os.open(path, os.O_CREAT | os.O_RDWR, 0o644))"),
    Mutant("D6", "a result that can't be stored falls back instead of wedging", R,
           "                except Exception as exc:\n                    # The result (or its frame report)",
           "                except ZeroDivisionError as exc:\n                    # The result (or its frame report)"),
    Mutant("D7", "dispatch is throttled when too many workers are stuck", R,
           "if stuck >= self.max_stuck_workers:", "if False:"),
    Mutant("D9", "a finished attempt never evicts a newer attempt's worker", R,
           "if self._live.get(key) is worker:  # never evict a newer attempt's worker",
           "if key in self._live:  # never evict a newer attempt's worker",
           equivalent="a newer attempt can only start after reconcile/resolve, which refuse while the older "
                      "worker is alive (R45/R46), so an older attempt never holds the slot when a newer one "
                      "registers. Kept as defence in depth."),
    Mutant("D8", "SQLite errors surface as StoreError", S,
           "        except sqlite3.Error as exc:\n            raise StoreError(f\"SAR database error: {exc}\") from exc",
           "        except ZeroDivisionError as exc:\n            raise StoreError(f\"SAR database error: {exc}\") from exc"),

    # -- signatures --------------------------------------------------------------------------------------- #
    Mutant("G1", "signatures cover alg and key id", SIG,
           'return canonical_json({"alg": alg, "digest": digest, "key_id": key_id}).encode("utf-8")',
           'return canonical_json({"digest": digest}).encode("utf-8")'),
    Mutant("G2", "Ed25519 signatures are verified", SIG,
           '        key.verify(bytes.fromhex(value), signed_message("Ed25519", key_id, digest))\n', '        pass\n'),
    Mutant("G3", "unknown signing key ids are refused", V,
           "if kid not in public_keys:", "if False:"),
    Mutant("G4", "short HMAC keys are refused", SIG,
           "if not isinstance(key, bytes) or len(key) < MIN_HMAC_KEY:", "if not isinstance(key, bytes):"),
    Mutant("V12", "a receipt can be required to be about a given action", V,
           'if expect_action_digest is not None and action.get("digest") != expect_action_digest:', "if False:"),
    Mutant("V13", "the stored state must be backed by the audit log", V,
           'if not states or states[-1].kind != f"call.{row.state}":', "if False:"),

    # -- CLI and telemetry ------------------------------------------------------------------------------------- #
    Mutant("L1", "verify-receipt refuses non-regular files", CLI,
           "if not stat.S_ISREG(st.st_mode):", "if False:"),
    Mutant("L2", "verify-receipt reports unreadable input as 'could not check' (exit 2)", CLI,
           "        except (OSError, ValueError, RecursionError) as exc:\n            print(f\"ERROR: cannot read receipt",
           "        except ZeroDivisionError as exc:\n            print(f\"ERROR: cannot read receipt"),
    Mutant("T1", "a failing tracer cannot change a decision", TEL,
           '            except Exception:\n                log.debug("telemetry: could not start span',
           '            except ZeroDivisionError:\n                log.debug("telemetry: could not start span'),
    Mutant("T2", "a failing span exit cannot change a decision", TEL,
           '                except Exception:\n                    log.debug("telemetry: could not end span',
           '                except ZeroDivisionError:\n                    log.debug("telemetry: could not end span'),

    # -- agent loop ------------------------------------------------------------------------------ #
    Mutant("A1", "the model is offered only granted tools", A,
           "tools = self.runtime.registry.schemas(self.principal.grants)",
           "tools = self.runtime.registry.schemas()"),
    Mutant("A2", "duplicate call ids in one turn are malformed", A,
           "if not isinstance(cid, str) or not cid or cid in seen:", "if not isinstance(cid, str) or not cid:"),
    Mutant("A3", "unknown keys in a tool call are malformed", A,
           'if not isinstance(c, dict) or set(c) - {"id", "name", "arguments"}:', "if not isinstance(c, dict):"),
    Mutant("A4", "a non-dict turn is malformed", A,
           "if not isinstance(raw, dict):\n        return None\n    text",
           "if raw is None:\n        return None\n    text"),
    Mutant("A5", "a call awaiting approval pauses the run", A,
           'if outcome.state == "awaiting_approval":\n                    run.waiting.append',
           'if False:\n                    run.waiting.append'),
    Mutant("A6", "max_steps bounds the loop", A,
           "while run.steps < self.max_steps:", "while True:"),
    Mutant("A7", "the agent reconciles uncertain outcomes", A,
           "            outcome = self.runtime.reconcile(key)\n", ""),
    Mutant("A8", "per-turn call limit", A,
           "if turn is None or len(turn[1]) > self.max_calls_per_turn:", "if turn is None:"),
    # -- resource ownership: whoever creates a Store closes it ---------------------------------- #
    Mutant("O1", "closing a runtime closes the store it owns", R,
           "        if self.owns_store:\n            self.store.close()\n\n    def __enter__",
           "        if False:\n            self.store.close()\n\n    def __enter__"),
    Mutant("O2", "closing a runtime never closes the caller's store", R,
           "        if self.owns_store:\n            self.store.close()\n\n    def __enter__",
           "        if True:\n            self.store.close()\n\n    def __enter__"),
    Mutant("O3", "a failed constructor closes the store it owns", R,
           "        except BaseException:\n            self.close()\n            raise",
           "        except BaseException:\n            self.store.detach(self)\n            raise"),
    Mutant("O4", "a failed constructor releases the caller's store", R,
           "        except BaseException:\n            self.close()\n            raise",
           "        except BaseException:\n            if self.owns_store:\n                self.store.close()\n            raise"),
    Mutant("O5", "a Store that fails to open closes its connection", S,
           "        if db is not None:\n            db.close()\n", ""),
    Mutant("O6", "a store created by the factory is owned by the runtime", f"{PKG}/examples/notes.py",
           "policy=Policy(), owns_store=owns,", "policy=Policy(), owns_store=False,"),
]


def apply(root: Path, m: Mutant) -> None:
    path = root / m.file
    text = path.read_text()
    n = text.count(m.old)
    if n != 1:
        raise SystemExit(f"{m.id}: original text found {n} times in {m.file}; update the mutant")
    path.write_text(text.replace(m.old, m.new))


def run_suite(root: Path, timeout: float) -> tuple[bool, str]:
    env = dict(os.environ, PYTHONPATH=str(root / "src"), PYTHONDONTWRITEBYTECODE="1")
    probe = subprocess.run([sys.executable, "-c", "import secure_agent_runtime as s; print(s.__file__)"],
                           cwd=root, env=env, capture_output=True, text=True)
    if not probe.stdout.strip().startswith(str(root)):
        raise SystemExit(f"mutated copy is not the one imported: {probe.stdout or probe.stderr}")
    try:
        p = subprocess.run([sys.executable, "-m", "pytest", "-x", "-q", "-p", "no:cacheprovider", "tests"],
                           cwd=root, env=env, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return False, "timeout"
    lines = (p.stdout + p.stderr).strip().splitlines()
    failed = next((ln.split("::", 1)[-1] for ln in lines if ln.startswith(("FAILED ", "ERROR "))), "")
    return p.returncode == 0, failed or (lines[-1] if lines else "")


def make_copy(tmp: Path) -> Path:
    root = tmp / "repo"
    shutil.copytree(ROOT / "src", root / "src")
    shutil.copytree(ROOT / "tests", root / "tests")
    shutil.copy(ROOT / "pyproject.toml", root / "pyproject.toml")
    return root


def run_mutant(m: Mutant, timeout: float) -> tuple[Mutant, bool, str]:
    with tempfile.TemporaryDirectory() as tmp:
        root = make_copy(Path(tmp))
        apply(root, m)
        passed, detail = run_suite(root, timeout)
    return m, passed, detail


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("-k", default="", help="only mutants whose id or rule contains this")
    ap.add_argument("-j", type=int, default=os.cpu_count() or 2)
    ap.add_argument("--timeout", type=float, default=60)
    ns = ap.parse_args()
    selected = [m for m in MUTANTS if ns.k.lower() in (m.id + " " + m.rule).lower()]
    ids = [m.id for m in MUTANTS]
    assert len(ids) == len(set(ids)), "duplicate mutant ids"

    with tempfile.TemporaryDirectory() as tmp:
        root = make_copy(Path(tmp))
        for m in selected:  # every mutant must apply cleanly to the current source
            apply(make_copy(Path(tmp) / m.id), m)
        ok, detail = run_suite(root, ns.timeout)
    if not ok:
        print(f"baseline suite fails ({detail}); refusing to run mutants")
        return 2

    with ThreadPoolExecutor(max_workers=ns.j) as pool:
        results = sorted(pool.map(lambda m: run_mutant(m, ns.timeout), selected),
                         key=lambda r: ids.index(r[0].id))

    killed = survived = equivalent = contradictions = 0
    for m, passed, detail in results:
        if m.equivalent and passed:
            equivalent += 1
            status = "EQUIVALENT"
        elif m.equivalent:
            contradictions += 1
            status = "KILLED?!"  # declared equivalent but a test caught it: fix the declaration
        elif passed:
            survived += 1
            status = "SURVIVED"
        else:
            killed += 1
            status = "killed"
        print(f"{m.id:>4}  {status:<10}  {m.rule}" + (f"  [{detail}]" if not passed else ""))
        if m.equivalent and passed:
            print(f"      why equivalent: {m.equivalent}")
    print(f"\n{len(results)} mutants: {killed} killed, {survived} survived, {equivalent} equivalent"
          + (f", {contradictions} declared-equivalent but killed" if contradictions else ""))
    return 1 if survived or contradictions else 0


if __name__ == "__main__":
    sys.exit(main())
