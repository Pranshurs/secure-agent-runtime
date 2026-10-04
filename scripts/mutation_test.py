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
           "f\"{_loc(e['loc'])}: {e['msg']}\" for e in exc.errors(include_input=False)",
           "f\"{_loc(e['loc'])}: {e['msg']} {e['input']}\" for e in exc.errors(include_input=True)"),
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
           "return sha256_text(canonical_json(args))", "return sha256_text(canonical_json(sorted(args)))"),
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
           '        del b["args"]\n', ""),

    # -- policy -------------------------------------------------------------------------- #
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
           'WHERE key=? AND state=?",\n                             (*values, key, from_state))',
           'WHERE key=? AND ?=?",\n                             (*values, key, from_state, from_state))'),
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
           '"effect_unknown" if effectful else "failed",\n                                  reason=f"no result within',
           '"failed",\n                                  reason=f"no result within'),
    Mutant("R33", "unexpected exception from an effectful tool is effect_unknown", R,
           'finish("effect_unknown" if effectful else "failed", reason=f"tool raised',
           'finish("failed", reason=f"tool raised'),
    Mutant("R34", "unreadable result from an effectful tool is effect_unknown", R,
           'finish("effect_unknown" if effectful else "output_rejected"', 'finish("output_rejected"'),
    Mutant("R35", "EffectNotApplied is a definite failure", R,
           'except EffectNotApplied:\n                finish("failed"',
           'except EffectNotApplied:\n                finish("effect_unknown"'),
    Mutant("R37", "only after_effect crash leaves the action executing", R,
           "            except BaseException:  # simulated crash: the worker dies without recording anything\n                return",
           "            except BaseException:  # simulated crash: the worker dies without recording anything\n                pass",
           equivalent="test-only fault hook: with the mutant the worker records the result instead of "
                      "dying, which changes the simulation, not the runtime. Production passes no faults."),

    # -- runtime: reconciliation -------------------------------------------------------------------- #
    Mutant("R38", "Applied reconciles to succeeded", R,
           "if isinstance(finding, Applied):", "if False:"),
    Mutant("R39", "only NotApplied permits another dispatch", R,
           "elif isinstance(finding, NotApplied):", "elif not isinstance(finding, Applied):"),
    Mutant("R40", "a reconciled result is validated", R,
           'if out is None:\n                self.store.record(row.run_id, "reconcile.result_invalid"',
           'if False:\n                self.store.record(row.run_id, "reconcile.result_invalid"'),
    Mutant("R41", "a human resolution needs an independent approver", R,
           "refusal = approval_refusal(self._principals.get(by), row.principal)\n        if refusal is not None:\n            self.store.record(row.run_id, \"resolve.refused\"",
           "refusal = None\n        if refusal is not None:\n            self.store.record(row.run_id, \"resolve.refused\""),
    Mutant("R42", "a reconciler is bounded by the tool timeout", R,
           "    t.join(timeout_s)\n    return box[0]", "    t.join()\n    return box[0]"),
    Mutant("R43", "a reconciler error counts as Unknown", R,
           'box.append(Unknown(f"reconciler raised {type(exc).__name__}"))',
           'box.append(NotApplied())'),

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
           "if pat.match(c.path) and c.change == r.change]", "if pat.match(c.path)]"),
    Mutant("E9", "'*' does not cross '/'", E,
           'out.append("[^/]*")', 'out.append(".*")'),
    Mutant("E10", "globs are anchored at the end", E,
           'return re.compile("".join(out) + r"\\Z")', 'return re.compile("".join(out))'),
    Mutant("E11", "forbidden beats allowed", E,
           "if any(p.match(c.path) for p in forbidden_pats):",
           "if not any(p.match(c.path) for p in allowed_pats) and any(p.match(c.path) for p in forbidden_pats):"),
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
           'if not hmac.compare_digest(expected, str(sig.get("value"))):', "if False:"),
    Mutant("V3", "a required signature must be present", V,
           'if not isinstance(sig, dict) or sig.get("alg") != "HMAC-SHA256":', "if sig is None and False:"),
    Mutant("V4", "receipt verification re-verifies the audit chain", V,
           'ok, msg = store.verify_audit(anchor=(head.get("seq", -1), head.get("hash", "")))',
           'ok, msg = True, ""'),
    Mutant("V5", "receipt audit events must match the store", V,
           'if stored is None or stored.hash != ev.get("hash") or stored.kind != ev.get("kind"):',
           "if stored is None:"),
    Mutant("V6", "receipt action digest must match the store", V,
           'elif action and row.action_digest != action.get("digest"):', "elif False:"),
    Mutant("V7", "receipt digest covers every field but digest and signature", V,
           'if k not in ("digest", "signature")}', 'if k not in ("digest", "signature", "outcome")}'),
    Mutant("V8", "receipt outcome reflects the frame verdict", V,
           'return frame["verdict"] if frame else "completed"', 'return "verified"'),

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
    failed = next((ln.split("::", 1)[1] for ln in lines if ln.startswith("FAILED ")), "")
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
