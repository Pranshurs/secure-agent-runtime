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


C, P, S, R, A = (f"{PKG}/{m}.py" for m in ("contracts", "policy", "store", "runtime", "agent"))

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
    Mutant("C7", "args hash is bound to the tool name", C,
           'canonical_json({"tool": tool, "args": args})', 'canonical_json({"args": args})'),
    Mutant("C8", "args hash covers argument values", C,
           'canonical_json({"tool": tool, "args": args})', 'canonical_json({"tool": tool, "args": sorted(args)})'),
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
    Mutant("C13", "validation errors never echo unknown field names", C,
           'str(p) if _SAFE_LOC.match(str(p)) else "<field>"', "str(p)"),
    Mutant("C12", "arguments must be a JSON object", C,
           "if not isinstance(raw, dict):\n        return None, \"arguments must be a JSON object\"",
           "if raw is None:\n        return None, \"arguments must be a JSON object\""),

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

    # -- runtime: proposals and replay ------------------------------------------------------ #
    Mutant("R1", "policy DENY becomes a denied call", R,
           'if decision.verdict is Verdict.DENY:\n            return "denied"',
           'if decision.verdict is Verdict.DENY:\n            return "approved"'),
    Mutant("R2", "REQUIRE_APPROVAL becomes a pending call", R,
           'return "pending_approval", decision.reason', 'return "approved", decision.reason'),
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
    Mutant("R8", "approval is bound to args_hash", R,
           "if refusal is None and args_hash != row.args_hash:", "if False:"),
    Mutant("R9", "only pending calls can be approved (and refusals are audited)", R,
           'if row.state != "pending_approval":\n            return f"call is {row.state}',
           'if False:\n            return f"call is {row.state}'),
    Mutant("R10", "approval window enforced", R,
           "if row.expires_at is not None and self.store.now() >= row.expires_at:\n            self.store",
           "if False:\n            self.store"),
    Mutant("R11", "approval window boundary is exclusive", R,
           "if row.expires_at is not None and self.store.now() >= row.expires_at:\n            self.store",
           "if row.expires_at is not None and self.store.now() > row.expires_at:\n            self.store"),
    Mutant("R12", "approve records the approver's hash", R,
           "approved_hash=args_hash, reason=", "approved_hash=None, reason="),

    # -- runtime: execution ---------------------------------------------------------------------- #
    Mutant("R13", "only approved calls take the execution path", R,
           'if row.state != "approved":\n            return Outcome.of(row)',
           'if row.state in ("succeeded",):\n            return Outcome.of(row)',
           equivalent="for any non-approved row the pre-execution check fails (approved_hash "
                      "is unset) and its cancel CAS fails; the approved->executing CAS is the "
                      "real guard (S1, S2, R15). This early return is a fast path."),
    Mutant("R14", "pre-execution check blocks execution", R,
           "if problem is not None:\n            self.store.transition(key, \"approved\", \"cancelled\"",
           "if False:\n            self.store.transition(key, \"approved\", \"cancelled\""),
    Mutant("R15", "execution claim is compare-and-set", R,
           'if not self.store.transition(key, "approved", "executing", event={"args_hash": row.args_hash}):\n'
           "            return Outcome.of(self._get(key))",
           'if not self.store.transition(key, "approved", "executing", event={"args_hash": row.args_hash}):\n'
           "            pass"),
    Mutant("R16", "stored args must match their hash", R,
           "if args_hash(row.tool, row.args) != row.args_hash:", "if False:"),
    Mutant("R17", "approval must match the stored args", R,
           "if row.approved_hash != row.args_hash:", "if False:"),
    Mutant("R18", "stored args re-validated against the current schema", R,
           'if args is None:\n            return "stored arguments no longer validate"',
           'if False:\n            return "stored arguments no longer validate"'),
    Mutant("R19", "policy re-checked at execution (revoked grant)", R,
           'if decision.verdict is Verdict.DENY:\n            return f"policy now denies',
           'if False:\n            return f"policy now denies'),
    Mutant("R20", "approver re-checked at execution", R,
           "if refusal is not None:\n                return f\"approval no longer valid",
           "if False:\n                return f\"approval no longer valid"),
    Mutant("R21", "execution re-check consults the policy, not the stored state", R,
           "if decision.verdict is Verdict.REQUIRE_APPROVAL:\n            # POLICY_APPROVER",
           "if False:\n            # POLICY_APPROVER"),

    # -- runtime: timeouts, output, recovery ---------------------------------------------------- #
    Mutant("R22", "timeout ends the call", R,
           "if worker.is_alive():\n            cancel.set()", "if False:\n            cancel.set()"),
    Mutant("R23", "timed-out tool is signalled to cancel", R,
           "if worker.is_alive():\n            cancel.set()", "if worker.is_alive():\n            pass"),
    Mutant("R24", "a late result is discarded with an audit event", R,
           'self.store.record(row.run_id, "call.late_result_discarded"',
           'None and self.store.record(row.run_id, "call.late_result_discarded"'),
    Mutant("R25", "invalid output is rejected", R,
           "if out is None:\n                finish(\"output_rejected\"",
           "if False:\n                finish(\"output_rejected\""),
    Mutant("R26", "tool exception messages are not recorded or shown", R,
           'finish("failed", reason=f"tool raised {type(exc).__name__}")',
           'finish("failed", reason=f"tool raised {exc}")'),
    Mutant("R27", "rejected output details are not shown to the model", R,
           'if self.state == "output_rejected":\n            return', 'if False:\n            return'),
    Mutant("R28", "only succeeded calls carry a result to the model", R,
           'if self.state == "succeeded":\n            return {"status": self.state, "result": self.result}',
           'if True:\n            return {"status": self.state, "result": self.result}'),
    Mutant("R29", "crash recovery marks executing calls outcome_unknown", R,
           'if self.store.transition(row.key, "executing", "outcome_unknown",',
           'if False and self.store.transition(row.key, "executing", "outcome_unknown",'),

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
    Mutant("A5", "a pending call pauses the run", A,
           'if outcome.state == "pending_approval":\n                    run.waiting.append',
           'if False:\n                    run.waiting.append'),
    Mutant("A6", "max_steps bounds the loop", A,
           "while run.steps < self.max_steps:", "while True:"),
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
