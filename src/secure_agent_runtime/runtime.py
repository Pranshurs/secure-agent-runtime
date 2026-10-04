"""The governor: the only path from a model's proposed tool call to the tool itself.

The model proposes; the runtime disposes::

    propose()    -> invalid | denied | awaiting_approval | approved
    approve()    awaiting_approval -> approved          (bound to the action digest)
    execute()    approved -> executing -> succeeded | failed | output_rejected | effect_unknown
    reconcile()  effect_unknown -> succeeded | approved (safe to dispatch again) | unchanged
    recover()    executing -> effect_unknown            (after a crash; never re-dispatched blindly)

``effect_unknown`` is the honest state for "the tool may have acted, and we don't know":
a timeout, a crash mid-call, an unexpected exception or an unreadable result from a WRITE
or EXTERNAL tool. Such an action is never dispatched again until reconciliation has
established that its effect did not happen.

Every decision is taken from the principal directory, the tool registry and the policy,
all supplied by the operator, plus the validated arguments. Model text never reaches
:meth:`Policy.decide`.
"""

from __future__ import annotations

import logging
import math
import threading
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel

from .action import Action, action_id_for, sha256_text
from .contracts import (
    Applied,
    Effect,
    EffectNotApplied,
    NotApplied,
    ToolContext,
    ToolRegistry,
    ToolSpec,
    Unknown,
    canonical_json,
    invoke,
    parse_input,
    plain_json,
    request_hash,
    validate_output,
)
from .effects import FrameSpec, Snapshot, check_frame, digests, from_digests
from .policy import Policy, Principal, Verdict, approval_refusal
from .store import CallRow, Store

POLICY_APPROVER = "policy:allow"
MAX_ID_LEN = 256

log = logging.getLogger(__name__)


class SARError(Exception):
    pass


class MalformedProposal(SARError):
    """The proposal can't even be keyed (e.g. a missing or non-string call id)."""


class ReplayDivergence(SARError):
    """The same idempotency key was proposed again with different content."""


class ApprovalRefused(SARError):
    pass


@dataclass(frozen=True)
class Outcome:
    key: str
    tool: str
    state: str
    action_digest: str | None
    reason: str = ""
    result: dict[str, Any] | None = None
    verification: str | None = None  # frame verdict: verified | violated | unverifiable

    @classmethod
    def of(cls, row: CallRow) -> Outcome:
        return cls(key=row.key, tool=row.tool, state=row.state, action_digest=row.action_digest,
                   reason=row.reason, result=row.result,
                   verification=row.frame_result["verdict"] if row.frame_result else None)

    def for_model(self) -> dict[str, Any]:
        """What the model is told. Only a succeeded call carries tool output.

        A rejected output's validation details (which can include field names chosen by
        the tool) stay in the store; the model gets a fixed message.
        """
        if self.state == "succeeded":
            out: dict[str, Any] = {"status": self.state, "result": self.result}
            if self.verification:
                out["verification"] = self.verification
            return out
        if self.state == "output_rejected":
            return {"status": self.state, "error": "tool output failed validation"}
        if self.state == "effect_unknown":
            return {"status": self.state, "error": "outcome uncertain; held for reconciliation"}
        return {"status": self.state, "error": self.reason}


def call_key(run_id: str, call_id: str) -> str:
    # JSON-encoded pair, so ("a:b", "c") and ("a", "b:c") can't collide.
    return canonical_json([run_id, call_id])


def _effectful(spec: ToolSpec | None) -> bool:
    return spec is None or spec.effect is not Effect.READ


_UNVERIFIABLE = {"verdict": "unverifiable", "observed": [], "required": [], "allowed": [],
                 "undeclared": [], "forbidden": []}


class Runtime:
    def __init__(self, *, registry: ToolRegistry, policy: Policy, principals: Iterable[Principal],
                 store: Store, approval_ttl_s: float = 3600.0,
                 faults: Callable[[str, str], None] | None = None) -> None:
        """``faults(point, key)`` is a fault-injection hook called at execution boundaries.
        Raising from it simulates a crash there: at ``after_claim`` the exception propagates
        out of ``execute`` with the action claimed but not dispatched; at ``after_effect``
        the worker exits after the tool returned, without recording the result."""
        if approval_ttl_s <= 0:
            raise ValueError("approval_ttl_s must be positive")
        self.registry = registry
        self.policy = policy
        self.store = store
        self.approval_ttl_s = approval_ttl_s
        self._faults = faults or (lambda point, key: None)
        self._before: dict[str, tuple[int, Snapshot]] = {}  # key -> (attempt, pre-dispatch snapshot)
        self._live: dict[str, threading.Thread] = {}  # key -> worker of the latest dispatch
        self._principals: dict[str, Principal] = {}
        for p in principals:
            if p.id in self._principals or p.id == POLICY_APPROVER:
                raise ValueError(f"duplicate or reserved principal id {p.id!r}")
            self._principals[p.id] = p

    def principal(self, principal_id: str) -> Principal | None:
        return self._principals.get(principal_id)

    # -- proposals ---------------------------------------------------------------- #
    def propose(self, *, run_id: str, principal_id: str, call_id: Any, tool: Any, arguments: Any,
                idempotency_key: str | None = None, deadline: float | None = None) -> Outcome:
        """Turn a proposal into a recorded action. ``idempotency_key`` defaults to
        ``(run_id, call_id)``; pass your own to dedupe across runs."""
        principal = self._principals.get(principal_id)
        if principal is None:
            raise KeyError(f"unknown principal {principal_id!r}")
        for label, value in (("run_id", run_id), ("call_id", call_id)):
            if not isinstance(value, str) or not 0 < len(value) <= MAX_ID_LEN or plain_json(value) is None:
                raise MalformedProposal(f"{label} must be a non-empty UTF-8 string of at most {MAX_ID_LEN}"
                                        " characters")
        key = call_key(run_id, call_id) if idempotency_key is None else idempotency_key
        if not isinstance(key, str) or not key or plain_json(key) is None:
            raise MalformedProposal("idempotency_key must be a non-empty UTF-8 string")
        if deadline is not None and (isinstance(deadline, bool) or not isinstance(deadline, (int, float))
                                     or not math.isfinite(deadline)):
            raise ValueError("deadline must be a finite number (seconds since the epoch) or None")
        deadline = None if deadline is None else float(deadline)
        rh = request_hash(tool, arguments, {"deadline": deadline})
        now = self.store.now()
        state, reason, args, action, tool_name = self._classify(
            principal, tool, arguments, key=key, run_id=run_id, now=now, deadline=deadline)
        digest = action.digest if action else None
        # The primary key decides: a replay (or a racing duplicate) fails the insert and is
        # answered from the stored record instead.
        inserted = self.store.insert_call(
            key=key, run_id=run_id, call_id=call_id, principal=principal_id, tool=tool_name, args=args,
            action=action.body() if action else None, action_digest=digest, request_hash=rh,
            state=state, reason=reason, created_at=now,
            expires_at=now + self.approval_ttl_s if state == "awaiting_approval" else None,
            approval=self._approval_record(POLICY_APPROVER, digest, now) if state == "approved" else None,
            event={"principal": principal_id, "tool": tool_name, "action_digest": digest, "request_hash": rh},
        )
        row = self._get(key)
        if not inserted:
            return self._replay(row, principal_id, rh)
        return Outcome.of(row)

    def _classify(self, principal: Principal, tool: Any, arguments: Any, *, key: str, run_id: str,
                  now: float, deadline: float | None) -> tuple[str, str, Any, Action | None, str]:
        named = isinstance(tool, str) and plain_json(tool) is not None and len(tool) <= MAX_ID_LEN
        tool_name = tool if named else f"<{type(tool).__name__}>"
        raw = arguments if plain_json(arguments) is not None else {"_unserialisable": type(arguments).__name__}
        spec = self.registry.get(tool) if named else None
        if spec is None:
            return "invalid", f"unknown tool {tool_name!r}", raw, None, tool_name
        model, error = parse_input(spec, arguments)
        if model is None:
            return "invalid", f"invalid arguments: {error}", raw, None, tool_name
        try:
            action = self._build_action(spec, model, key=key, actor=principal.id, run_id=run_id,
                                        created_at=now, deadline=deadline)
        except Exception as exc:  # an operator frame builder that fails is a refusal, not a crash
            return "invalid", f"could not declare effects: {type(exc).__name__}", raw, None, tool_name
        decision = self.policy.decide(principal, spec, action.args)
        if decision.verdict is Verdict.DENY:
            return "denied", f"{decision.rule}: {decision.reason}", action.args, action, tool_name
        if decision.verdict is Verdict.REQUIRE_APPROVAL:
            return "awaiting_approval", decision.reason, action.args, action, tool_name
        if decision.verdict is Verdict.ALLOW:
            return "approved", decision.reason, action.args, action, tool_name
        raise AssertionError(f"unhandled verdict {decision.verdict!r}")  # pragma: no cover

    @staticmethod
    def _build_action(spec: ToolSpec, model: BaseModel, *, key: str, actor: str, run_id: str,
                      created_at: float, deadline: float | None) -> Action:
        frame = None
        if spec.frame is not None:
            declared = spec.frame(model)
            if not isinstance(declared, FrameSpec):
                raise TypeError("frame builder must return a FrameSpec")
            frame = declared.to_json()
        return Action(action_id=action_id_for(key), idempotency_key=key, actor=actor, run_id=run_id,
                      tool=spec.name, tool_version=spec.version, schema_digest=spec.schema_digest,
                      args=model.model_dump(mode="json"), authority=spec.effect.value, frame=frame,
                      created_at=created_at, deadline=deadline)

    def _replay(self, row: CallRow, principal_id: str, rh: str) -> Outcome:
        if row.request_hash != rh or row.principal != principal_id:
            self.store.record(row.run_id, "call.replay_divergence",
                              {"stored_request_hash": row.request_hash, "new_request_hash": rh,
                               "principal": principal_id}, call_key=row.key)
            raise ReplayDivergence(f"action {row.key} was already proposed with different content")
        self.store.record(row.run_id, "call.replayed", {"state": row.state}, call_key=row.key)
        return Outcome.of(row)

    # -- approvals ---------------------------------------------------------------- #
    @staticmethod
    def _approval_record(approver: str, digest: str | None, at: float) -> dict[str, Any]:
        return {"approver": approver, "action_digest": digest, "approved_at": at,
                "kind": "policy" if approver == POLICY_APPROVER else "human"}

    def approve(self, key: str, *, approver_id: str, action_digest: str) -> Outcome:
        """Approve exactly the action whose digest the approver was shown."""
        row = self._get(key)
        refusal = self._approval_problem(row, approver_id)
        if refusal is None and action_digest != row.action_digest:
            refusal = "approval is for a different action"
        if refusal is not None:
            self.store.record(row.run_id, "approval.refused",
                              {"approver": approver_id, "reason": refusal, "action_digest": action_digest},
                              call_key=key)
            raise ApprovalRefused(refusal)
        record = self._approval_record(approver_id, action_digest, self.store.now())
        if not self.store.transition(key, "awaiting_approval", "approved", approval=record,
                                     reason=f"approved by {approver_id}",
                                     event={"approver": approver_id, "action_digest": action_digest}):
            raise ApprovalRefused("action is no longer awaiting approval")
        return Outcome.of(self._get(key))

    def reject(self, key: str, *, approver_id: str, reason: str = "") -> Outcome:
        row = self._get(key)
        refusal = self._approval_problem(row, approver_id)
        if refusal is not None:
            self.store.record(row.run_id, "approval.refused", {"approver": approver_id, "reason": refusal},
                              call_key=key)
            raise ApprovalRefused(refusal)
        if not self.store.transition(key, "awaiting_approval", "rejected", reason=reason or "rejected",
                                     event={"approver": approver_id}):
            raise ApprovalRefused("action is no longer awaiting approval")
        return Outcome.of(self._get(key))

    def _approval_problem(self, row: CallRow, approver_id: str) -> str | None:
        if row.state != "awaiting_approval":
            return f"action is {row.state}, not awaiting approval"
        if row.expires_at is not None and self.store.now() >= row.expires_at:
            self.store.transition(row.key, "awaiting_approval", "expired", reason="approval window elapsed")
            return "approval window elapsed"
        return approval_refusal(self._principals.get(approver_id), row.principal)

    def expire_pending(self) -> list[str]:
        now, expired = self.store.now(), []
        for row in self.store.calls(state="awaiting_approval"):
            if row.expires_at is not None and now >= row.expires_at and self.store.transition(
                    row.key, "awaiting_approval", "expired", reason="approval window elapsed"):
                expired.append(row.key)
        return expired

    def cancel(self, key: str, *, reason: str = "cancelled") -> Outcome:
        """Cancel (or revoke the approval of) an action that has not been dispatched."""
        row = self._get(key)
        if row.state in ("awaiting_approval", "approved"):
            self.store.transition(key, row.state, "cancelled", reason=reason)
        return Outcome.of(self._get(key))

    # -- execution ---------------------------------------------------------------- #
    def execute(self, key: str) -> Outcome:
        """Dispatch an approved action. Any other state returns the stored outcome without
        touching the tool."""
        row = self._get(key)
        if row.state != "approved":
            return Outcome.of(row)
        problem, spec, model, action = self._pre_execution_check(row)
        if problem is not None:
            self.store.transition(key, "approved", "cancelled", reason=f"blocked at execution: {problem}")
            return Outcome.of(self._get(key))
        assert spec is not None and model is not None and action is not None

        before: Snapshot | None = None
        if spec.observer is not None:
            try:
                before = spec.observer.snapshot()
            except Exception as exc:
                self.store.transition(key, "approved", "cancelled",
                                      reason=f"could not observe state before dispatch: {type(exc).__name__}")
                return Outcome.of(self._get(key))
        attempt = row.dispatches + 1
        # The executing event is committed before the tool is invoked, so the audit log can
        # over-count invocations after a crash (see recover()) but can never under-count.
        if not self.store.transition(key, "approved", "executing", dispatches=attempt,
                                     before=digests(before) if before is not None else None,
                                     event={"action_digest": row.action_digest, "attempt": attempt}):
            return Outcome.of(self._get(key))
        if before is not None:
            self._before[key] = (attempt, before)
        self._faults("after_claim", key)

        effectful = _effectful(spec)
        ctx = ToolContext(action_id=action.action_id, idempotency_key=key, attempt=attempt,
                          cancel=threading.Event())

        def finish(state: str, **fields: Any) -> None:
            try:
                if not self.store.transition(key, "executing", state, attempt=attempt, **fields):
                    self.store.record(row.run_id, "call.late_result_discarded", {"would_have_been": state},
                                      call_key=key)
            except Exception:  # e.g. the store was closed while a timed-out tool kept running
                log.exception("could not record the result of %s", key)

        def work() -> None:
            try:
                raw = invoke(spec, model, ctx)
            except EffectNotApplied:
                finish("failed", reason="tool reported its effect was not applied")
                return
            except BaseException as exc:  # SystemExit in a tool must not strand the action
                finish("effect_unknown" if effectful else "failed", reason=f"tool raised {type(exc).__name__}")
                return
            try:
                self._faults("after_effect", key)
            except BaseException:  # simulated crash: the worker dies without recording anything
                return
            out, error = validate_output(spec, raw)  # never raises
            if out is None:
                finish("effect_unknown" if effectful else "output_rejected", reason=f"invalid output: {error}")
                return
            finish("succeeded", result=out, result_digest=sha256_text(canonical_json(out)), reason="",
                   frame_result=self._frame_result(spec, action, key, attempt))

        worker = threading.Thread(target=work, name=f"sar-tool-{spec.name}", daemon=True)
        self._live[key] = worker
        worker.start()
        worker.join(spec.timeout_s)
        if worker.is_alive():
            ctx.cancel.set()
            self.store.transition(key, "executing", "effect_unknown" if effectful else "failed",
                                  attempt=attempt, reason=f"no result within {spec.timeout_s}s")
        return Outcome.of(self._get(key))

    def _frame_result(self, spec: ToolSpec, action: Action, key: str, attempt: int) -> dict[str, Any] | None:
        if spec.observer is None or action.frame is None:
            return None
        cached = self._before.get(key)
        before = None
        if cached is not None and cached[0] == attempt:
            before = self._before.pop(key)[1]
        if before is None:
            row = self.store.get_call(key)
            if row is None or row.before is None:
                return {**_UNVERIFIABLE, "note": "no pre-dispatch snapshot"}
            before = from_digests(row.before)  # after a restart: digests only
        try:
            after = spec.observer.snapshot()
        except Exception as exc:
            return {**_UNVERIFIABLE, "note": f"observer raised {type(exc).__name__}"}
        return check_frame(FrameSpec.from_json(action.frame), before, after).to_json()

    def _pre_execution_check(self, row: CallRow) -> tuple[str | None, ToolSpec | None, BaseModel | None,
                                                          Action | None]:
        """Re-check everything at the last moment, from stored facts and current config."""
        none = (None, None, None)
        spec = self.registry.get(row.tool)
        principal = self._principals.get(row.principal)
        if spec is None or principal is None or row.action is None:
            return ("tool or principal no longer registered", *none)
        try:
            stored = Action.from_body(row.action)
        except (KeyError, TypeError, ValueError):
            return ("stored action is unreadable", *none)
        if stored.digest != row.action_digest:
            return ("stored action does not match its digest", *none)
        if not row.approval or row.approval.get("action_digest") != row.action_digest:
            return ("approval does not match the stored action", *none)
        if stored.deadline is not None and self.store.now() >= stored.deadline:
            return ("action deadline has passed", *none)
        model, _ = parse_input(spec, stored.args)  # the tool's schema may have changed since
        if model is None or model.model_dump(mode="json") != stored.args:
            return ("stored arguments no longer validate", *none)
        try:
            current = self._build_action(spec, model, key=row.key, actor=stored.actor, run_id=stored.run_id,
                                         created_at=stored.created_at, deadline=stored.deadline)
        except Exception as exc:
            return (f"could not declare effects: {type(exc).__name__}", *none)
        if current.digest != row.action_digest:
            return ("the tool, its version, schema or declared effects changed since approval", *none)
        decision = self.policy.decide(principal, spec, current.args)
        if decision.verdict is Verdict.DENY:
            return (f"policy now denies: {decision.reason}", *none)
        if decision.verdict is Verdict.REQUIRE_APPROVAL:
            # POLICY_APPROVER is reserved and never in the directory, so an action that was
            # auto-allowed but now needs approval is refused here too.
            refusal = approval_refusal(self._principals.get(row.approval.get("approver", "")), row.principal)
            if refusal is not None:
                return (f"approval no longer valid: {refusal}", *none)
        return None, spec, model, current

    # -- uncertain outcomes ------------------------------------------------------- #
    def reconcile(self, key: str) -> Outcome:
        """Ask the tool's reconciler whether an ``effect_unknown`` action took effect.

        Applied -> ``succeeded`` with the reconciled result. NotApplied -> ``approved``,
        so ``execute`` may dispatch it again (re-checking everything). Unknown, a
        reconciler error or timeout, or no reconciler -> stays ``effect_unknown``.
        """
        row = self._get(key)
        if row.state != "effect_unknown":
            return Outcome.of(row)
        spec = self.registry.get(row.tool)
        if spec is None or spec.reconciler is None or row.action is None:
            self.store.record(row.run_id, "reconcile.unavailable", {}, call_key=key)
            return Outcome.of(row)
        action = Action.from_body(row.action)
        model, _ = parse_input(spec, action.args)
        if model is None:
            self.store.record(row.run_id, "reconcile.unavailable", {"why": "args no longer validate"},
                              call_key=key)
            return Outcome.of(row)
        worker = self._live.get(key)
        if worker is not None and worker.is_alive():
            # The timed-out dispatch is still running here and could yet act; asking now
            # could get "not applied" just before it applies. Wait for it to finish.
            self.store.record(row.run_id, "reconcile.deferred", {"why": "dispatch still running"}, call_key=key)
            return Outcome.of(row)
        reconciler = spec.reconciler
        attempt = row.dispatches
        ctx = ToolContext(action_id=action.action_id, idempotency_key=key, attempt=attempt,
                          cancel=threading.Event())
        finding = _bounded(lambda: reconciler(model, ctx), spec.timeout_s)
        if isinstance(finding, Applied):
            out, error = validate_output(spec, finding.result)
            if out is None:
                self.store.record(row.run_id, "reconcile.result_invalid", {"error": error}, call_key=key)
                return Outcome.of(row)
            if not self.store.transition(key, "effect_unknown", "succeeded", attempt=attempt, result=out,
                                         result_digest=sha256_text(canonical_json(out)),
                                         reason="reconciled: effect was applied",
                                         frame_result=self._frame_result(spec, action, key, attempt),
                                         event={"reconciled": "applied", "attempt": attempt}):
                self.store.record(row.run_id, "reconcile.stale", {"attempt": attempt}, call_key=key)
        elif isinstance(finding, NotApplied):
            if not self.store.transition(key, "effect_unknown", "approved", attempt=attempt,
                                         reason="reconciled: effect not applied; may be dispatched again",
                                         event={"reconciled": "not_applied", "attempt": attempt}):
                self.store.record(row.run_id, "reconcile.stale", {"attempt": attempt}, call_key=key)
        else:
            why = finding.reason if isinstance(finding, Unknown) else f"reconciler returned {type(finding).__name__}"
            self.store.record(row.run_id, "reconcile.unknown", {"why": (why or "undecided")[:200]}, call_key=key)
        return Outcome.of(self._get(key))

    def resolve(self, key: str, *, by: str, applied: bool, result: Any = None,
                redispatch: bool = False) -> Outcome:
        """A human's verdict on an ``effect_unknown`` action, for tools with no reconciler.

        ``by`` must be an approver other than the requester. ``applied=False`` ends the
        action as ``failed`` unless ``redispatch=True``, which re-approves it.
        """
        row = self._get(key)
        if row.state != "effect_unknown":
            raise ApprovalRefused(f"action is {row.state}, not effect_unknown")
        refusal = approval_refusal(self._principals.get(by), row.principal)
        if refusal is not None:
            self.store.record(row.run_id, "resolve.refused", {"by": by, "reason": refusal}, call_key=key)
            raise ApprovalRefused(refusal)
        worker = self._live.get(key)
        if worker is not None and worker.is_alive():
            raise ApprovalRefused("the last dispatch is still running; resolve after it finishes")
        spec = self.registry.get(row.tool)
        attempt = row.dispatches
        if applied:
            out = None
            if result is not None and spec is not None:
                out, error = validate_output(spec, result)
                if out is None:
                    raise ValueError(f"result does not validate: {error}")
            frame = None
            if spec is not None and row.action is not None:
                frame = self._frame_result(spec, Action.from_body(row.action), key, attempt)
            ok = self.store.transition(key, "effect_unknown", "succeeded", attempt=attempt, result=out,
                                       result_digest=sha256_text(canonical_json(out)) if out is not None else None,
                                       reason=f"resolved by {by}: effect was applied", frame_result=frame,
                                       event={"resolved_by": by, "applied": True, "attempt": attempt})
        else:
            ok = self.store.transition(key, "effect_unknown", "approved" if redispatch else "failed",
                                       attempt=attempt, reason=f"resolved by {by}: effect not applied",
                                       event={"resolved_by": by, "applied": False, "redispatch": redispatch,
                                              "attempt": attempt})
        if not ok:
            raise ApprovalRefused("the action changed while it was being resolved")
        return Outcome.of(self._get(key))

    # -- recovery ----------------------------------------------------------------- #
    def recover(self) -> list[str]:
        """After a crash: actions left ``executing`` become ``effect_unknown`` (or ``failed``
        for READ tools, which have no effect). Nothing is re-dispatched automatically.

        Call this only at startup, before any worker of this store is running.
        """
        moved = []
        for row in self.store.calls(state="executing"):
            target = "effect_unknown" if _effectful(self.registry.get(row.tool)) else "failed"
            if self.store.transition(row.key, "executing", target, reason="runtime stopped during execution"):
                moved.append(row.key)
        return moved

    # -- receipts ----------------------------------------------------------------- #
    def receipt(self, key: str, *, signing_key: bytes | None = None, key_id: str = "default") -> dict[str, Any]:
        """A machine-verifiable Agent Receipt for one action (see ``receipts``)."""
        from .receipts import build_receipt

        return build_receipt(self.store, key, signing_key=signing_key, key_id=key_id)

    def _get(self, key: str) -> CallRow:
        row = self.store.get_call(key)
        if row is None:
            raise KeyError(f"no action {key!r}")
        return row


def _bounded(fn: Callable[[], Any], timeout_s: float) -> Any:
    """Run ``fn`` in a thread; return its value, or an Unknown on error or timeout."""
    box: list[Any] = []

    def run() -> None:
        try:
            box.append(fn())
        except BaseException as exc:
            box.append(Unknown(f"reconciler raised {type(exc).__name__}"))

    t = threading.Thread(target=run, name="sar-reconcile", daemon=True)
    t.start()
    t.join(timeout_s)
    return box[0] if box else Unknown("reconciler timed out")
