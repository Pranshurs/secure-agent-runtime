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

import json
import logging
import math
import threading
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel

from .action import Action, action_id_for, new_salt, sha256_text
from .auth import AuthContext, Authenticator
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
from .errors import CredentialReused, SARError
from .policy import Policy, Principal, Verdict, approval_refusal
from .store import CallRow, Store, approval_digest
from .telemetry import Telemetry

POLICY_APPROVER = "policy:allow"
MAX_ID_LEN = 256

log = logging.getLogger(__name__)


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
                 store: Store, authenticator: Authenticator | None = None, approval_ttl_s: float = 3600.0,
                 max_stuck_workers: int = 32, recover_on_start: bool = True,
                 telemetry: Telemetry | None = None,
                 faults: Callable[[str, str], None] | None = None, owns_store: bool = False) -> None:
        """``faults(point, key)`` is a fault-injection hook called at execution boundaries.
        Raising from it simulates a crash there: at ``after_claim`` the exception propagates
        out of ``execute`` with the action claimed but not dispatched; at ``after_effect``
        the worker exits after the tool returned, without recording the result.

        ``authenticator`` turns approval credentials into an :class:`AuthContext`; without
        one, ``approve``/``reject``/``resolve`` refuse. ``approval_ttl_s`` bounds both the
        window to approve and the time an approval stays valid for dispatch.
        ``recover_on_start`` runs :meth:`recover` immediately: the store has a single owner
        (see :class:`Store`), so any action still ``executing`` is an orphan of a crash.

        ``owns_store`` says who closes ``store``. A store you pass in stays yours (the
        default); a factory that creates the store itself passes ``owns_store=True`` so that
        :meth:`close` closes it, as does a constructor that fails."""
        if approval_ttl_s <= 0:
            raise ValueError("approval_ttl_s must be positive")
        self.owns_store = owns_store
        try:
            store.attach(self)
        except BaseException:
            if owns_store:
                store.close()
            raise
        self.store = store
        try:
            self._setup(registry=registry, policy=policy, principals=principals, approval_ttl_s=approval_ttl_s,
                        max_stuck_workers=max_stuck_workers, recover_on_start=recover_on_start,
                        telemetry=telemetry, authenticator=authenticator, faults=faults)
        except BaseException:
            self.close()
            raise

    def _setup(self, *, registry: ToolRegistry, policy: Policy, principals: Iterable[Principal],
               authenticator: Authenticator | None, approval_ttl_s: float, max_stuck_workers: int,
               recover_on_start: bool, telemetry: Telemetry | None,
               faults: Callable[[str, str], None] | None) -> None:
        store = self.store
        self.telemetry = telemetry if telemetry is not None else Telemetry.from_global()
        self.authenticator = authenticator
        self.max_stuck_workers = max_stuck_workers
        self.registry = registry
        self.policy = policy
        self.approval_ttl_s = approval_ttl_s
        self._faults = faults or (lambda point, key: None)
        self._before: dict[str, tuple[int, Snapshot]] = {}  # key -> (attempt, pre-dispatch snapshot)
        self._live: dict[str, Any] = {}  # key -> worker (thread or process) of the latest dispatch
        self._mem = threading.Lock()  # guards _before and _live, shared by every calling thread
        self._principals: dict[str, Principal] = {}
        for p in principals:
            if p.id in self._principals or p.id == POLICY_APPROVER:
                raise ValueError(f"duplicate or reserved principal id {p.id!r}")
            self._principals[p.id] = p
        if store.path == ":memory:" and any(_effectful(registry.get(n)) for n in registry.names()):
            log.warning("SAR is using an in-memory store with WRITE/EXTERNAL tools: idempotency, approvals "
                        "and crash recovery are lost when the process exits")
        self.recovered: list[str] = self.recover() if recover_on_start else []
        if self.recovered:
            log.warning("recovered %d action(s) left executing by a previous run; they are effect_unknown "
                        "until reconciled", len(self.recovered))

    def close(self) -> None:
        """Release the store for another Runtime. The store is closed too only if this
        Runtime owns it (``owns_store=True``); a store passed in stays open for its owner."""
        self.store.detach(self)
        if self.owns_store:
            self.store.close()

    def __enter__(self) -> Runtime:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def principal(self, principal_id: str) -> Principal | None:
        return self._principals.get(principal_id)

    # -- public operations: traced wrappers (telemetry can't change their result) ---- #
    def propose(self, *, run_id: str, principal_id: str, call_id: Any, tool: Any, arguments: Any,
                idempotency_key: str | None = None, deadline: float | None = None) -> Outcome:
        """Turn a proposal into a recorded action (see :meth:`_propose`)."""
        with self.telemetry.span("sar.propose", **{"sar.run_id": run_id if isinstance(run_id, str) else None}) as sp:
            o = self._propose(run_id=run_id, principal_id=principal_id, call_id=call_id, tool=tool,
                              arguments=arguments, idempotency_key=idempotency_key, deadline=deadline)
            self._observe(sp, o)
            return o

    def approve(self, key: str, *, credential: Any, action_digest: str) -> Outcome:
        """Approve exactly the action whose digest the approver was shown (see :meth:`_approve`)."""
        with self.telemetry.span("sar.approve", **{"sar.action_id": action_id_for(key)}) as sp:
            o = self._approve(key, credential=credential, action_digest=action_digest)
            self._observe(sp, o)
            return o

    def reject(self, key: str, *, credential: Any, reason: str = "") -> Outcome:
        with self.telemetry.span("sar.reject", **{"sar.action_id": action_id_for(key)}) as sp:
            o = self._reject(key, credential=credential, reason=reason)
            self._observe(sp, o)
            return o

    def cancel(self, key: str, *, reason: str = "cancelled") -> Outcome:
        """Cancel (or revoke the approval of) an action that has not been dispatched."""
        with self.telemetry.span("sar.cancel", **{"sar.action_id": action_id_for(key)}) as sp:
            o = self._cancel(key, reason=reason)
            self._observe(sp, o)
            return o

    def execute(self, key: str) -> Outcome:
        """Dispatch an approved action; any other state returns the stored outcome (see :meth:`_execute`)."""
        row = self._get(key)
        spec = self.registry.get(row.tool)
        attrs = {"gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": row.tool, "sar.tool": row.tool,
                 "sar.action_id": action_id_for(key), "sar.run_id": row.run_id, "sar.attempt": row.dispatches + 1,
                 "sar.isolation": spec.isolation if spec else None, "sar.tool.version": spec.version if spec else None}
        started = time.monotonic()
        with self.telemetry.span(f"execute_tool {row.tool}", **attrs) as sp:
            o = self._execute(key)
            self._observe(sp, o)
            if row.state == "approved" and o.state != "approved":
                self.telemetry.dispatch_duration(o.tool, o.state, started)
            return o

    def reconcile(self, key: str) -> Outcome:
        """Settle an ``effect_unknown`` action through the tool's reconciler (see :meth:`_reconcile`)."""
        with self.telemetry.span("sar.reconcile", **{"sar.action_id": action_id_for(key)}) as sp:
            o = self._reconcile(key)
            self._observe(sp, o)
            sp.set("sar.reconcile.finding", {"succeeded": "applied", "approved": "not_applied"}.get(o.state, "unknown"))
            return o

    def resolve(self, key: str, *, credential: Any, applied: bool, result: Any = None,
                redispatch: bool = False) -> Outcome:
        """A human's verdict on an ``effect_unknown`` action (see :meth:`_resolve`)."""
        with self.telemetry.span("sar.resolve", **{"sar.action_id": action_id_for(key)}) as sp:
            o = self._resolve(key, credential=credential, applied=applied, result=result, redispatch=redispatch)
            self._observe(sp, o)
            return o

    def _observe(self, sp: Any, o: Outcome) -> None:
        sp.set("sar.tool", o.tool)
        sp.set("sar.state", o.state)
        sp.set("sar.frame.verdict", o.verification)
        self.telemetry.transition(o.tool, o.state)

    # -- proposals ---------------------------------------------------------------- #
    def _propose(self, *, run_id: str, principal_id: str, call_id: Any, tool: Any, arguments: Any,
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
        if idempotency_key is not None and (not isinstance(idempotency_key, str) or not idempotency_key
                                            or plain_json(idempotency_key) is None):
            raise MalformedProposal("idempotency_key must be a non-empty UTF-8 string")
        key = call_key(run_id, call_id) if idempotency_key is None else canonical_json({"key": idempotency_key})
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
                      created_at: float, deadline: float | None, salt: str | None = None) -> Action:
        frame = None
        if spec.frame is not None:
            declared = spec.frame(model)
            if not isinstance(declared, FrameSpec):
                raise TypeError("frame builder must return a FrameSpec")
            frame = declared.to_json()
        return Action(action_id=action_id_for(key), idempotency_key=key, actor=actor, run_id=run_id,
                      tool=spec.name, tool_version=spec.version, schema_digest=spec.schema_digest,
                      args=model.model_dump(mode="json"), authority=spec.effect.value, frame=frame,
                      created_at=created_at, deadline=deadline, salt=new_salt() if salt is None else salt)

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

    def _authenticate(self, credential: Any, action_digest: str | None) -> AuthContext | str:
        """The authenticated context for ``credential``, or a refusal reason."""
        if self.authenticator is None:
            return "no authenticator is configured; approvals are disabled"
        try:
            ctx = self.authenticator.authenticate(credential)
        except Exception as exc:  # a broken authenticator must never mean "authenticated"
            return f"authenticator raised {type(exc).__name__}"
        if not isinstance(ctx, AuthContext):
            return "authentication failed"
        if ctx.expires_at is not None and self.store.now() >= ctx.expires_at:
            return "credential has expired"
        if ctx.scope is not None and ctx.scope != action_digest:
            return "credential is scoped to a different action"
        return ctx

    def _refuse(self, row: CallRow, reason: str, **data: Any) -> ApprovalRefused:
        self.store.record(row.run_id, "approval.refused", {"reason": reason, **data}, call_key=row.key)
        return ApprovalRefused(reason)

    def _approve(self, key: str, *, credential: Any, action_digest: str) -> Outcome:
        """Approve exactly the action whose digest the approver was shown.

        ``credential`` is authenticated by the operator's :class:`Authenticator`; the
        resulting identity, not any string the caller supplies, is the approver.
        """
        row = self._get(key)
        ctx = self._authenticate(credential, row.action_digest)
        if isinstance(ctx, str):
            raise self._refuse(row, ctx, action_digest=action_digest)
        refusal = self._approval_problem(row, ctx.subject)
        if refusal is None and action_digest != row.action_digest:
            refusal = "approval is for a different action"
        if refusal is not None:
            raise self._refuse(row, refusal, approver=ctx.subject, action_digest=action_digest)
        record = {**self._approval_record(ctx.subject, action_digest, self.store.now()), "auth": ctx.record()}
        try:
            ok = self.store.transition(key, "awaiting_approval", "approved", approval=record,
                                       reason=f"approved by {ctx.subject}", unexpired_at=self.store.now(),
                                       consume_credential=ctx.record()["credential"],
                                       event={"approver": ctx.subject, "action_digest": action_digest,
                                              "approval_digest": approval_digest(record)})
        except CredentialReused:
            raise self._refuse(row, "this approval credential has already been used", approver=ctx.subject) from None
        if not ok:
            raise self._refuse(row, "action is no longer awaiting approval (or its window just elapsed)",
                               approver=ctx.subject)
        return Outcome.of(self._get(key))

    def _reject(self, key: str, *, credential: Any, reason: str = "") -> Outcome:
        row = self._get(key)
        ctx = self._authenticate(credential, row.action_digest)
        if isinstance(ctx, str):
            raise self._refuse(row, ctx)
        refusal = self._approval_problem(row, ctx.subject)
        if refusal is not None:
            raise self._refuse(row, refusal, approver=ctx.subject)
        if not self.store.transition(key, "awaiting_approval", "rejected", reason=reason or "rejected",
                                     consume_credential=ctx.record()["credential"],
                                     event={"approver": ctx.subject}):
            raise self._refuse(row, "action is no longer awaiting approval", approver=ctx.subject)
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

    def _cancel(self, key: str, *, reason: str = "cancelled") -> Outcome:
        """Cancel (or revoke the approval of) an action that has not been dispatched."""
        row = self._get(key)
        if row.state in ("awaiting_approval", "approved"):
            self.store.transition(key, row.state, "cancelled", reason=reason)
        return Outcome.of(self._get(key))

    # -- execution ---------------------------------------------------------------- #
    def _execute(self, key: str) -> Outcome:
        """Dispatch an approved action. Any other state returns the stored outcome without
        touching the tool."""
        row = self._get(key)
        if row.state != "approved":
            return Outcome.of(row)
        problem, spec, model, action = self._pre_execution_check(row)
        if problem is not None:
            self.store.transition(key, "approved", "cancelled", attempt=row.dispatches,
                                  reason=f"blocked at execution: {problem}")
            return Outcome.of(self._get(key))
        assert spec is not None and model is not None and action is not None
        stuck = self._stuck_workers()
        if stuck >= self.max_stuck_workers:
            # Timed-out tools that ignore cancellation still hold threads; don't pile up more.
            self.store.record(row.run_id, "dispatch.throttled", {"live_workers": stuck}, call_key=key)
            log.warning("not dispatching %s: %d workers from earlier dispatches are still running", key, stuck)
            return Outcome.of(row)

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
        # Fenced on the dispatch count read above, so an executor holding a stale row can't
        # claim an action that was dispatched, reconciled and re-approved in the meantime.
        if not self.store.transition(key, "approved", "executing", attempt=row.dispatches, dispatches=attempt,
                                     before=digests(before) if before is not None else None,
                                     event={"action_digest": row.action_digest, "attempt": attempt}):
            return Outcome.of(self._get(key))
        if before is not None:
            with self._mem:
                self._before[key] = (attempt, before)
        self._faults("after_claim", key)

        effectful = _effectful(spec)
        ctx = ToolContext(action_id=action.action_id, idempotency_key=key, attempt=attempt,
                          cancel=threading.Event())

        def finish(state: str, **fields: Any) -> None:
            try:
                try:
                    ok = self.store.transition(key, "executing", state, attempt=attempt, **fields)
                except Exception as exc:
                    # The result (or its frame report) could not be stored. Don't leave the action
                    # wedged in executing: record the honest fallback instead.
                    log.warning("could not record %s for %s (%s); recording the fallback", state, key,
                                type(exc).__name__)
                    fallback = "effect_unknown" if effectful else "failed"
                    ok = self.store.transition(key, "executing", fallback, attempt=attempt,
                                               reason=f"result could not be recorded ({type(exc).__name__})")
                if ok:
                    self._forget_snapshot(key)
                    if state == "effect_unknown":
                        log.warning("action %s: effect unknown (%s)", key, fields.get("reason", ""))
                else:
                    log.warning("discarding a late result for %s (attempt %d)", key, attempt)
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

        if spec.isolation == "process":
            self._dispatch_in_process(spec, model, action, key, attempt, effectful, finish)
            return Outcome.of(self._get(key))

        worker = threading.Thread(target=work, name=f"sar-tool-{spec.name}", daemon=True)
        with self._mem:
            self._live[key] = worker
        worker.start()
        worker.join(spec.timeout_s)
        if worker.is_alive():
            ctx.cancel.set()
            if self.store.transition(key, "executing", "effect_unknown" if effectful else "failed",
                                     attempt=attempt, reason=f"no result within {spec.timeout_s}s"):
                log.warning("action %s timed out; the worker thread cannot be killed and may still act", key)
        else:
            self._release_worker(key, worker)
        return Outcome.of(self._get(key))

    def _dispatch_in_process(self, spec: ToolSpec, model: BaseModel, action: Action, key: str, attempt: int,
                             effectful: bool, finish: Callable[..., None]) -> None:
        """Run one attempt in a fresh worker process; kill it on timeout.

        Killing the worker proves nothing about the external effect, so a timeout of an
        effectful tool is ``effect_unknown`` exactly as in thread mode. The worker never
        writes to the store; its single message is tagged with action id and attempt,
        and the outcome is recorded here, fenced by attempt.
        """
        from .isolation import Worker

        token = f"{action.action_id}#{attempt}"
        worker = Worker(token, spec.fn, spec.input_model, canonical_json(model.model_dump(mode="json")),
                        {"action_id": action.action_id, "idempotency_key": key, "attempt": attempt},
                        spec.takes_ctx)
        with self._mem:
            self._live[key] = worker
        self._faults("after_spawn", key)
        res = worker.wait(spec.timeout_s)
        self._release_worker(key, worker)
        self._faults("after_effect", key)
        unknown = "effect_unknown" if effectful else "failed"
        if res.kind == "ok":
            try:
                raw = json.loads(res.payload)
            except ValueError:
                raw = None
            out, error = validate_output(spec, raw)
            if out is None:
                finish(unknown if effectful else "output_rejected", reason=f"invalid output: {error}")
            else:
                finish("succeeded", result=out, result_digest=sha256_text(canonical_json(out)), reason="",
                       frame_result=self._frame_result(spec, action, key, attempt))
        elif res.kind == "not_applied":
            finish("failed", reason="tool reported its effect was not applied")
        elif res.kind == "raised":
            finish(unknown, reason=f"tool raised {res.payload}")
        elif res.kind == "bad_output":
            finish(unknown if effectful else "output_rejected", reason="invalid output: not plain JSON")
        elif res.kind == "timeout":
            finish(unknown, reason=f"no result within {spec.timeout_s}s; worker killed")
        elif res.kind == "wrong_token":
            self.store.record(action.run_id, "worker.message_rejected", {"attempt": attempt}, call_key=key)
            finish(unknown, reason="worker sent a message for a different attempt")
        else:  # died
            finish(unknown, reason=f"worker process died ({res.payload})")

    def _frame_result(self, spec: ToolSpec, action: Action, key: str, attempt: int) -> dict[str, Any] | None:
        if spec.observer is None or action.frame is None:
            return None
        with self._mem:
            cached = self._before.get(key)
        before = cached[1] if cached is not None and cached[0] == attempt else None
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
        if not self._approval_is_audited(row):
            return ("approval record is not backed by the audit log", *none)
        if (row.approval.get("kind") == "human"
                and self.store.now() >= float(row.approval.get("approved_at", 0)) + self.approval_ttl_s):
            return ("approval expired before dispatch", *none)
        if stored.deadline is not None and self.store.now() >= stored.deadline:
            return ("action deadline has passed", *none)
        model, _ = parse_input(spec, stored.args)  # the tool's schema may have changed since
        if model is None or model.model_dump(mode="json") != stored.args:
            return ("stored arguments no longer validate", *none)
        try:
            current = self._build_action(spec, model, key=row.key, actor=stored.actor, run_id=stored.run_id,
                                         created_at=stored.created_at, deadline=stored.deadline,
                                         salt=stored.salt)
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

    # -- in-memory bookkeeping (thread-safe) ----------------------------------- #
    def _stuck_workers(self) -> int:
        """Workers still running; dead ones are pruned so the map can't grow without bound."""
        with self._mem:
            for k in [k for k, w in self._live.items() if not w.is_alive()]:
                del self._live[k]
            return len(self._live)

    def _release_worker(self, key: str, worker: Any) -> None:
        with self._mem:
            if self._live.get(key) is worker:  # never evict a newer attempt's worker
                del self._live[key]

    def _worker_alive(self, key: str) -> bool:
        with self._mem:
            worker = self._live.get(key)
        return worker is not None and worker.is_alive()

    def _forget_snapshot(self, key: str) -> None:
        with self._mem:
            self._before.pop(key, None)

    def _approval_is_audited(self, row: CallRow) -> bool:
        """The latest ``call.approved`` event must carry this exact approval record's digest."""
        latest = None
        for e in self.store.events(call_key=row.key, kind="call.approved"):
            latest = e
        return (latest is not None and row.approval is not None
                and latest.data.get("approval_digest") == approval_digest(row.approval))

    # -- uncertain outcomes ------------------------------------------------------- #
    def _reconcile(self, key: str) -> Outcome:
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
        if self._worker_alive(key):
            # The timed-out dispatch is still running here and could yet act; asking now
            # could get "not applied" just before it applies. Wait for it to finish.
            self.store.record(row.run_id, "reconcile.deferred", {"why": "dispatch still running"}, call_key=key)
            return Outcome.of(row)
        reconciler = spec.reconciler
        attempt = row.dispatches
        ctx = ToolContext(action_id=action.action_id, idempotency_key=key, attempt=attempt,
                          cancel=threading.Event())
        finding = _bounded(lambda: reconciler(model, ctx), spec.timeout_s)
        self._faults("after_reconcile", key)
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
            else:
                self._forget_snapshot(key)
                log.info("action %s reconciled: applied", key)
        elif isinstance(finding, NotApplied):
            if not self.store.transition(key, "effect_unknown", "approved", attempt=attempt,
                                         reason="reconciled: effect not applied; may be dispatched again",
                                         event={"reconciled": "not_applied", "attempt": attempt,
                                                "approval_digest": approval_digest(row.approval or {})}):
                self.store.record(row.run_id, "reconcile.stale", {"attempt": attempt}, call_key=key)
            else:
                self._forget_snapshot(key)
                log.info("action %s reconciled: not applied; it may be dispatched again", key)
        else:
            why = finding.reason if isinstance(finding, Unknown) else f"reconciler returned {type(finding).__name__}"
            self.store.record(row.run_id, "reconcile.unknown", {"why": (why or "undecided")[:200]}, call_key=key)
        return Outcome.of(self._get(key))

    def _resolve(self, key: str, *, credential: Any, applied: bool, result: Any = None,
                redispatch: bool = False) -> Outcome:
        """A human's verdict on an ``effect_unknown`` action, for tools with no reconciler.

        The authenticated subject of ``credential`` must be an approver other than the
        requester. ``applied=False`` ends the action as ``failed`` unless
        ``redispatch=True``, which re-approves it in the resolver's name.
        """
        row = self._get(key)
        if row.state != "effect_unknown":
            hint = " (if the runtime crashed, recover() moves it to effect_unknown)" if row.state == "executing" else ""
            raise ApprovalRefused(f"action is {row.state}, not effect_unknown{hint}")
        ctx = self._authenticate(credential, row.action_digest)
        refusal = ctx if isinstance(ctx, str) else approval_refusal(self._principals.get(ctx.subject), row.principal)
        if refusal is not None:
            self.store.record(row.run_id, "resolve.refused", {"reason": refusal}, call_key=key)
            raise ApprovalRefused(refusal)
        assert isinstance(ctx, AuthContext)
        by = ctx.subject
        if self._worker_alive(key):
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
            try:
                ok = self.store.transition(
                    key, "effect_unknown", "succeeded", attempt=attempt, result=out,
                    result_digest=sha256_text(canonical_json(out)) if out is not None else None,
                    reason=f"resolved by {by}: effect was applied", frame_result=frame,
                    consume_credential=ctx.record()["credential"],
                    event={"resolved_by": by, "applied": True, "attempt": attempt})
            except CredentialReused:
                raise ApprovalRefused("this approval credential has already been used") from None
        elif redispatch:
            record = {**self._approval_record(by, row.action_digest, self.store.now()), "auth": ctx.record()}
            try:
                ok = self.store.transition(
                    key, "effect_unknown", "approved", attempt=attempt, approval=record,
                    reason=f"resolved by {by}: effect not applied; re-approved",
                    consume_credential=ctx.record()["credential"],
                    event={"resolved_by": by, "applied": False, "redispatch": True, "attempt": attempt,
                           "approval_digest": approval_digest(record)})
            except CredentialReused:
                raise ApprovalRefused("this approval credential has already been used") from None
        else:
            try:
                ok = self.store.transition(key, "effect_unknown", "failed", attempt=attempt,
                                           reason=f"resolved by {by}: effect not applied",
                                           consume_credential=ctx.record()["credential"],
                                           event={"resolved_by": by, "applied": False, "attempt": attempt})
            except CredentialReused:
                raise ApprovalRefused("this approval credential has already been used") from None
        if not ok:
            raise ApprovalRefused("the action changed while it was being resolved")
        self._forget_snapshot(key)
        return Outcome.of(self._get(key))

    # -- recovery ----------------------------------------------------------------- #
    def recover(self) -> list[str]:
        """After a crash: actions left ``executing`` become ``effect_unknown`` (or ``failed``
        for READ tools, which have no effect). Nothing is re-dispatched automatically.

        Runs automatically when a Runtime is constructed (``recover_on_start``). Call it by
        hand only when no worker of this store is running.
        """
        moved = []
        for row in self.store.calls(state="executing"):
            target = "effect_unknown" if _effectful(self.registry.get(row.tool)) else "failed"
            if self.store.transition(row.key, "executing", target, reason="runtime stopped during execution"):
                moved.append(row.key)
        return moved

    # -- receipts ----------------------------------------------------------------- #
    def receipt(self, key: str, *, signer: Any = None, signing_key: bytes | None = None,
                key_id: str = "default") -> dict[str, Any]:
        """A machine-verifiable Agent Receipt for one action (see ``receipts``)."""
        from .receipts import build_receipt

        with self.telemetry.span("sar.receipt", **{"sar.action_id": action_id_for(key)}) as sp:
            r = build_receipt(self.store, key, signer=signer, signing_key=signing_key, key_id=key_id)
            sp.set("sar.outcome", r["outcome"])
            sp.set("sar.signature.alg", (r.get("signature") or {}).get("alg"))
            return r

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
