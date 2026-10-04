"""The governor: the only path from a model's proposed tool call to the tool itself.

The model proposes; the runtime disposes::

    propose()  -> invalid | denied | pending_approval | approved
    approve()  pending_approval -> approved        (bound to args_hash, never by the requester)
    execute()  approved -> executing -> succeeded | failed | timed_out | output_rejected
    recover()  executing -> outcome_unknown        (after a crash; never re-executed)

Every decision is taken from the principal directory, the tool registry and the policy,
all supplied by the operator, plus the validated arguments. Model text never reaches
:meth:`Policy.decide`.
"""

from __future__ import annotations

import threading
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from .contracts import (
    ToolRegistry,
    args_hash,
    canonical_json,
    invoke,
    request_hash,
    validate_input,
    validate_output,
)
from .policy import Policy, Principal, Verdict, approval_refusal
from .store import CallRow, Store

POLICY_APPROVER = "policy:allow"


class RuntimeErrorBase(Exception):
    pass


class MalformedProposal(RuntimeErrorBase):
    """The proposal can't even be keyed (e.g. a missing or non-string call id)."""


class ReplayDivergence(RuntimeErrorBase):
    """The same (run_id, call_id) was proposed again with different content."""


class ApprovalRefused(RuntimeErrorBase):
    pass


@dataclass(frozen=True)
class Outcome:
    key: str
    tool: str
    state: str
    args_hash: str
    reason: str = ""
    result: dict[str, Any] | None = None

    @classmethod
    def of(cls, row: CallRow) -> Outcome:
        return cls(key=row.key, tool=row.tool, state=row.state, args_hash=row.args_hash,
                   reason=row.reason, result=row.result)

    def for_model(self) -> dict[str, Any]:
        """What the model is told. Only a succeeded call carries tool output.

        A rejected output's validation details (which can include field names chosen by
        the tool) stay in the store; the model gets a fixed message.
        """
        if self.state == "succeeded":
            return {"status": self.state, "result": self.result}
        if self.state == "output_rejected":
            return {"status": self.state, "error": "tool output failed validation"}
        return {"status": self.state, "error": self.reason}


def call_key(run_id: str, call_id: str) -> str:
    # JSON-encoded pair, so ("a:b", "c") and ("a", "b:c") can't collide.
    return canonical_json([run_id, call_id])


class Runtime:
    def __init__(self, *, registry: ToolRegistry, policy: Policy, principals: Iterable[Principal],
                 store: Store, approval_ttl_s: float = 3600.0) -> None:
        if approval_ttl_s <= 0:
            raise ValueError("approval_ttl_s must be positive")
        self.registry = registry
        self.policy = policy
        self.store = store
        self.approval_ttl_s = approval_ttl_s
        self._principals: dict[str, Principal] = {}
        for p in principals:
            if p.id in self._principals or p.id == POLICY_APPROVER:
                raise ValueError(f"duplicate or reserved principal id {p.id!r}")
            self._principals[p.id] = p

    def principal(self, principal_id: str) -> Principal | None:
        return self._principals.get(principal_id)

    # -- proposals ---------------------------------------------------------------- #
    def propose(self, *, run_id: str, principal_id: str, call_id: Any, tool: Any,
                arguments: Any) -> Outcome:
        principal = self._principals.get(principal_id)
        if principal is None:
            raise KeyError(f"unknown principal {principal_id!r}")
        if not isinstance(run_id, str) or not run_id:
            raise MalformedProposal("run_id must be a non-empty string")
        if not isinstance(call_id, str) or not call_id:
            raise MalformedProposal("call_id must be a non-empty string")
        key = call_key(run_id, call_id)
        rh = request_hash(tool, arguments)
        # Classify first and let the primary key decide: a replay (or a racing duplicate)
        # fails the insert and is answered from the stored record instead.
        state, reason, args, ah, tool_name = self._classify(principal, tool, arguments)
        inserted = self.store.insert_call(
            key=key, run_id=run_id, call_id=call_id, principal=principal_id, tool=tool_name,
            args=args, args_hash=ah, request_hash=rh, state=state, reason=reason,
            expires_at=self.store.now() + self.approval_ttl_s if state == "pending_approval" else None,
            approved_by=POLICY_APPROVER if state == "approved" else None,
            approved_hash=ah if state == "approved" else None,
            event={"principal": principal_id, "tool": tool_name, "args_hash": ah, "request_hash": rh},
        )
        row = self.store.get_call(key)
        assert row is not None
        if not inserted:
            return self._replay(row, principal_id, rh)
        return Outcome.of(row)

    def _classify(self, principal: Principal, tool: Any, arguments: Any) -> tuple[str, str, Any, str, str]:
        tool_name = tool if isinstance(tool, str) else repr(tool)
        stored_args = arguments
        try:
            canonical_json(arguments)
        except (TypeError, ValueError):
            stored_args = {"_unserialisable": type(arguments).__name__}
        raw_hash = request_hash(tool, arguments)
        spec = self.registry.get(tool) if isinstance(tool, str) else None
        if spec is None:
            return "invalid", f"unknown tool {tool_name!r}", stored_args, raw_hash, tool_name
        args, error = validate_input(spec, arguments)
        if args is None:
            return "invalid", f"invalid arguments: {error}", stored_args, raw_hash, tool_name
        ah = args_hash(spec.name, args)
        decision = self.policy.decide(principal, spec, args)
        if decision.verdict is Verdict.DENY:
            return "denied", f"{decision.rule}: {decision.reason}", args, ah, tool_name
        if decision.verdict is Verdict.REQUIRE_APPROVAL:
            return "pending_approval", decision.reason, args, ah, tool_name
        if decision.verdict is Verdict.ALLOW:
            return "approved", decision.reason, args, ah, tool_name
        raise AssertionError(f"unhandled verdict {decision.verdict!r}")  # pragma: no cover

    def _replay(self, row: CallRow, principal_id: str, rh: str) -> Outcome:
        if row.request_hash != rh or row.principal != principal_id:
            self.store.record(row.run_id, "call.replay_divergence",
                              {"stored_request_hash": row.request_hash, "new_request_hash": rh,
                               "principal": principal_id}, call_key=row.key)
            raise ReplayDivergence(f"call {row.key} was already proposed with different content")
        self.store.record(row.run_id, "call.replayed", {"state": row.state}, call_key=row.key)
        return Outcome.of(row)

    # -- approvals ---------------------------------------------------------------- #
    def approve(self, key: str, *, approver_id: str, args_hash: str) -> Outcome:
        """Approve exactly the arguments whose hash the approver was shown."""
        row = self._get(key)
        refusal = self._approval_problem(row, approver_id)
        if refusal is None and args_hash != row.args_hash:
            refusal = "approval is for different arguments"
        if refusal is not None:
            self.store.record(row.run_id, "approval.refused",
                              {"approver": approver_id, "reason": refusal, "args_hash": args_hash},
                              call_key=key)
            raise ApprovalRefused(refusal)
        if not self.store.transition(key, "pending_approval", "approved", approved_by=approver_id,
                                     approved_hash=args_hash, reason=f"approved by {approver_id}",
                                     event={"approver": approver_id, "args_hash": args_hash}):
            raise ApprovalRefused("call is no longer pending approval")
        return Outcome.of(self._get(key))

    def reject(self, key: str, *, approver_id: str, reason: str = "") -> Outcome:
        row = self._get(key)
        refusal = self._approval_problem(row, approver_id)
        if refusal is not None:
            self.store.record(row.run_id, "approval.refused", {"approver": approver_id, "reason": refusal},
                              call_key=key)
            raise ApprovalRefused(refusal)
        if not self.store.transition(key, "pending_approval", "rejected", reason=reason or "rejected",
                                     event={"approver": approver_id}):
            raise ApprovalRefused("call is no longer pending approval")
        return Outcome.of(self._get(key))

    def _approval_problem(self, row: CallRow, approver_id: str) -> str | None:
        if row.state != "pending_approval":
            return f"call is {row.state}, not pending approval"
        if row.expires_at is not None and self.store.now() >= row.expires_at:
            self.store.transition(row.key, "pending_approval", "expired", reason="approval window elapsed")
            return "approval window elapsed"
        return approval_refusal(self._principals.get(approver_id), row.principal)

    def expire_pending(self) -> list[str]:
        now, expired = self.store.now(), []
        for row in self.store.calls(state="pending_approval"):
            if row.expires_at is not None and now >= row.expires_at and self.store.transition(
                    row.key, "pending_approval", "expired", reason="approval window elapsed"):
                expired.append(row.key)
        return expired

    def cancel(self, key: str, *, reason: str = "cancelled") -> Outcome:
        row = self._get(key)
        if row.state in ("pending_approval", "approved"):
            self.store.transition(key, row.state, "cancelled", reason=reason)
        return Outcome.of(self._get(key))

    # -- execution ---------------------------------------------------------------- #
    def execute(self, key: str) -> Outcome:
        """Run an approved call at most once. Any other state returns the stored outcome."""
        row = self._get(key)
        if row.state != "approved":
            return Outcome.of(row)
        problem, args = self._pre_execution_check(row)
        if problem is not None:
            self.store.transition(key, "approved", "cancelled", reason=f"blocked at execution: {problem}")
            return Outcome.of(self._get(key))
        spec = self.registry.get(row.tool)
        assert spec is not None and args is not None
        # The executing event is committed before the tool is invoked, so the audit log can
        # over-count invocations after a crash (see recover()) but can never under-count.
        if not self.store.transition(key, "approved", "executing", event={"args_hash": row.args_hash}):
            return Outcome.of(self._get(key))

        cancel = threading.Event()

        def finish(state: str, **fields: Any) -> None:
            if not self.store.transition(key, "executing", state, **fields):
                self.store.record(row.run_id, "call.late_result_discarded", {"would_have_been": state},
                                  call_key=key)

        def work() -> None:
            try:
                raw = invoke(spec, args, cancel)
            except Exception as exc:
                finish("failed", reason=f"tool raised {type(exc).__name__}")
                return
            out, error = validate_output(spec, raw)
            if out is None:
                finish("output_rejected", reason=f"invalid output: {error}")
            else:
                finish("succeeded", result=out, reason="")

        worker = threading.Thread(target=work, name=f"sar-tool-{spec.name}", daemon=True)
        worker.start()
        worker.join(spec.timeout_s)
        if worker.is_alive():
            cancel.set()
            self.store.transition(key, "executing", "timed_out",
                                  reason=f"no result within {spec.timeout_s}s; effect unknown")
        return Outcome.of(self._get(key))

    def _pre_execution_check(self, row: CallRow) -> tuple[str | None, dict[str, Any] | None]:
        """Re-check everything at the last moment, from stored facts and current config.

        Returns (problem, None) or (None, args to invoke with).
        """
        spec = self.registry.get(row.tool)
        principal = self._principals.get(row.principal)
        if spec is None or principal is None:
            return "tool or principal no longer registered", None
        if args_hash(row.tool, row.args) != row.args_hash:
            return "stored arguments do not match their hash", None
        if row.approved_hash != row.args_hash:
            return "approval does not match the stored arguments", None
        args, _ = validate_input(spec, row.args)  # the tool's schema may have changed since
        if args is None:
            return "stored arguments no longer validate", None
        decision = self.policy.decide(principal, spec, args)
        if decision.verdict is Verdict.DENY:
            return f"policy now denies: {decision.reason}", None
        if decision.verdict is Verdict.REQUIRE_APPROVAL:
            # POLICY_APPROVER is reserved and never in the directory, so a call that was
            # auto-allowed but now needs approval is refused here too.
            refusal = approval_refusal(self._principals.get(row.approved_by or ""), row.principal)
            if refusal is not None:
                return f"approval no longer valid: {refusal}", None
        return None, args

    # -- recovery ----------------------------------------------------------------- #
    def recover(self) -> list[str]:
        """Mark calls left in ``executing`` by a crash as ``outcome_unknown``.

        Call this only at startup, before any worker of this store is running. Such calls
        are never re-executed automatically: the tool may or may not have taken effect.
        """
        return [row.key for row in self.store.calls(state="executing")
                if self.store.transition(row.key, "executing", "outcome_unknown",
                                         reason="runtime stopped during execution; effect unknown")]

    def _get(self, key: str) -> CallRow:
        row = self.store.get_call(key)
        if row is None:
            raise KeyError(f"no call {key!r}")
        return row
