"""A minimal agent loop on top of :class:`Runtime`.

The model is anything with ``respond(messages, tools) -> dict``. The returned dict is
treated as untrusted data in a provider-neutral shape::

    {"text": "...", "tool_calls": [{"id": "...", "name": "...", "arguments": {...}}]}

The loop never interprets the text. Each tool call goes through ``Runtime.propose`` and,
when approved, ``Runtime.execute``. A call that needs a human pauses the run. A call whose
outcome is uncertain (``effect_unknown``) is reconciled, and dispatched again only if
reconciliation shows its effect did not happen.

Conversation history is held in memory by this object. The call ledger and audit log are
durable (they live in the :class:`Store`); the transcript is not, yet.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

from .runtime import MalformedProposal, Outcome, ReplayDivergence, Runtime


class Model(Protocol):
    def respond(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> Any: ...


@dataclass
class RunResult:
    status: str  # completed | awaiting_approval | malformed_model_output | max_steps
    text: str | None = None
    pending: list[str] = field(default_factory=list)
    outcomes: list[Outcome] = field(default_factory=list)


@dataclass
class _Run:
    messages: list[dict[str, Any]]
    waiting: list[tuple[str, str]] = field(default_factory=list)  # (model call id, key)
    steps: int = 0
    finished: bool = False


class Agent:
    def __init__(self, runtime: Runtime, model: Model, principal_id: str, *, max_steps: int = 8,
                 max_calls_per_turn: int = 16, max_dispatches: int = 2) -> None:
        principal = runtime.principal(principal_id)
        if principal is None:
            raise KeyError(f"unknown principal {principal_id!r}")
        self.runtime = runtime
        self.model = model
        self.principal = principal
        self.max_steps = max_steps
        self.max_calls_per_turn = max_calls_per_turn
        self.max_dispatches = max_dispatches
        self._runs: dict[str, _Run] = {}

    def start(self, run_id: str, user_message: str) -> RunResult:
        if run_id in self._runs:
            raise ValueError(f"run {run_id!r} already started")
        self._runs[run_id] = _Run(messages=[{"role": "user", "content": user_message}])
        self.runtime.store.record(run_id, "run.started", {"principal": self.principal.id})
        return self._loop(run_id)

    def resume(self, run_id: str) -> RunResult:
        """Continue after approvals or rejections. Still-pending calls keep the run paused."""
        run = self._runs[run_id]
        if run.finished:
            raise ValueError(f"run {run_id!r} has already finished")
        self.runtime.expire_pending()
        still, outcomes = [], []
        for model_call_id, key in run.waiting:
            outcome = self._drive(key)
            if outcome.state == "awaiting_approval":
                still.append((model_call_id, key))
                continue
            outcomes.append(outcome)
            run.messages.append({"role": "tool", "call_id": model_call_id, "content": outcome.for_model()})
        run.waiting = still
        if still:
            return RunResult("awaiting_approval", pending=[k for _, k in still], outcomes=outcomes)
        result = self._loop(run_id)
        result.outcomes = outcomes + result.outcomes
        return result

    def _loop(self, run_id: str) -> RunResult:
        result = self._steps(run_id)
        if result.status != "awaiting_approval":
            self._runs[run_id].finished = True
        return result

    def _steps(self, run_id: str) -> RunResult:
        run = self._runs[run_id]
        outcomes: list[Outcome] = []
        tools = self.runtime.registry.schemas(self.principal.grants)
        while run.steps < self.max_steps:
            run.steps += 1
            turn = _parse_turn(self.model.respond(list(run.messages), tools))
            if turn is None or len(turn[1]) > self.max_calls_per_turn:
                self.runtime.store.record(run_id, "model.malformed_output", {"step": run.steps})
                return RunResult("malformed_model_output", outcomes=outcomes)
            text, calls = turn
            run.messages.append({"role": "assistant", "text": text, "tool_calls": calls})
            if not calls:
                self.runtime.store.record(run_id, "run.completed", {"steps": run.steps})
                return RunResult("completed", text=text, outcomes=outcomes)
            for call in calls:
                try:
                    outcome = self.runtime.propose(run_id=run_id, principal_id=self.principal.id,
                                                   call_id=call["id"], tool=call["name"],
                                                   arguments=call["arguments"])
                except (MalformedProposal, ReplayDivergence) as exc:
                    # ReplayDivergence: the model reused an earlier call id for a different call.
                    self.runtime.store.record(run_id, "model.malformed_output",
                                              {"step": run.steps, "error": type(exc).__name__})
                    return RunResult("malformed_model_output", outcomes=outcomes)
                outcome = self._drive(outcome.key)
                if outcome.state == "awaiting_approval":
                    run.waiting.append((call["id"], outcome.key))
                    continue
                outcomes.append(outcome)
                run.messages.append({"role": "tool", "call_id": call["id"], "content": outcome.for_model()})
            if run.waiting:
                return RunResult("awaiting_approval", pending=[k for _, k in run.waiting], outcomes=outcomes)
        self.runtime.store.record(run_id, "run.max_steps", {"steps": run.steps})
        return RunResult("max_steps", outcomes=outcomes)


    def _drive(self, key: str) -> Outcome:
        """Execute; if the outcome is uncertain, reconcile, and dispatch again only when
        reconciliation established that the effect did not happen."""
        outcome = self.runtime.execute(key)
        for _ in range(self.max_dispatches - 1):
            if outcome.state != "effect_unknown":
                break
            outcome = self.runtime.reconcile(key)
            if outcome.state == "approved":
                outcome = self.runtime.execute(key)
        return outcome


def _parse_turn(raw: Any) -> tuple[str | None, list[dict[str, Any]]] | None:
    """Shape-check a model turn. Returns None if it is not even a well-formed turn.

    Only the envelope is checked here; tool names and arguments are validated by the
    runtime, which records malformed ones as ``invalid`` calls.
    """
    if not isinstance(raw, dict):
        return None
    text = raw.get("text")
    calls = raw.get("tool_calls", [])
    if text is not None and not isinstance(text, str):
        return None
    if not isinstance(calls, list):
        return None
    seen: set[str] = set()
    parsed = []
    for c in calls:
        if not isinstance(c, dict) or set(c) - {"id", "name", "arguments"}:
            return None
        cid = c.get("id")
        if not isinstance(cid, str) or not cid or cid in seen:
            return None
        seen.add(cid)
        parsed.append({"id": cid, "name": c.get("name"), "arguments": c.get("arguments")})
    return text, parsed
