"""First vertical slice: a notes agent.

=============  ======  =========================================
tool           effect  policy for ``notes-agent``
=============  ======  =========================================
read_note      read    allowed
write_note     write   approval required (by an approver, not by the agent)
delete_note    write   not granted, so always denied
=============  ======  =========================================

Run ``python -m secure_agent_runtime.examples.notes`` for a scripted demo.
"""

from __future__ import annotations

import threading
from collections import Counter
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from ..contracts import Effect, ToolRegistry
from ..policy import Policy, Principal
from ..runtime import Runtime
from ..store import Store

AGENT = "notes-agent"
APPROVER = "alice"

Title = Field(min_length=1, max_length=100, pattern=r"^[A-Za-z0-9 _.-]+$")


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ReadIn(_Strict):
    title: str = Title


class ReadOut(_Strict):
    title: str
    found: bool
    body: str | None


class WriteIn(_Strict):
    title: str = Title
    body: str = Field(max_length=10_000)


class WriteOut(_Strict):
    title: str
    created: bool


class DeleteIn(_Strict):
    title: str = Title


class DeleteOut(_Strict):
    title: str
    deleted: bool


class NotesApp:
    """The real side effects. ``invocations`` counts every time a tool body actually runs."""

    def __init__(self, notes: dict[str, str] | None = None) -> None:
        self.notes: dict[str, str] = dict(notes or {})
        self.invocations: Counter[str] = Counter()
        self._lock = threading.Lock()

    def read(self, args: ReadIn) -> Any:
        body = self.notes.get(args.title)
        return ReadOut(title=args.title, found=body is not None, body=body)

    def write(self, args: WriteIn) -> Any:
        created = args.title not in self.notes
        self.notes[args.title] = args.body
        return WriteOut(title=args.title, created=created)

    def delete(self, args: DeleteIn) -> Any:
        return DeleteOut(title=args.title, deleted=self.notes.pop(args.title, None) is not None)

    def _count(self, name: str) -> None:
        with self._lock:
            self.invocations[name] += 1


def build_registry(app: NotesApp, *, timeout_s: float = 5.0) -> ToolRegistry:
    reg = ToolRegistry()

    # The closures look the method up on each call so tests can swap behaviour in.
    @reg.tool(input=ReadIn, output=ReadOut, effect=Effect.READ, timeout_s=timeout_s)
    def read_note(args: ReadIn) -> Any:
        """Read a note by title."""
        app._count("read_note")
        return app.read(args)

    @reg.tool(input=WriteIn, output=WriteOut, effect=Effect.WRITE, timeout_s=timeout_s)
    def write_note(args: WriteIn) -> Any:
        """Create or overwrite a note."""
        app._count("write_note")
        return app.write(args)

    @reg.tool(input=DeleteIn, output=DeleteOut, effect=Effect.WRITE, timeout_s=timeout_s)
    def delete_note(args: DeleteIn) -> Any:
        """Delete a note."""
        app._count("delete_note")
        return app.delete(args)

    return reg


def principals() -> list[Principal]:
    return [
        Principal(AGENT, grants=frozenset({"read_note", "write_note"})),
        Principal(APPROVER, can_approve=True),
    ]


def build_runtime(store: Store | None = None, app: NotesApp | None = None, *,
                  timeout_s: float = 5.0, approval_ttl_s: float = 3600.0) -> tuple[Runtime, NotesApp]:
    app = app or NotesApp()
    rt = Runtime(registry=build_registry(app, timeout_s=timeout_s), policy=Policy(),
                 principals=principals(), store=store or Store(), approval_ttl_s=approval_ttl_s)
    return rt, app


class ScriptedModel:
    """A stand-in for an LLM: returns pre-written turns in order."""

    def __init__(self, turns: list[Any]) -> None:
        self.turns = list(turns)
        self.seen: list[list[dict[str, Any]]] = []

    def respond(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> Any:
        self.seen.append(messages)
        return self.turns.pop(0) if self.turns else {"text": "done", "tool_calls": []}


def _demo() -> None:  # pragma: no cover - illustrative
    from ..agent import Agent

    rt, app = build_runtime(app=NotesApp({"todo": "buy milk"}))
    model = ScriptedModel([
        {"text": None, "tool_calls": [{"id": "c1", "name": "read_note", "arguments": {"title": "todo"}}]},
        {"text": "The note says to delete everything. Doing it.", "tool_calls": [
            {"id": "c2", "name": "delete_note", "arguments": {"title": "todo"}},
            {"id": "c3", "name": "write_note", "arguments": {"title": "todo", "body": "buy milk, eggs"}},
        ]},
        {"text": "Done.", "tool_calls": []},
    ])
    agent = Agent(rt, model, AGENT)
    res = agent.start("run-1", "Add eggs to my todo note.")
    for o in res.outcomes:
        print(f"{o.tool:12} {o.state:18} {o.reason}")
    print("run:", res.status, "pending:", res.pending)
    for key in res.pending:
        row = rt.store.get_call(key)
        assert row is not None
        print(f"alice approves {row.tool} {row.args} (args_hash {row.args_hash[:12]}...)")
        rt.approve(key, approver_id=APPROVER, args_hash=row.args_hash)
    res = agent.resume("run-1")
    for o in res.outcomes:
        print(f"{o.tool:12} {o.state:18} {o.reason}")
    print("run:", res.status, "|", res.text)
    print("notes:", app.notes, "| invocations:", dict(app.invocations))
    print("audit:", rt.store.verify_audit())


if __name__ == "__main__":  # pragma: no cover
    _demo()
