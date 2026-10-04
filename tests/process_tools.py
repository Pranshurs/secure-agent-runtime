"""Module-level tools for process-isolation tests (a worker process must import them)."""

from __future__ import annotations

import os

from pydantic import BaseModel, ConfigDict

from secure_agent_runtime.contracts import EffectNotApplied


class In(BaseModel):
    model_config = ConfigDict(extra="forbid")
    mode: str


class Out(BaseModel):
    model_config = ConfigDict(extra="forbid")
    ok: bool


def tool(args: In) -> object:
    if args.mode == "exit":
        os._exit(7)  # the worker dies mid-call: no message, no result
    if args.mode == "raise":
        raise RuntimeError("secret detail that must not leak")
    if args.mode == "not_applied":
        raise EffectNotApplied("declined")
    if args.mode == "unserialisable":
        return {"ok": object()}
    if args.mode == "invalid":
        return {"ok": "yes"}
    return Out(ok=True)
