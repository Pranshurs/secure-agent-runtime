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


class LateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    mode: str  # "child": a child process; "thread": a thread left running after returning
    dir: str


def act_later(d: str) -> None:
    """Say it is running, then act only once the test creates <d>/release."""
    import time

    open(os.path.join(d, "started"), "w").close()
    for _ in range(600):
        if os.path.exists(os.path.join(d, "release")):
            open(os.path.join(d, "late_effect"), "w").close()
            return
        time.sleep(0.05)


def late_tool(args: LateIn) -> object:
    import subprocess  # nosec B404 - test helper
    import sys
    import threading
    import time

    if args.mode == "child":  # a child in the worker's process group, then the tool hangs
        code = ("import sys; sys.path[:0] = sys.argv[2:]; "
                "from tests.process_tools import act_later; act_later(sys.argv[1])")
        subprocess.Popen([sys.executable, "-c", code, args.dir, *sys.path])  # nosec B603
        time.sleep(60)
    threading.Thread(target=act_later, args=(args.dir,)).start()  # non-daemon: outlives the reply
    return Out(ok=True)
