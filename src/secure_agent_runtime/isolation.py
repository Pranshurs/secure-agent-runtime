"""Process isolation: run one dispatch in a fresh worker process that can be killed.

The worker is started with the ``spawn`` method (no inherited threads or locks), gets
the tool function and the validated arguments, runs the tool, and sends back exactly
one message tagged with the action id and attempt number. It never touches the store:
the runtime records the outcome, fenced by attempt, in its own process.

On Linux the worker asks the kernel to SIGKILL it if the runtime dies
(``PR_SET_PDEATHSIG``), so a crashed runtime does not leave an orphan that could still
act after recovery has reconciled. Other platforms have no equivalent; there an orphan
worker can outlive the runtime (documented in the threat model).
"""

from __future__ import annotations

import ctypes
import ctypes.util
import json
import multiprocessing
import os
import signal
import sys
import threading
from dataclasses import dataclass
from multiprocessing.connection import Connection
from typing import Any

from pydantic import BaseModel

_CTX = multiprocessing.get_context("spawn")
PR_SET_PDEATHSIG = 1


def _die_with_parent(parent_pid: int) -> None:
    if not sys.platform.startswith("linux"):
        return
    libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6", use_errno=True)
    libc.prctl(PR_SET_PDEATHSIG, signal.SIGKILL)
    if os.getppid() != parent_pid:  # the runtime died before prctl took effect
        os._exit(1)


def _worker(conn: Connection, parent_pid: int, token: str, fn: Any, input_model: type[BaseModel],
            args_json: str, ctx_fields: dict[str, Any], takes_ctx: bool) -> None:
    from .contracts import EffectNotApplied, ToolContext  # imported in the child

    _die_with_parent(parent_pid)
    try:
        model = input_model.model_validate_json(args_json, strict=True)
        ctx = ToolContext(cancel=threading.Event(), **ctx_fields)
        raw = fn(model, ctx) if takes_ctx else fn(model)
        if isinstance(raw, BaseModel):
            raw = raw.model_dump(mode="json")
        try:
            payload = json.dumps(raw, allow_nan=False)
        except Exception as exc:
            conn.send(("bad_output", token, type(exc).__name__))
        else:
            conn.send(("ok", token, payload))
    except EffectNotApplied:
        conn.send(("not_applied", token, ""))
    except BaseException as exc:  # report the type only; messages may hold secrets
        conn.send(("raised", token, type(exc).__name__))
    finally:
        conn.close()


@dataclass
class WorkerResult:
    kind: str  # ok | not_applied | raised | bad_output | timeout | died | wrong_token
    payload: str = ""


class Worker:
    """One spawned process for one attempt."""

    def __init__(self, token: str, fn: Any, input_model: type[BaseModel], args_json: str,
                 ctx_fields: dict[str, Any], takes_ctx: bool) -> None:
        self.token = token
        self._recv, send = _CTX.Pipe(duplex=False)
        self.process = _CTX.Process(
            target=_worker, name=f"sar-worker-{token}", daemon=True,
            args=(send, os.getpid(), token, fn, input_model, args_json, ctx_fields, takes_ctx))
        self.process.start()
        send.close()

    def is_alive(self) -> bool:
        return self.process.is_alive()

    def wait(self, timeout_s: float) -> WorkerResult:
        try:
            if not self._recv.poll(timeout_s):
                self.kill()
                return WorkerResult("timeout")
            kind, token, payload = self._recv.recv()
        except (EOFError, OSError):
            self.process.join(5)
            return WorkerResult("died", f"exit code {self.process.exitcode}")
        finally:
            self._recv.close()
        self.process.join(5)
        if token != self.token:  # a message for some other attempt is never accepted
            return WorkerResult("wrong_token")
        return WorkerResult(kind, payload)

    def kill(self) -> None:
        if self.process.is_alive():
            self.process.kill()
        self.process.join(5)
