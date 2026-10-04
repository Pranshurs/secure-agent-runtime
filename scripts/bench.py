#!/usr/bin/env python3
"""Measure SAR's per-action overhead on this machine. Prints a table; numbers are local.

    python scripts/bench.py [-n 2000]

Each scenario runs the same trivial in-memory tool, so the time reported is the
runtime's own cost: validation, policy, SQLite writes (one transaction per state change),
the worker thread, and (where noted) snapshots and receipts.
"""

from __future__ import annotations

import argparse
import os
import platform
import sqlite3
import statistics
import sys
import tempfile
import time
from collections.abc import Callable

from secure_agent_runtime.examples import refund as rf
from secure_agent_runtime.examples.notes import AGENT, APPROVER, NotesApp, ReadIn, build_runtime
from secure_agent_runtime.store import Store


def timed(n: int, fn: Callable[[int], None]) -> list[float]:
    for i in range(min(50, n)):  # warm-up
        fn(-1 - i)
    out = []
    for i in range(n):
        t = time.perf_counter_ns()
        fn(i)
        out.append((time.perf_counter_ns() - t) / 1000)
    return out


def row(name: str, samples: list[float]) -> str:
    q = statistics.quantiles(samples, n=100)
    return f"| {name:<46} | {statistics.median(samples):>9.1f} | {q[94]:>9.1f} |"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("-n", type=int, default=2000)
    n = ap.parse_args().n
    results = []

    app = NotesApp({"todo": "x"})
    results.append(row("direct tool call (no SAR)", timed(n, lambda i: app.read(ReadIn(title="todo")))))

    rt, _ = build_runtime(Store(), NotesApp({"todo": "x"}))

    def read(i: int) -> None:
        o = rt.propose(run_id="b", principal_id=AGENT, call_id=f"r{i}", tool="read_note", arguments={"title": "todo"})
        rt.execute(o.key)

    results.append(row("read: propose + execute, SQLite :memory:", timed(n, read)))

    with tempfile.TemporaryDirectory() as tmp:
        rt_disk, _ = build_runtime(Store(os.path.join(tmp, "b.db")), NotesApp({"todo": "x"}))

        def read_disk(i: int) -> None:
            o = rt_disk.propose(run_id="b", principal_id=AGENT, call_id=f"r{i}", tool="read_note",
                                arguments={"title": "todo"})
            rt_disk.execute(o.key)

        results.append(row("read: propose + execute, SQLite file (WAL)", timed(n, read_disk)))
        rt_disk.store.close()

    def write(i: int) -> None:
        o = rt.propose(run_id="b", principal_id=AGENT, call_id=f"w{i}", tool="write_note",
                       arguments={"title": "todo", "body": "y"})
        rt.approve(o.key, approver_id=APPROVER, action_digest=o.action_digest)
        rt.execute(o.key)

    results.append(row("write: propose + approve + execute", timed(n, write)))

    service = rf.PaymentService()
    rrt = rf.build_runtime(service)

    def refund(i: int) -> None:
        o = rrt.propose(run_id="b", principal_id=rf.AGENT, call_id=f"f{i}", tool="refund",
                        arguments={"order": 1, "amount_inr": 1})
        rrt.approve(o.key, approver_id=rf.APPROVER, action_digest=o.action_digest)
        rrt.execute(o.key)

    service_small = len(service.refunds)
    results.append(row("refund: approve + execute + frame check*", timed(n, refund)))

    def replay(i: int) -> None:
        rt.execute(rt.propose(run_id="b", principal_id=AGENT, call_id="r0", tool="read_note",
                              arguments={"title": "todo"}).key)

    results.append(row("replay of a completed action", timed(n, replay)))
    key = rrt.store.calls()[-1].key
    results.append(row("build receipt", timed(min(n, 500), lambda i: rrt.receipt(key))))

    print(f"Python {platform.python_version()} on {platform.system()} {platform.machine()}, "
          f"SQLite {sqlite3.sqlite_version}, {os.cpu_count()} CPUs, n={n}\n")
    print("| scenario                                       | median µs |    p95 µs |")
    print("|------------------------------------------------|-----------|-----------|")
    print("\n".join(results))
    print(f"\n* the refund observer snapshots the whole mock ledger, which grows from {service_small} to "
          f"{len(service.refunds)} refunds during the run, so later iterations cost more.")
    sys.stdout.flush()


if __name__ == "__main__":
    main()
