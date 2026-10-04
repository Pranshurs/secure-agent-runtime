#!/usr/bin/env python3
"""Measure SAR's own overhead on this machine. Numbers are local; rerun them yourself.

    python scripts/bench.py [-n 2000] [--process-n 30] [--threads 8] [--json out.json]

Every scenario runs a trivial tool, so the time is SAR's cost, not the tool's. For each
scenario the table gives the sample count, p50/p95/p99 and mean latency of one timed
region, and the sequential throughput (samples / total time inside the timed regions,
one thread). The "concurrent" row is different: wall-clock throughput of N threads
sharing one runtime. What each timed region includes is printed under the table.
Setup that is not part of the operation (making an action effect_unknown before timing
reconcile, for example) is done outside the timed region.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import sqlite3
import statistics
import subprocess  # nosec B404 - only runs "git rev-parse" for the environment line
import tempfile
import threading
import time
from collections.abc import Callable
from typing import Any

from secure_agent_runtime.auth import demo_token
from secure_agent_runtime.examples import refund as rf
from secure_agent_runtime.examples.notes import AGENT, APPROVER, NotesApp, ReadIn, build_runtime
from secure_agent_runtime.receipts import verify_receipt
from secure_agent_runtime.store import Store

INCLUDES: dict[str, str] = {}


def measure(name: str, includes: str, n: int, fn: Callable[[Any], None],
            setup: Callable[[int], Any] = lambda i: i, warmup: int = 20) -> dict[str, Any]:
    INCLUDES[name] = includes
    for i in range(min(warmup, n)):
        fn(setup(-1 - i))
    samples = []
    for i in range(n):
        arg = setup(i)
        t = time.perf_counter_ns()
        fn(arg)
        samples.append((time.perf_counter_ns() - t) / 1000)
    q = statistics.quantiles(samples, n=100, method="inclusive")
    return {"scenario": name, "n": n, "p50_us": q[49], "p95_us": q[94], "p99_us": q[98],
            "mean_us": statistics.fmean(samples), "ops_per_s": n / (sum(samples) / 1e6)}


def _synchronous() -> str:
    with tempfile.TemporaryDirectory() as d, Store(os.path.join(d, "s.db")) as s:
        level = s._db.execute("PRAGMA synchronous").fetchone()[0]
    return {0: "OFF", 1: "NORMAL", 2: "FULL", 3: "EXTRA"}.get(level, str(level))


def environment() -> dict[str, Any]:
    cpu = platform.processor() or platform.machine()
    try:
        with open("/proc/cpuinfo") as f:
            cpu = next((ln.split(":", 1)[1].strip() for ln in f if ln.startswith("model name")), cpu)
    except OSError:
        pass
    try:
        rev = subprocess.run(["git", "rev-parse", "--short", "HEAD"], capture_output=True, text=True,  # nosec
                             check=False).stdout.strip() or "unknown"
    except OSError:
        rev = "unknown"
    load = os.getloadavg() if hasattr(os, "getloadavg") else None
    return {"python": platform.python_version(), "implementation": platform.python_implementation(),
            "os": f"{platform.system()} {platform.release()}", "cpu": cpu, "cpus": os.cpu_count(),
            "sqlite": sqlite3.sqlite_version, "sqlite_synchronous": _synchronous(), "git": rev,
            "loadavg_1m_at_start": round(load[0], 2) if load else None}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("-n", type=int, default=2000, help="samples per in-process scenario")
    ap.add_argument("--process-n", type=int, default=30, help="samples for process-isolated dispatch")
    ap.add_argument("--threads", type=int, default=8, help="threads for the concurrent row")
    ap.add_argument("--json", help="also write the results here")
    ns = ap.parse_args()
    n = ns.n
    env = environment()
    results = []
    tmp = tempfile.mkdtemp(prefix="sar-bench-")

    app = NotesApp({"todo": "x"})
    results.append(measure("direct tool call (no SAR)", "the tool function alone: the baseline",
                           n, lambda i: app.read(ReadIn(title="todo"))))

    with Store() as mem:
        rt, _ = build_runtime(mem, NotesApp({"todo": "x"}))

        def read(i: int) -> None:
            o = rt.propose(run_id="b", principal_id=AGENT, call_id=f"r{i}", tool="read_note",
                           arguments={"title": "todo"})
            rt.execute(o.key)

        results.append(measure(
            "read: propose + execute, :memory:",
            "input validation, canonical action + digest, policy, insert + 3 state transitions with "
            "audit events (SQLite in memory), last-moment re-check, worker thread, output validation",
            n, read))

        def replay(i: int) -> None:
            rt.execute(rt.propose(run_id="b", principal_id=AGENT, call_id="r0", tool="read_note",
                                  arguments={"title": "todo"}).key)

        results.append(measure("replay of a completed action",
                               "propose with an existing call id (request-hash check, recorded outcome "
                               "returned) + execute no-op; the tool does not run", n, replay))
        rt.close()

    with Store(os.path.join(tmp, "b.db")) as disk:
        rtd, _ = build_runtime(disk, NotesApp({"todo": "x"}))

        def read_disk(i: int) -> None:
            o = rtd.propose(run_id="b", principal_id=AGENT, call_id=f"r{i}", tool="read_note",
                            arguments={"title": "todo"})
            rtd.execute(o.key)

        results.append(measure("read: propose + execute, SQLite file (WAL)",
                               "as the :memory: read, with every transaction committed to a WAL file "
                               "(SAR leaves PRAGMA synchronous at SQLite's default; see the header)",
                               n, read_disk))

        def write(i: int) -> None:
            o = rtd.propose(run_id="b", principal_id=AGENT, call_id=f"w{i}", tool="write_note",
                            arguments={"title": "todo", "body": "y"})
            rtd.approve(o.key, credential=demo_token(rtd, APPROVER, scope=o.action_digest),
                        action_digest=o.action_digest)
            rtd.execute(o.key)

        results.append(measure("write: propose + approve + execute, file",
                               "propose (awaiting_approval) + minting and authenticating a one-time "
                               "demo credential, consuming it, recording the approval + execute "
                               "(policy re-check, digest re-check, approval age, dispatch)", n, write))

        stop = threading.Event()
        counts = [0] * ns.threads

        def worker(t: int) -> None:
            i = 0
            while not stop.is_set():
                o = rtd.propose(run_id="c", principal_id=AGENT, call_id=f"t{t}-{i}", tool="read_note",
                                arguments={"title": "todo"})
                rtd.execute(o.key)
                i += 1
            counts[t] = i

        threads = [threading.Thread(target=worker, args=(t,)) for t in range(ns.threads)]
        t0 = time.perf_counter()
        for th in threads:
            th.start()
        time.sleep(5.0)
        stop.set()
        for th in threads:
            th.join()
        wall = time.perf_counter() - t0
        concurrent = {"scenario": f"concurrent reads, {ns.threads} threads, file", "n": sum(counts),
                      "p50_us": None, "p95_us": None, "p99_us": None, "mean_us": None,
                      "ops_per_s": sum(counts) / wall}
        INCLUDES[concurrent["scenario"]] = ("wall-clock throughput of the file-backed read above, "
                                            f"{ns.threads} threads sharing one Runtime for 5 s (one "
                                            "SQLite connection, so writes are serialised)")
        rtd.close()

    with Store(os.path.join(tmp, "r.db")) as rstore:
        service = rf.PaymentService(os.path.join(tmp, "ledger.db"))
        rrt = rf.build_runtime(service, rstore, isolation="thread")

        def approved(i: int) -> str:
            o = rrt.propose(run_id="b", principal_id=rf.AGENT, call_id=f"f{i}", tool="refund",
                            arguments={"order": 1, "amount_inr": 1})
            rf.approve_as_finance(rrt, o)
            return o.key

        before = len(service.refunds)
        results.append(measure("refund execute (thread), frame check",
                               "execute of an approved refund: ledger snapshot before + after "
                               "(MappingObserver over the SQLite mock ledger), the tool's own SQLite "
                               "transaction, frame evaluation, recording the result", n // 4, rrt.execute,
                               setup=approved))
        after = len(service.refunds)

        def unknown(i: int) -> str:
            key = approved(10_000_000 + i)
            service.fail_next = "after_effect"
            assert rrt.execute(key).state == "effect_unknown"
            return key

        results.append(measure("reconcile an effect_unknown refund",
                               "reconcile(): the reconciler's lookup by idempotency key in the mock "
                               "ledger + Applied -> succeeded transition with its audit event",
                               max(n // 10, 50), rrt.reconcile, setup=unknown))

        key = rrt.store.calls(state="succeeded")[-1].key
        results.append(measure("build receipt (unsigned)",
                               "receipt(): read the row and its events, verify the audit chain head, "
                               "assemble and digest the receipt", min(n, 500), lambda i: rrt.receipt(key)))
        try:
            from secure_agent_runtime.signing import Ed25519Signer
            signer = Ed25519Signer.generate("bench")
            keys = {signer.key_id: signer.public_key_bytes()}
            results.append(measure("build receipt + Ed25519 signature",
                                   "as above, plus one Ed25519 signature over {alg, digest, key_id}",
                                   min(n, 500), lambda i: rrt.receipt(key, signer=signer)))
            signed = rrt.receipt(key, signer=signer)
            results.append(measure("verify receipt: Ed25519 + against the store",
                                   "digest, Ed25519 signature, expect_key, full audit-chain verification "
                                   "and every field compared with the store",
                                   min(n, 500), lambda i: verify_receipt(signed, public_keys=keys,
                                                                         expect_key=key, store=rstore)))
        except ImportError:
            print("(signing extra not installed: Ed25519 rows skipped)")
        rrt.close()

    with Store(os.path.join(tmp, "p.db")) as pstore:
        pservice = rf.PaymentService(os.path.join(tmp, "pledger.db"))
        prt = rf.build_runtime(pservice, pstore, isolation="process")

        def p_approved(i: int) -> str:
            o = prt.propose(run_id="p", principal_id=rf.AGENT, call_id=f"p{i}", tool="refund",
                            arguments={"order": 1, "amount_inr": 1})
            rf.approve_as_finance(prt, o)
            return o.key

        results.append(measure("refund execute (process-isolated)",
                               "as the thread refund, plus spawning a fresh worker process (start "
                               "method 'spawn': a new interpreter importing SAR and the tool), the "
                               "pipe round trip and reaping the worker", ns.process_n, prt.execute,
                               setup=p_approved, warmup=2))
        prt.close()
    results.append(concurrent)

    print(f"SAR {env['git']} | Python {env['python']} ({env['implementation']}) | {env['os']} | "
          f"{env['cpu']} | {env['cpus']} CPUs | "
          f"SQLite {env['sqlite']} (WAL, synchronous={env['sqlite_synchronous']}) | "
          f"1-min load at start {env['loadavg_1m_at_start']}\n")
    print("| scenario | n | p50 µs | p95 µs | p99 µs | mean µs | ops/s |")
    print("|---|--:|--:|--:|--:|--:|--:|")
    for r in results:
        cells = [f"{r[k]:,.0f}" if r[k] is not None else "–" for k in ("p50_us", "p95_us", "p99_us", "mean_us")]
        print(f"| {r['scenario']} | {r['n']:,} | " + " | ".join(cells) + f" | {r['ops_per_s']:,.0f} |")
    print("\nWhat each timed region includes:")
    for name, inc in INCLUDES.items():
        print(f"* **{name}**: {inc}.")
    print(f"\nThe refund observer snapshots the whole mock ledger, which grew from {before} to {after} "
          "refunds during its row, so later samples cost more.")
    if ns.json:
        with open(ns.json, "w") as f:
            json.dump({"environment": env, "results": results, "includes": INCLUDES}, f, indent=2)


if __name__ == "__main__":
    main()
