#!/usr/bin/env python3
"""Concurrency / fault stress harness for SAR. Reproducible by seed.

    python scripts/stress.py --seeds 1 2 3 --actions 200 --threads 8 --rounds 2

Each round builds a fresh file-backed store and a file-backed payment ledger, then:

* proposes every action from 1-3 threads at once (duplicate requests);
* approves, executes from several threads at once, reconciles concurrently, cancels a few;
* tools fail in seeded ways: response lost after the effect, request lost before it,
  slow (some past their timeout, cooperating with cancellation), exceptions; about 10%
  of actions run in a killable worker process;
* drains: reconciles and dispatches until every action is settled.

Then it checks, against the ledger (ground truth):

* no action has more than one effect;
* every action is settled: succeeded with exactly one effect, or ended with none;
* no worker thread is deadlocked (all joins finish);
* the audit chain verifies and every row's state is its last state event;
* claimed dispatches >= provider calls (a claim may precede a cooperative cancel).

Prints one JSON line per round and exits 1 if any invariant failed.
"""

from __future__ import annotations

import argparse
import functools
import json
import os
import random
import sys
import tempfile
import threading
import time
import tracemalloc
from collections import Counter
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from secure_agent_runtime.auth import TokenAuthenticator
from secure_agent_runtime.contracts import Applied, Effect, EffectNotApplied, NotApplied, ToolContext, ToolRegistry
from secure_agent_runtime.errors import SARError, StoreError
from secure_agent_runtime.examples.refund import ConnectionLost, PaymentService
from secure_agent_runtime.policy import Policy, Principal
from secure_agent_runtime.runtime import ApprovalRefused, ReplayDivergence, Runtime
from secure_agent_runtime.store import Store

AGENT, APPROVER = "agent", "approver"
FAULTS = ["ok"] * 5 + ["lost_after", "lost_before", "slow", "slow_past_timeout", "raise"]


class StressIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    order: int = Field(gt=0)
    amount: int = Field(gt=0)
    fault: str
    delay_ms: int = Field(ge=0, le=5000)


class StressOut(BaseModel):
    model_config = ConfigDict(extra="forbid")
    refund_id: str


def stress_tool(ledger_path: str, args: StressIn, ctx: ToolContext) -> StressOut:
    """Module-level so the process-isolated variant can import it. Faults are transient:
    they hit the first attempt only, as a flaky network would."""
    if ctx.attempt > 1:
        args = args.model_copy(update={"fault": "ok", "delay_ms": 0})
    if args.delay_ms and ctx.cancel.wait(args.delay_ms / 1000):
        raise EffectNotApplied("cancelled before sending")  # a cooperative tool stops in time
    if args.fault == "lost_before":
        raise ConnectionLost
    if args.fault == "raise":
        raise RuntimeError("tool bug")
    rid = PaymentService(ledger_path).refund(args.order, args.amount, idempotency_key=ctx.idempotency_key)
    if args.fault == "lost_after":
        raise ConnectionLost
    return StressOut(refund_id=rid)


def build(store: Store, ledger: PaymentService) -> Runtime:
    reg = ToolRegistry()
    fn = functools.partial(stress_tool, ledger.path)
    reg.tool(name="pay", input=StressIn, output=StressOut, effect=Effect.EXTERNAL, timeout_s=0.5)(fn)
    reg.tool(name="pay_p", input=StressIn, output=StressOut, effect=Effect.EXTERNAL, timeout_s=10,
             isolation="process")(fn)

    def recon(args: StressIn, ctx: ToolContext) -> Applied | NotApplied:
        found = ledger.find_by_key(ctx.idempotency_key)
        return Applied(StressOut(refund_id=found[0])) if found else NotApplied()

    reg.reconciler("pay")(recon)
    reg.reconciler("pay_p")(recon)
    return Runtime(registry=reg, policy=Policy(), store=store, authenticator=TokenAuthenticator(),
                   approval_ttl_s=3600, max_stuck_workers=10_000,
                   principals=[Principal(AGENT, grants=frozenset({"pay", "pay_p"})),
                               Principal(APPROVER, can_approve=True)])


def run_round(seed: int, n_actions: int, n_threads: int, round_no: int) -> dict[str, Any]:
    rng = random.Random(seed * 1000 + round_no)
    tmp = tempfile.mkdtemp(prefix="sar-stress-")
    store = Store(os.path.join(tmp, "sar.db"), busy_timeout_ms=30_000)
    ledger = PaymentService(os.path.join(tmp, "ledger.db"))
    rt = build(store, ledger)
    stats: Counter[str] = Counter()
    lock = threading.Lock()

    plans = []
    for i in range(n_actions):
        fault = rng.choice(FAULTS)
        delay = {"slow": rng.randint(10, 200), "slow_past_timeout": rng.randint(600, 900)}.get(fault, 0)
        tool = "pay_p" if rng.random() < 0.1 and fault != "slow_past_timeout" else "pay"
        plans.append({"call": f"c{i}", "tool": tool, "args": {"order": i + 1, "amount": rng.randint(1, 9),
                                                             "fault": fault, "delay_ms": delay},
                      "dupes": rng.randint(1, 3), "cancel": rng.random() < 0.05})
    keys: dict[str, str] = {}

    def count(name: str) -> None:
        with lock:
            stats[name] += 1

    def proposer(p: dict[str, Any]) -> None:
        try:
            o = rt.propose(run_id="stress", principal_id=AGENT, call_id=p["call"], tool=p["tool"],
                           arguments=p["args"])
            with lock:
                keys[p["call"]] = o.key
            count("proposals")
        except ReplayDivergence:
            count("divergence")
        except StoreError:
            count("store_errors")

    def worker(p: dict[str, Any]) -> None:
        key = keys.get(p["call"])
        if key is None:
            return
        try:
            row = store.get_call(key)
            if p["cancel"] and rng.random() < 0.5:
                rt.cancel(key)
            if row is not None and row.state == "awaiting_approval":
                try:
                    rt.approve(key, credential=rt.authenticator.issue(APPROVER), action_digest=row.action_digest)
                except ApprovalRefused:
                    count("approve_raced")
            rt.execute(key)
            if rng.random() < 0.5:
                rt.reconcile(key)
            rt.execute(key)
        except StoreError:
            count("store_errors")
        except SARError:
            count("sar_errors")

    t0 = time.monotonic()
    threads = []
    for p in plans:  # duplicate proposals race each other
        for _ in range(p["dupes"]):
            threads.append(threading.Thread(target=proposer, args=(p,)))
    rng.shuffle(threads)
    _run_pool(threads, n_threads)
    workers = [threading.Thread(target=worker, args=(p,)) for p in plans for _ in range(2)]
    rng.shuffle(workers)
    deadlocks = _run_pool(workers, n_threads)

    # Drain: settle everything the way an operator would.
    for _ in range(50):
        busy = 0
        for key in keys.values():
            row = store.get_call(key)
            assert row is not None
            if row.state == "awaiting_approval":
                rt.approve(key, credential=rt.authenticator.issue(APPROVER), action_digest=row.action_digest)
                busy += 1
            if row.state in ("approved", "awaiting_approval"):
                rt.execute(key)
                busy += 1
            elif row.state == "effect_unknown":
                rt.reconcile(key)
                busy += 1
            elif row.state == "executing":
                busy += 1
        if not busy:
            break
        time.sleep(0.05)
    elapsed = time.monotonic() - t0

    failures = []
    refunds = Counter(r["idempotency_key"] for r in ledger.refunds.values())
    for p in plans:
        key = keys[p["call"]]
        row = store.get_call(key)
        assert row is not None
        effects = refunds.get(key, 0)
        if effects > 1:
            failures.append(f"{key}: {effects} effects")
        if row.state == "succeeded" and effects != 1:
            failures.append(f"{key}: succeeded with {effects} effects")
        if row.state in ("failed", "cancelled", "expired", "rejected") and effects != 0:
            failures.append(f"{key}: {row.state} but {effects} effects")
        if row.state not in ("succeeded", "failed", "cancelled", "expired", "rejected"):
            failures.append(f"{key}: not settled ({row.state})")
        events = [e.kind for e in store.events(call_key=key) if e.kind.startswith("call.") and e.kind not in (
            "call.requested", "call.replayed", "call.replay_divergence", "call.late_result_discarded")]
        if events[-1] != f"call.{row.state}":
            failures.append(f"{key}: row state {row.state} not backed by last event {events[-1]}")
        stats["state:" + row.state] += 1
    ok, msg = store.verify_audit()
    if not ok:
        failures.append(f"audit: {msg}")
    claims = len(store.events(kind="call.executing"))
    if claims < ledger.calls:
        failures.append(f"claims {claims} < provider calls {ledger.calls}")
    if deadlocks:
        failures.append(f"{deadlocks} worker threads did not finish (deadlock?)")
    late = len(store.events(kind="call.late_result_discarded"))
    store.close()
    return {"seed": seed, "round": round_no, "actions": n_actions, "threads": n_threads,
            "proposals": stats["proposals"], "duplicates_absorbed": stats["proposals"] - n_actions,
            "claims": claims, "provider_calls": ledger.calls, "effects": sum(refunds.values()),
            "late_results_discarded": late,
            "store_errors": stats["store_errors"], "states": {k[6:]: v for k, v in stats.items()
                                                              if k.startswith("state:")},
            "seconds": round(elapsed, 2), "failures": failures}


def _run_pool(threads: list[threading.Thread], width: int) -> int:
    stuck = 0
    for i in range(0, len(threads), width):
        batch = threads[i:i + width]
        for t in batch:
            t.start()
        for t in batch:
            t.join(120)
            stuck += t.is_alive()
    return stuck


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", type=int, nargs="+", default=[1, 2, 3])
    ap.add_argument("--actions", type=int, default=200)
    ap.add_argument("--threads", type=int, default=8)
    ap.add_argument("--rounds", type=int, default=2)
    ns = ap.parse_args()
    tracemalloc.start()
    bad = 0
    mem = []
    for seed in ns.seeds:
        for r in range(ns.rounds):
            res = run_round(seed, ns.actions, ns.threads, r)
            current, _ = tracemalloc.get_traced_memory()
            mem.append(current)
            res["traced_kib_after"] = current // 1024
            print(json.dumps(res), flush=True)
            bad += bool(res["failures"])
    print(json.dumps({"rounds": len(mem), "failed_rounds": bad, "traced_kib": [m // 1024 for m in mem]}))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
