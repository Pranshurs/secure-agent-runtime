"""Run the refund runtime in its own process and SIGKILL it at a chosen point.

Used by tests/test_process_crashes.py:  python tests/crash_harness.py DB LEDGER MODE POINT

MODE "dispatch": propose, approve and execute one refund.
MODE "reconcile": restart on an existing DB, recover() and reconcile().
POINT names where to die: a Runtime fault point, "commit:<from->to>" for a Store
transaction just before COMMIT, "after_execute" once execute() has returned, or "none".
"""

from __future__ import annotations

import os
import signal
import sys

from secure_agent_runtime.examples import refund as rf
from secure_agent_runtime.store import Store

ARGS = {"order": 821, "amount_inr": 4500}


def die() -> None:
    sys.stdout.flush()
    os.kill(os.getpid(), signal.SIGKILL)


def main() -> None:
    db, ledger, mode, point = sys.argv[1:5]

    def runtime_fault(p: str, key: str) -> None:
        if p == point:
            die()

    def store_fault(p: str, detail: str) -> None:
        if point == f"commit:{detail}":
            die()

    service = rf.PaymentService(ledger)
    rt = rf.build_runtime(service, Store(db, faults=store_fault), faults=runtime_fault)
    if mode == "dispatch":
        o = rt.propose(run_id="t", principal_id=rf.AGENT, call_id="c1", tool="refund", arguments=ARGS)
        rf.approve_as_finance(rt, o)
        out = rt.execute(o.key)
        print(out.state, flush=True)
        if point == "after_execute":
            die()
    else:
        rt.recover()
        key = rt.store.calls()[0].key
        print(rt.reconcile(key).state, flush=True)
    rt.store.close()


if __name__ == "__main__":
    main()
