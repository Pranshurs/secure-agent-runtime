"""Real process death at every execution boundary, with a process-isolated tool.

Each scenario runs the runtime in a separate process (tests/crash_harness.py) and kills
it with SIGKILL at one point. The test then opens the same database in a fresh runtime,
recovers, reconciles as needed, and checks the ground truth in the payment ledger:
exactly one refund, never two, and never a redispatch while the outcome was unknown.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

from secure_agent_runtime.examples import refund as rf
from secure_agent_runtime.store import Store

pytestmark = pytest.mark.skipif(not sys.platform.startswith("linux"),
                                reason="PR_SET_PDEATHSIG (worker dies with the runtime) is Linux-only")

HARNESS = str(Path(__file__).with_name("crash_harness.py"))
KILLED = -signal.SIGKILL


def harness(tmp_path, mode, point, *, background=False):
    cmd = [sys.executable, HARNESS, str(tmp_path / "sar.db"), str(tmp_path / "ledger.db"), mode, point]
    if background:
        return subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return subprocess.run(cmd, capture_output=True, text=True, timeout=60)


def wait_for_file(path: Path, timeout=20.0) -> None:
    deadline = time.monotonic() + timeout
    while not path.exists():
        assert time.monotonic() < deadline, f"{path} never appeared"
        time.sleep(0.01)


def restart(tmp_path):
    service = rf.PaymentService(str(tmp_path / "ledger.db"))
    rt = rf.build_runtime(service, Store(str(tmp_path / "sar.db")))
    return rt, service


def settle(rt):
    """What an operator does after a restart: recover, then reconcile and (only if the
    reconciler says the effect did not happen) dispatch again."""
    rt.recover()
    key = rt.store.calls()[0].key
    out = rt.reconcile(key)
    if out.state == "approved":
        out = rt.execute(key)
    return key, out


def assert_settled_once(rt, service, key, out, *, provider_calls):
    assert out.state == "succeeded", out
    assert len(service.refunds) == 1 and service.total_refunded(821) == 4500
    assert service.calls == provider_calls
    again = rt.propose(run_id="t", principal_id=rf.AGENT, call_id="c1", tool="refund", arguments=rf_args())
    assert rt.execute(again.key).state == "succeeded" and len(service.refunds) == 1  # replay: no redispatch
    assert rt.store.verify_audit()[0]
    rt.store.close()


def rf_args():
    return {"order": 821, "amount_inr": 4500}


@pytest.mark.parametrize("point,provider_calls", [
    ("after_claim", 1),                          # claimed, worker never started
    ("after_spawn", 1),                          # worker started; it dies with the runtime (PDEATHSIG)
    ("after_effect", 1),                         # worker returned; result not yet recorded
    ("commit:executing->succeeded", 1),          # killed inside the completion transaction
])
def test_runtime_killed_during_dispatch(tmp_path, point, provider_calls):
    p = harness(tmp_path, "dispatch", point)
    assert p.returncode == KILLED, (p.stdout, p.stderr)
    rt, service = restart(tmp_path)
    key = rt.store.calls()[0].key
    assert rt.recovered == [key]  # nothing was recorded past the claim; start-up recovery found it
    assert rt.store.get_call(key).state == "effect_unknown"
    key, out = settle(rt)
    assert_settled_once(rt, service, key, out, provider_calls=provider_calls)


@pytest.mark.parametrize("fault,expect_calls", [
    ("slow_before_effect", 2),   # killed before the refund: reconcile says not applied, one more dispatch
    ("slow_after_effect", 1),    # killed after the refund: reconcile finds it, no second dispatch
])
def test_runtime_killed_while_the_effect_is_executing(tmp_path, fault, expect_calls):
    rf.PaymentService(str(tmp_path / "ledger.db")).fail_next = fault
    proc = harness(tmp_path, "dispatch", "none", background=True)
    wait_for_file(Path(str(tmp_path / "ledger.db") + ".inflight"))
    worker_pid = int(Path(str(tmp_path / "ledger.db") + ".inflight").read_text())
    proc.send_signal(signal.SIGKILL)
    proc.wait(10)
    deadline = time.monotonic() + 10
    while _alive(worker_pid):  # the worker must die with the runtime
        assert time.monotonic() < deadline, "orphan worker survived the runtime"
        time.sleep(0.01)
    rt, service = restart(tmp_path)
    key, out = settle(rt)
    time.sleep(0.2)  # nothing left alive that could still refund
    assert_settled_once(rt, service, key, out, provider_calls=expect_calls)


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    try:  # a zombie has exited; reap-less children of a dead parent are reparented and reaped
        with open(f"/proc/{pid}/stat") as f:
            return f.read().split()[2] != "Z"
    except FileNotFoundError:
        return False


@pytest.mark.parametrize("point", ["after_reconcile", "commit:effect_unknown->succeeded"])
def test_runtime_killed_during_reconciliation(tmp_path, point):
    rf.PaymentService(str(tmp_path / "ledger.db")).fail_next = "after_effect"
    assert harness(tmp_path, "dispatch", "none").stdout.strip() == "effect_unknown"
    p = harness(tmp_path, "reconcile", point)
    assert p.returncode == KILLED, (p.stdout, p.stderr)
    rt, service = restart(tmp_path)
    assert rt.store.get_call(rt.store.calls()[0].key).state == "effect_unknown"
    key, out = settle(rt)
    assert_settled_once(rt, service, key, out, provider_calls=1)


def test_runtime_killed_while_the_reconciler_is_querying(tmp_path):
    service = rf.PaymentService(str(tmp_path / "ledger.db"))
    service.fail_next = "after_effect"
    assert harness(tmp_path, "dispatch", "none").stdout.strip() == "effect_unknown"
    service.fail_reconcile_next = "slow"
    proc = harness(tmp_path, "reconcile", "none", background=True)
    wait_for_file(Path(str(tmp_path / "ledger.db") + ".inflight"))
    proc.send_signal(signal.SIGKILL)
    proc.wait(10)
    rt, service = restart(tmp_path)
    key, out = settle(rt)
    assert_settled_once(rt, service, key, out, provider_calls=1)


def test_runtime_killed_after_completion_replays_without_redispatch(tmp_path):
    p = harness(tmp_path, "dispatch", "after_execute")
    assert p.returncode == KILLED and p.stdout.strip() == "succeeded"
    rt, service = restart(tmp_path)
    assert rt.recover() == []
    key = rt.store.calls()[0].key
    assert_settled_once(rt, service, key, rt.execute(key), provider_calls=1)


# -- the worker itself is killed on timeout ------------------------------------------------------- #

@pytest.mark.parametrize("fault,refunds_after_kill,expect_calls", [
    ("slow_before_effect", 0, 2), ("slow_after_effect", 1, 1)])
def test_timed_out_worker_is_killed_and_cannot_act_later(tmp_path, fault, refunds_after_kill, expect_calls):
    service = rf.PaymentService(str(tmp_path / "ledger.db"))
    with Store(str(tmp_path / "sar.db")) as store:
        _killed_worker_scenario(service, store, tmp_path, fault, refunds_after_kill, expect_calls)


def _killed_worker_scenario(service, store, tmp_path, fault, refunds_after_kill, expect_calls):
    import dataclasses

    rt = rf.build_runtime(service, store)
    spec = rt.registry.get("refund")
    # The fault sleeps 30 s once inside the tool, so any timeout well under that kills the worker
    # mid-call. It must also cover spawning the worker and importing SAR before the tool starts
    # (seconds on a slow runner), or the worker is killed before it writes the ".inflight" marker.
    rt.registry.replace(dataclasses.replace(spec, timeout_s=10.0))
    o = rt.propose(run_id="t", principal_id=rf.AGENT, call_id="c1", tool="refund", arguments=rf_args())
    rf.approve_as_finance(rt, o)
    service.fail_next = fault
    out = rt.execute(o.key)
    assert out.state == "effect_unknown" and "worker killed" in out.reason
    worker_pid = int(Path(str(tmp_path / "ledger.db") + ".inflight").read_text())
    assert not _alive(worker_pid)
    time.sleep(0.3)
    assert len(service.refunds) == refunds_after_kill  # a killed worker never finishes its effect
    rt.registry.replace(spec)
    out = rt.reconcile(o.key)
    if out.state == "approved":
        out = rt.execute(o.key)
    assert out.state == "succeeded" and len(service.refunds) == 1 and service.calls == expect_calls


def test_process_isolation_requires_importable_tools():
    from pydantic import BaseModel, ConfigDict

    from secure_agent_runtime.contracts import ContractError, Effect, ToolRegistry

    class M(BaseModel):  # defined in a function: not importable by reference
        model_config = ConfigDict(extra="forbid")

    with pytest.raises(ContractError, match="importable"):
        ToolRegistry().tool(name="t", input=M, output=M, effect=Effect.WRITE, isolation="process")(lambda a: M())


# -- every way a worker can end, in process mode ------------------------------------------------- #

@pytest.mark.parametrize("mode,effect,expected,reason", [
    ("ok", "external", "succeeded", ""),
    ("exit", "external", "effect_unknown", "worker process died"),
    ("raise", "external", "effect_unknown", "tool raised RuntimeError"),
    ("not_applied", "external", "failed", "not applied"),
    ("unserialisable", "external", "effect_unknown", "invalid output"),
    ("invalid", "external", "effect_unknown", "invalid output"),
    ("exit", "read", "failed", "worker process died"),
    ("invalid", "read", "output_rejected", "invalid output"),
])
def test_worker_outcomes_in_process_mode(store, mode, effect, expected, reason):
    from secure_agent_runtime.auth import TokenAuthenticator
    from secure_agent_runtime.contracts import Effect, ToolRegistry
    from secure_agent_runtime.policy import Policy, Principal
    from secure_agent_runtime.runtime import Runtime

    from . import process_tools as pt

    reg = ToolRegistry()
    reg.tool(name="t", input=pt.In, output=pt.Out, effect=Effect(effect), isolation="process", timeout_s=20)(pt.tool)
    rt = Runtime(registry=reg, policy=Policy(require_approval_for_effects=frozenset()), store=store,
                 authenticator=TokenAuthenticator(), principals=[Principal("p", grants=frozenset({"t"}))])
    o = rt.propose(run_id="r", principal_id="p", call_id="c", tool="t", arguments={"mode": mode})
    out = rt.execute(o.key)
    assert out.state == expected and reason in out.reason
    assert "secret detail" not in str([e.data for e in store.events()])
    assert rt.execute(o.key).state == expected  # nothing re-dispatches on its own


# -- nothing the tool left running can act after the attempt is decided ---------------------------- #

@pytest.mark.skipif(not hasattr(os, "killpg"), reason="process groups are POSIX-only")
@pytest.mark.parametrize("mode,expected", [("child", "effect_unknown"), ("thread", "succeeded")])
def test_nothing_the_worker_left_running_acts_after_the_attempt_is_decided(store, tmp_path, mode, expected):
    """'child': the tool starts a child process and then times out. 'thread': the tool returns
    but leaves a thread running. Either way SAR kills the worker's whole process group once the
    attempt is decided, so the leftover can't act later (it would act when 'release' appears)."""
    from secure_agent_runtime.auth import TokenAuthenticator
    from secure_agent_runtime.contracts import Effect, ToolRegistry
    from secure_agent_runtime.policy import Policy, Principal
    from secure_agent_runtime.runtime import Runtime

    from . import process_tools as pt

    reg = ToolRegistry()
    reg.tool(name="t", input=pt.LateIn, output=pt.Out, effect=Effect.EXTERNAL, isolation="process",
             timeout_s=8 if mode == "child" else 20)(pt.late_tool)
    rt = Runtime(registry=reg, policy=Policy(require_approval_for_effects=frozenset()), store=store,
                 authenticator=TokenAuthenticator(), principals=[Principal("p", grants=frozenset({"t"}))])
    o = rt.propose(run_id="r", principal_id="p", call_id="c", tool="t", arguments={"mode": mode, "dir": str(tmp_path)})
    assert rt.execute(o.key).state == expected
    deadline = time.monotonic() + 10
    while not (tmp_path / "started").exists() and time.monotonic() < deadline:  # the leftover really ran
        time.sleep(0.05)
    assert (tmp_path / "started").exists()
    (tmp_path / "release").touch()
    time.sleep(1.0)
    assert not (tmp_path / "late_effect").exists()
