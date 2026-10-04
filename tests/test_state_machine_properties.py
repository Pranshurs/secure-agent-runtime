"""Property-based state-machine testing of the runtime (hypothesis).

Hypothesis generates sequences of propose / approve / execute-with-a-fault / reconcile /
resolve / cancel / clock / crash-and-restart against one store, with a ground-truth
ledger standing in for the external system. After every step it checks invariants
that must hold for *any* sequence:

* no effect happens twice for one action (the ledger never shows two refunds per key);
* every dispatch is preceded by an approval since the previous dispatch;
* terminal states never change;
* an action leaves ``effect_unknown`` only through reconciliation or a human
  resolution, and returns to ``approved`` only when the effect really did not happen;
* the audit chain verifies, and the stored state is the last state event;
* claimed dispatches (``call.executing``) = tool calls + claims lost to injected crashes.

Failing examples are saved by hypothesis (``.hypothesis/``) and replayed first on the
next run. Set ``SAR_PROPERTY_EXAMPLES`` to run more examples (CI's deep job does).
"""

from __future__ import annotations

import os
from collections import Counter

import hypothesis.strategies as st
from hypothesis import HealthCheck, settings
from hypothesis.stateful import RuleBasedStateMachine, initialize, invariant, precondition, rule
from pydantic import BaseModel, ConfigDict, Field

from secure_agent_runtime.auth import TokenAuthenticator
from secure_agent_runtime.contracts import Applied, Effect, EffectNotApplied, NotApplied, ToolContext, ToolRegistry
from secure_agent_runtime.errors import SARError
from secure_agent_runtime.policy import Policy, Principal
from secure_agent_runtime.runtime import ApprovalRefused, ReplayDivergence, Runtime
from secure_agent_runtime.store import TERMINAL_STATES, Store

from .conftest import Clock

AGENT, APPROVER = "agent", "approver"
FAULTS = ["ok", "lost_after", "lost_before", "definite_failure", "garbage", "raise_after"]
EXAMPLES = int(os.environ.get("SAR_PROPERTY_EXAMPLES", "150"))


class RefundIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    amount: int = Field(gt=0)


class RefundOut(BaseModel):
    model_config = ConfigDict(extra="forbid")
    amount: int


class ConnectionLost(Exception):
    pass


class Ledger:
    """The external system. ``effects[key]`` counts real refunds per idempotency key."""

    def __init__(self) -> None:
        self.effects: Counter[str] = Counter()
        self.calls = 0
        self.fault = "ok"

    def refund(self, args: RefundIn, ctx: ToolContext) -> object:
        self.calls += 1
        fault, self.fault = self.fault, "ok"
        if fault == "lost_before":
            raise ConnectionLost
        if fault == "definite_failure":
            raise EffectNotApplied("declined")
        self.effects[ctx.idempotency_key] += 1
        if fault == "lost_after":
            raise ConnectionLost
        if fault == "raise_after":
            raise RuntimeError("boom after the effect")
        if fault == "garbage":
            return {"nope": True}
        return RefundOut(amount=args.amount)

    def reconcile(self, args: RefundIn, ctx: ToolContext) -> object:
        return Applied(RefundOut(amount=args.amount)) if self.effects[ctx.idempotency_key] else NotApplied()


class RuntimeMachine(RuleBasedStateMachine):
    @initialize()
    def setup(self) -> None:
        self.clock = Clock()
        self.ledger = Ledger()
        self.store = Store(now=self.clock)
        self.crash_next = False
        self.crashed_claims = 0
        self.keys: list[str] = []
        self.terminal: dict[str, str] = {}
        self._start()

    def _start(self) -> None:
        reg = ToolRegistry()
        reg.tool(name="refund", input=RefundIn, output=RefundOut, effect=Effect.EXTERNAL,
                 timeout_s=5)(self.ledger.refund)
        reg.reconciler("refund")(self.ledger.reconcile)

        def faults(point: str, key: str) -> None:
            if point == "after_claim" and self.crash_next:
                self.crash_next = False
                self.crashed_claims += 1
                raise SystemExit("simulated crash")

        self.rt = Runtime(registry=reg, policy=Policy(), store=self.store, approval_ttl_s=600,
                          authenticator=TokenAuthenticator(now=self.clock), faults=faults,
                          principals=[Principal(AGENT, grants=frozenset({"refund"})),
                                      Principal(APPROVER, can_approve=True)])

    # -- rules ---------------------------------------------------------------------------------- #

    @rule(call=st.sampled_from(["a", "b", "c", "d"]), amount=st.sampled_from([1, 2]))
    def propose(self, call: str, amount: int) -> None:
        try:
            o = self.rt.propose(run_id="r", principal_id=AGENT, call_id=call, tool="refund",
                                arguments={"amount": amount})
        except ReplayDivergence:
            return
        if o.key not in self.keys:
            self.keys.append(o.key)

    @precondition(lambda self: self.keys)
    @rule(i=st.integers(0, 3), who=st.sampled_from([APPROVER, APPROVER, AGENT, "mallory"]),
          right_digest=st.booleans(), scoped=st.booleans())
    def approve(self, i: int, who: str, right_digest: bool, scoped: bool) -> None:
        key = self.keys[i % len(self.keys)]
        row = self.store.get_call(key)
        digest = row.action_digest if right_digest else "sha256:" + "0" * 64
        token = self.rt.authenticator.issue(who, scope=row.action_digest if scoped else None)
        try:
            self.rt.approve(key, credential=token, action_digest=digest)
        except ApprovalRefused:
            pass

    @precondition(lambda self: self.keys)
    @rule(i=st.integers(0, 3), fault=st.sampled_from(FAULTS), retries=st.integers(0, 2))
    def approve_then_execute(self, i: int, fault: str, retries: int) -> None:
        """The common path, so that sequences reach dispatch, uncertainty and retries often."""
        key = self.keys[i % len(self.keys)]
        row = self.store.get_call(key)
        if row.state == "awaiting_approval":
            self.approve(i, APPROVER, True, True)
        self.execute(i, fault)
        for _ in range(retries):  # the agent retries; SAR must not redispatch an unknown outcome
            self.execute(i, "ok")

    @precondition(lambda self: self.keys)
    @rule(i=st.integers(0, 3), fault=st.sampled_from(FAULTS))
    def execute(self, i: int, fault: str) -> None:
        key = self.keys[i % len(self.keys)]
        self.ledger.fault = fault
        try:
            self.rt.execute(key)
        except SystemExit:
            pass  # crashed after the claim; restart() will recover it
        self.ledger.fault = "ok"

    @precondition(lambda self: self.keys)
    @rule(i=st.integers(0, 3))
    def reconcile(self, i: int) -> None:
        key = self.keys[i % len(self.keys)]
        before = self.store.get_call(key).state
        self.rt.reconcile(key)
        after = self.store.get_call(key).state
        if before == "effect_unknown" and after == "approved":
            assert self.ledger.effects[key] == 0, "re-approved although the effect happened"

    @precondition(lambda self: self.keys)
    @rule(i=st.integers(0, 3), redispatch=st.booleans())
    def resolve(self, i: int, redispatch: bool) -> None:
        """An *honest* operator: asserts what the ledger says."""
        key = self.keys[i % len(self.keys)]
        applied = self.ledger.effects[key] > 0
        try:
            self.rt.resolve(key, credential=self.rt.authenticator.issue(APPROVER), applied=applied,
                            redispatch=redispatch and not applied)
        except (ApprovalRefused, SARError, ValueError):
            pass

    @precondition(lambda self: len(self.keys) > 2)
    @rule()
    def cancel(self) -> None:
        self.rt.cancel(self.keys[-1])

    @rule(seconds=st.sampled_from([1, 1, 30, 700]))
    def advance(self, seconds: int) -> None:
        self.clock.advance(seconds)
        self.rt.expire_pending()

    @rule()
    def arm_crash(self) -> None:
        self.crash_next = True

    @rule()
    def restart(self) -> None:
        self.rt.close()
        self.crash_next = False
        self._start()  # start-up recovery moves orphaned executions to effect_unknown

    # -- invariants ------------------------------------------------------------------------------- #

    @invariant()
    def at_most_one_effect_per_action(self) -> None:
        assert all(n <= 1 for n in self.ledger.effects.values()), dict(self.ledger.effects)

    @invariant()
    def claims_equal_calls_plus_crashed_claims(self) -> None:
        if not hasattr(self, "store"):
            return
        assert len(self.store.events(kind="call.executing")) == self.ledger.calls + self.crashed_claims

    @invariant()
    def terminal_states_never_change(self) -> None:
        if not hasattr(self, "store"):
            return
        for row in self.store.calls():
            if row.key in self.terminal:
                assert row.state == self.terminal[row.key], (row.key, self.terminal[row.key], row.state)
            elif row.state in TERMINAL_STATES:
                self.terminal[row.key] = row.state

    @invariant()
    def history_is_lawful(self) -> None:
        if not hasattr(self, "store"):
            return
        assert self.store.verify_audit()[0]
        for row in self.store.calls():
            events = [e for e in self.store.events(call_key=row.key)
                      if e.kind.startswith("call.") and e.kind not in (
                          "call.requested", "call.replayed", "call.replay_divergence", "call.late_result_discarded")]
            assert events[-1].kind == f"call.{row.state}"
            approved_since_dispatch = False
            prev = None
            for e in events:
                if e.kind == "call.approved":
                    approved_since_dispatch = True
                if e.kind == "call.executing":
                    assert approved_since_dispatch, f"{row.key}: dispatch without a fresh approval"
                    approved_since_dispatch = False
                if prev == "call.effect_unknown" and e.kind != "call.effect_unknown":
                    assert "reconciled" in e.data or "resolved_by" in e.data, (row.key, e.kind, e.data)
                prev = e.kind

    def teardown(self) -> None:
        if hasattr(self, "store"):
            self.store.close()


RuntimeMachine.TestCase.settings = settings(
    max_examples=EXAMPLES, stateful_step_count=40, deadline=None,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.filter_too_much])
TestRuntimeStateMachine = RuntimeMachine.TestCase
