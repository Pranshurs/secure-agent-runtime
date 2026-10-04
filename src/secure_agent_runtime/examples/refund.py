"""Demo: a refund whose response is lost after the money has moved.

    refund ₹4,500  ->  service processes it  ->  connection drops  ->  caller retries

An unsafe caller retries and refunds the customer twice. SAR records the first attempt as
``effect_unknown``, refuses to dispatch it again on retry, asks the payment service what
happened (reconciliation), finds the existing refund, and closes the action with one
refund and a verifiable receipt.

Everything is local and deterministic: :class:`PaymentService` is an in-memory mock.
"""

from __future__ import annotations

import threading
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from ..contracts import Applied, Effect, NotApplied, ToolContext, ToolRegistry
from ..effects import FrameSpec, MappingObserver, Required
from ..policy import Policy, Principal
from ..receipts import verify_receipt
from ..runtime import Runtime
from ..store import Store

AGENT = "support-agent"
APPROVER = "finance-lead"


class ConnectionLost(Exception):
    """The request may or may not have been processed; the response never arrived."""


class PaymentService:
    """A mock payment provider. ``fail_next`` injects one fault into the next refund call:

    * ``"after_effect"``: process the refund, then lose the response;
    * ``"before_effect"``: lose the request before anything happens.

    Refunds are *not* deduplicated by idempotency key here, so the demo shows SAR's
    reconciliation doing the work rather than the provider.
    """

    def __init__(self) -> None:
        self.refunds: dict[str, dict[str, Any]] = {}
        self.fail_next: str | None = None
        self.calls = 0
        self._lock = threading.Lock()

    def refund(self, order: int, amount_inr: int, idempotency_key: str | None = None) -> str:
        with self._lock:
            self.calls += 1
            fault, self.fail_next = self.fail_next, None
            if fault == "before_effect":
                raise ConnectionLost("request lost before processing")
            refund_id = f"rf_{len(self.refunds) + 1:04d}"
            self.refunds[refund_id] = {"order": order, "amount_inr": amount_inr, "idempotency_key": idempotency_key}
            if fault == "after_effect":
                raise ConnectionLost("refund processed, response lost")
            return refund_id

    def find_by_key(self, idempotency_key: str) -> tuple[str, dict[str, Any]] | None:
        with self._lock:
            return next(((rid, r) for rid, r in self.refunds.items() if r["idempotency_key"] == idempotency_key), None)

    def total_refunded(self, order: int) -> int:
        return sum(r["amount_inr"] for r in self.refunds.values() if r["order"] == order)


class RefundIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    order: int = Field(gt=0)
    amount_inr: int = Field(gt=0, le=100_000)


class RefundOut(BaseModel):
    model_config = ConfigDict(extra="forbid")
    refund_id: str
    order: int
    amount_inr: int


def build_runtime(service: PaymentService, store: Store | None = None, **kw: Any) -> Runtime:
    reg = ToolRegistry()
    observer = MappingObserver(lambda: {f"refunds/{rid}": r for rid, r in service.refunds.items()})

    def frame(args: RefundIn) -> FrameSpec:
        # Exactly one new refund, for this order and amount. Anything else is undeclared.
        return FrameSpec(required=(Required("refunds/*", "added", count=1,
                                            after_contains=f'"amount_inr":{args.amount_inr},"idempotency_key"'),))

    @reg.tool(input=RefundIn, output=RefundOut, effect=Effect.EXTERNAL, version="2026-10",
              timeout_s=2.0, observer=observer, frame=frame)
    def refund(args: RefundIn, ctx: ToolContext) -> RefundOut:
        """Refund an order."""
        rid = service.refund(args.order, args.amount_inr, idempotency_key=ctx.idempotency_key)
        return RefundOut(refund_id=rid, order=args.order, amount_inr=args.amount_inr)

    @reg.reconciler("refund")
    def find_refund(args: RefundIn, ctx: ToolContext) -> Applied | NotApplied:
        found = service.find_by_key(ctx.idempotency_key)
        if found is None:
            return NotApplied()
        rid, r = found
        return Applied(RefundOut(refund_id=rid, order=r["order"], amount_inr=r["amount_inr"]))

    return Runtime(registry=reg, policy=Policy(), store=store or Store(), principals=[
        Principal(AGENT, grants=frozenset({"refund"})), Principal(APPROVER, can_approve=True)], **kw)


def unsafe_retry(service: PaymentService, order: int, amount_inr: int, attempts: int = 2) -> None:
    """What a naive tool loop does: call, and on a network error, call again."""
    for _ in range(attempts):
        try:
            service.refund(order, amount_inr)
            return
        except ConnectionLost:
            continue


def run_sar(service: PaymentService, *, fault: str, store: Store | None = None) -> tuple[Runtime, str, list[str]]:
    """Propose, approve, dispatch (with the fault), retry, reconcile. Returns a trace."""
    rt = build_runtime(service, store)
    trace = []
    args = {"order": 821, "amount_inr": 4500}
    o = rt.propose(run_id="ticket-77", principal_id=AGENT, call_id="call_1", tool="refund", arguments=args)
    trace.append(f"proposed refund(order=821, amount_inr=4500) -> {o.state}")
    rt.approve(o.key, approver_id=APPROVER, action_digest=o.action_digest)
    trace.append(f"{APPROVER} approved action {o.action_digest[:23]}...")
    service.fail_next = fault
    out = rt.execute(o.key)
    trace.append(f"dispatch 1 -> {out.state.upper()} ({out.reason})")
    retry = rt.propose(run_id="ticket-77", principal_id=AGENT, call_id="call_1", tool="refund", arguments=args)
    out = rt.execute(retry.key)
    trace.append(f"agent retries the same call -> {out.state.upper()}, no dispatch")
    out = rt.reconcile(o.key)
    trace.append(f"reconcile -> {out.state.upper()} ({out.reason})")
    if out.state == "approved":
        out = rt.execute(o.key)
        trace.append(f"dispatch 2 -> {out.state.upper()}")
    return rt, o.key, trace


def main() -> None:  # pragma: no cover - exercised by tests/test_demos.py via subprocess
    print("Scenario: refund ₹4,500 -> service processes it -> response lost -> caller retries\n")
    naive = PaymentService()
    naive.fail_next = "after_effect"
    unsafe_retry(naive, 821, 4500)
    print("UNSAFE BASELINE (retry on error)")
    print(f"  refunds issued: {len(naive.refunds)}   total refunded: ₹{naive.total_refunded(821):,}")
    print("  -> customer refunded twice\n")

    for fault, title in (("after_effect", "SAR, response lost AFTER the refund"),
                         ("before_effect", "SAR, request lost BEFORE the refund")):
        service = PaymentService()
        rt, key, trace = run_sar(service, fault=fault)
        print(title)
        for line in trace:
            print("  " + line)
        receipt = rt.receipt(key, signing_key=b"demo-key")
        problems = verify_receipt(receipt, signing_key=b"demo-key", store=rt.store)
        print(f"  refunds issued: {len(service.refunds)}   total refunded: ₹{service.total_refunded(821):,}"
              f"   provider calls: {service.calls}")
        print(f"  receipt {receipt['receipt_id']}: outcome {receipt['outcome'].upper()}, "
              f"dispatches {receipt['execution']['dispatches']}, "
              f"verification {'OK' if not problems else problems}\n")


if __name__ == "__main__":  # pragma: no cover
    main()
