"""Demo: a refund whose response is lost after the money has moved.

    refund ₹4,500  ->  service processes it  ->  connection drops  ->  caller retries

An unsafe caller retries and refunds the customer twice. SAR records the first attempt as
``effect_unknown``, refuses to dispatch it again on retry, asks the payment service what
happened (reconciliation), finds the existing refund, and closes the action with one
refund and a verifiable receipt.

Everything is local and deterministic. :class:`PaymentService` is a mock provider whose
ledger is a SQLite file, so a refund made by a worker process (or by a runtime that was
then killed) is visible to whoever looks next, as with a real provider.
"""

from __future__ import annotations

import contextlib
import functools
import os
import sqlite3
import tempfile
import time
from collections.abc import Iterator
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from ..auth import TokenAuthenticator, demo_token
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
    """A mock payment provider backed by a SQLite ledger file.

    ``fail_next`` injects one fault into the next refund call:

    * ``"after_effect"``: process the refund, then lose the response;
    * ``"before_effect"``: lose the request before anything happens;
    * ``"slow_before_effect"`` / ``"slow_after_effect"``: write ``<ledger>.inflight`` and
      sleep (up to 30 s) before / after processing, so a test can kill whoever is waiting.

    ``fail_reconcile_next = "slow"`` does the same inside :meth:`find_by_key`.
    Refunds are *not* deduplicated by idempotency key, so the demo shows SAR's
    reconciliation doing the work rather than the provider.
    """

    def __init__(self, path: str | None = None) -> None:
        if path is None:
            fd, path = tempfile.mkstemp(prefix="sar-ledger-", suffix=".db")
            os.close(fd)
        self.path = path
        with self._db() as db:
            db.execute("CREATE TABLE IF NOT EXISTS refunds (n INTEGER PRIMARY KEY AUTOINCREMENT, order_id INTEGER,"
                       " amount_inr INTEGER, idempotency_key TEXT)")
            db.execute("CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT)")

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        db.execute("PRAGMA busy_timeout=30000")
        return db

    @contextlib.contextmanager
    def _db(self) -> Iterator[sqlite3.Connection]:
        # sqlite3's own context manager commits but never closes; close explicitly.
        db = self._connect()
        try:
            yield db
        finally:
            db.close()

    def _take(self, db: sqlite3.Connection, k: str) -> str | None:
        row = db.execute("SELECT v FROM meta WHERE k=?", (k,)).fetchone()
        db.execute("DELETE FROM meta WHERE k=?", (k,))
        return row[0] if row else None

    def _set(self, k: str, v: str | None) -> None:
        with self._db() as db:
            if v is None:
                db.execute("DELETE FROM meta WHERE k=?", (k,))
            else:
                db.execute("INSERT OR REPLACE INTO meta VALUES (?,?)", (k, v))

    @property
    def fail_next(self) -> str | None:
        with self._db() as db:
            row = db.execute("SELECT v FROM meta WHERE k='fail_next'").fetchone()
        return row[0] if row else None

    @fail_next.setter
    def fail_next(self, value: str | None) -> None:
        self._set("fail_next", value)

    @property
    def fail_reconcile_next(self) -> str | None:
        return None

    @fail_reconcile_next.setter
    def fail_reconcile_next(self, value: str | None) -> None:
        self._set("fail_reconcile_next", value)

    @property
    def calls(self) -> int:
        with self._db() as db:
            row = db.execute("SELECT v FROM meta WHERE k='calls'").fetchone()
        return int(row[0]) if row else 0

    def _pause(self) -> None:
        with open(self.path + ".inflight", "w") as f:
            f.write(str(os.getpid()))
        time.sleep(30)

    def refund(self, order: int, amount_inr: int, idempotency_key: str | None = None) -> str:
        db = self._connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            calls = db.execute("SELECT v FROM meta WHERE k='calls'").fetchone()
            db.execute("INSERT OR REPLACE INTO meta VALUES ('calls', ?)", (str(int(calls[0]) + 1 if calls else 1),))
            fault = self._take(db, "fail_next")
            db.execute("COMMIT")
            if fault == "before_effect":
                raise ConnectionLost("request lost before processing")
            if fault == "slow_before_effect":
                self._pause()
            cur = db.execute("INSERT INTO refunds (order_id, amount_inr, idempotency_key) VALUES (?,?,?)",
                             (order, amount_inr, idempotency_key))
            refund_id = f"rf_{cur.lastrowid:04d}"
            if fault == "slow_after_effect":
                self._pause()
            if fault == "after_effect":
                raise ConnectionLost("refund processed, response lost")
            return refund_id
        finally:
            db.close()

    def find_by_key(self, idempotency_key: str) -> tuple[str, dict[str, Any]] | None:
        with self._db() as db:
            if self._take(db, "fail_reconcile_next") == "slow":
                self._pause()
            row = db.execute("SELECT n, order_id, amount_inr, idempotency_key FROM refunds WHERE idempotency_key=?"
                             " ORDER BY n LIMIT 1", (idempotency_key,)).fetchone()
        if row is None:
            return None
        return f"rf_{row[0]:04d}", {"order": row[1], "amount_inr": row[2], "idempotency_key": row[3]}

    @property
    def refunds(self) -> dict[str, dict[str, Any]]:
        with self._db() as db:
            rows = db.execute("SELECT n, order_id, amount_inr, idempotency_key FROM refunds ORDER BY n").fetchall()
        return {f"rf_{n:04d}": {"order": o, "amount_inr": a, "idempotency_key": k} for n, o, a, k in rows}

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


def _refund(service_path: str, args: RefundIn, ctx: ToolContext) -> RefundOut:
    """Module-level so a spawned worker process can import it."""
    rid = PaymentService(service_path).refund(args.order, args.amount_inr, idempotency_key=ctx.idempotency_key)
    return RefundOut(refund_id=rid, order=args.order, amount_inr=args.amount_inr)


def build_runtime(service: PaymentService, store: Store | None = None, *, isolation: str = "process",
                  **kw: Any) -> Runtime:
    """``isolation="process"`` (the default) runs each refund in its own worker process,
    which is killed on timeout. ``"thread"`` runs it in-process (tests use it to swap in
    misbehaving tools)."""
    reg = ToolRegistry()
    observer = MappingObserver(lambda: {f"refunds/{rid}": r for rid, r in service.refunds.items()})

    def frame(args: RefundIn) -> FrameSpec:
        # Exactly one new refund, for this order and amount. Anything else is undeclared.
        return FrameSpec(required=(Required("refunds/*", "added", count=1,
                                            after_contains=f'"amount_inr":{args.amount_inr},"idempotency_key"'),))

    if isolation == "process":
        fn: Any = functools.partial(_refund, service.path)
    else:
        def fn(args: RefundIn, ctx: ToolContext) -> RefundOut:
            rid = service.refund(args.order, args.amount_inr, idempotency_key=ctx.idempotency_key)
            return RefundOut(refund_id=rid, order=args.order, amount_inr=args.amount_inr)

    reg.tool(name="refund", input=RefundIn, output=RefundOut, effect=Effect.EXTERNAL, version="2026-10",
             timeout_s=10.0 if isolation == "process" else 2.0, observer=observer, frame=frame,
             isolation=isolation)(fn)

    @reg.reconciler("refund")
    def find_refund(args: RefundIn, ctx: ToolContext) -> Applied | NotApplied:
        found = service.find_by_key(ctx.idempotency_key)
        if found is None:
            return NotApplied()
        rid, r = found
        return Applied(RefundOut(refund_id=rid, order=r["order"], amount_inr=r["amount_inr"]))

    store = store or Store()
    kw.setdefault("authenticator", TokenAuthenticator(now=store.now))
    return Runtime(registry=reg, policy=Policy(), store=store, principals=[
        Principal(AGENT, grants=frozenset({"refund"})), Principal(APPROVER, can_approve=True)], **kw)


def approve_as_finance(rt: Runtime, o: Any) -> Any:
    """The finance lead approves exactly the action they were shown."""
    token = demo_token(rt, APPROVER, scope=o.action_digest)  # minted for this action only
    return rt.approve(o.key, credential=token, action_digest=o.action_digest)


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
    approve_as_finance(rt, o)
    trace.append(f"{APPROVER} approved action {(o.action_digest or '')[:23]}...")
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
        rt, key, trace = run_sar(service, fault=fault, store=_temp_store())
        print(title)
        for line in trace:
            print("  " + line)
        signer, keys = _demo_signer()
        receipt = rt.receipt(key, signer=signer)
        problems = verify_receipt(receipt, store=rt.store, expect_key=key, **keys)
        print(f"  refunds issued: {len(service.refunds)}   total refunded: ₹{service.total_refunded(821):,}"
              f"   provider calls: {service.calls}")
        print(f"  receipt {receipt['receipt_id']}: outcome {receipt['outcome'].upper()}, "
              f"dispatches {receipt['execution']['dispatches']}, {receipt['signature']['alg']} signature, "
              f"verification {'OK' if not problems else problems}\n")


def _temp_store() -> Store:
    return Store(os.path.join(tempfile.mkdtemp(prefix="sar-demo-"), "sar.db"))


def _demo_signer() -> tuple[Any, dict[str, Any]]:
    """Ed25519 when the 'signing' extra is installed, else HMAC with a random key."""
    from ..signing import Ed25519Signer, HmacSigner

    try:
        signer = Ed25519Signer.generate("demo-ed25519")
        return signer, {"public_keys": {signer.key_id: signer.public_key_bytes()}}
    except Exception:
        key = os.urandom(32)
        return HmacSigner(key, "demo-hmac"), {"signing_key": key}


if __name__ == "__main__":  # pragma: no cover
    main()
