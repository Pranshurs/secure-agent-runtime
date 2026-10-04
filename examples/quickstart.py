"""The README quick start, runnable: python examples/quickstart.py (twice: the rerun replays).

Needs the signing extra: pip install -e '.[signing]'
"""

from pydantic import BaseModel, ConfigDict

from secure_agent_runtime import (
    Applied,
    Effect,
    NotApplied,
    Policy,
    Principal,
    Runtime,
    Store,
    ToolRegistry,
    verify_receipt,
)
from secure_agent_runtime.auth import TokenAuthenticator
from secure_agent_runtime.signing import Ed25519Signer  # needs the 'signing' extra


class Payments:                                   # stands in for your provider's client
    def __init__(self):
        self.refunds = {}

    def refund(self, order, amount, idempotency_key):
        self.refunds[idempotency_key] = f"rf_{len(self.refunds) + 1}"
        return self.refunds[idempotency_key]


payments = Payments()


class RefundIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    order: int
    amount_inr: int


class RefundOut(BaseModel):
    model_config = ConfigDict(extra="forbid")
    refund_id: str


reg = ToolRegistry()


@reg.tool(input=RefundIn, output=RefundOut, effect=Effect.EXTERNAL, version="2026-10")
def refund(args, ctx):
    return RefundOut(refund_id=payments.refund(args.order, args.amount_inr,
                                               idempotency_key=ctx.idempotency_key))


@reg.reconciler("refund")
def find_refund(args, ctx):                       # "did this action's effect happen?"
    rid = payments.refunds.get(ctx.idempotency_key)
    return Applied(RefundOut(refund_id=rid)) if rid else NotApplied()


auth = TokenAuthenticator()                       # demo only: use your identity provider
with Store("sar.db") as store:
    rt = Runtime(registry=reg, policy=Policy(), store=store, authenticator=auth,
                 principals=[Principal("support-agent", grants=frozenset({"refund"})),
                             Principal("finance-lead", can_approve=True)])

    o = rt.propose(run_id="ticket-77", principal_id="support-agent", call_id="call_1",
                   tool="refund", arguments={"order": 821, "amount_inr": 4500})
    print(o.state)            # awaiting_approval (EXTERNAL needs a person); on a rerun, the
                              # recorded outcome: the same call id is never executed twice
    if o.state == "awaiting_approval":
        # The approver signs in, is shown o.action_digest, and approves exactly that action.
        credential = auth.issue("finance-lead", scope=o.action_digest)
        rt.approve(o.key, credential=credential, action_digest=o.action_digest)

    o = rt.execute(o.key)                         # succeeded | effect_unknown | failed | ...
    if o.state == "effect_unknown":
        o = rt.reconcile(o.key)                   # asks find_refund; never blindly re-runs
    print(o.state)                                # succeeded

    signer = Ed25519Signer.generate("ops-2026-10")
    receipt = rt.receipt(o.key, signer=signer)    # Agent Receipt, sar.receipt/v1
    print(verify_receipt(receipt, public_keys={signer.key_id: signer.public_key_bytes()},
                         expect_key=o.key, store=store))   # [] means verified
    rt.close()
