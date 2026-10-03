"""Deterministic policy: who may call which tool, with which arguments, and with whose approval.

Policy sees only structured facts: the principal, the tool's registered spec and the
*validated* arguments. It never sees model text, tool descriptions or earlier tool
output, so instructions injected into any of those can make the model *ask* for a call
but can't change whether the call is allowed.

Evaluation order, first match wins:

1. tool not granted to the principal                -> DENY (least privilege, default deny)
2. any argument constraint fails                    -> DENY
3. tool's effect or name requires approval          -> REQUIRE_APPROVAL
4. otherwise                                        -> ALLOW
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any, Callable

from .contracts import Effect, ToolSpec


class Verdict(str, enum.Enum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


@dataclass(frozen=True)
class Decision:
    verdict: Verdict
    reason: str
    rule: str


@dataclass(frozen=True)
class Principal:
    """An identity the runtime acts for. ``grants`` is the complete set of tools it may use."""

    id: str
    grants: frozenset[str] = frozenset()
    can_approve: bool = False


# A constraint returns None if the arguments are acceptable, else a reason.
Constraint = Callable[[dict[str, Any]], "str | None"]


@dataclass
class Policy:
    require_approval_for_effects: frozenset[Effect] = frozenset({Effect.WRITE, Effect.EXTERNAL})
    require_approval_for_tools: frozenset[str] = frozenset()
    constraints: dict[str, list[Constraint]] = field(default_factory=dict)

    def constrain(self, tool: str, check: Constraint) -> Policy:
        self.constraints.setdefault(tool, []).append(check)
        return self

    def decide(self, principal: Principal, spec: ToolSpec, args: dict[str, Any]) -> Decision:
        if spec.name not in principal.grants:
            return Decision(Verdict.DENY, f"{principal.id} is not granted {spec.name}", "grant")
        for check in self.constraints.get(spec.name, []):
            problem = check(args)
            if problem:
                return Decision(Verdict.DENY, problem, f"constraint:{getattr(check, '__name__', 'check')}")
        if spec.effect in self.require_approval_for_effects or spec.name in self.require_approval_for_tools:
            return Decision(Verdict.REQUIRE_APPROVAL, f"{spec.effect.value} tool {spec.name} needs approval",
                            "approval")
        return Decision(Verdict.ALLOW, "granted, constraints pass, no approval needed", "allow")
