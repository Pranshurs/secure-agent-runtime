"""The canonical action: one proposed tool call, after validation, in a versioned envelope.

The model proposes a tool name and raw arguments. The runtime turns that into an
:class:`Action` whose fields come from operator-controlled facts (who is acting, which
registered tool, which version and schema) plus the *validated* arguments. Its
:attr:`Action.digest` is the identity that approvals are bound to and receipts refer to.

Canonical form: JSON with sorted keys, no insignificant whitespace, UTF-8, no NaN or
Infinity, integers and strings exactly as validated. Dict ordering never matters. A
change to any argument, the tool, its version, its input/output schema, the actor, the
run, the idempotency key, the declared frame or the deadline changes the digest.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass, field
from typing import Any

from .contracts import canonical_json

ACTION_SCHEMA = "sar.action/v1"


def sha256_text(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def args_digest(args: dict[str, Any], salt: str = "") -> str:
    """Salted, so a receipt's digest of low-entropy arguments (an amount, a short id) can't
    be reversed by trying every value. Whoever holds the stored action can recompute it."""
    return sha256_text(salt + canonical_json(args))


def new_salt() -> str:
    return secrets.token_hex(16)


def action_id_for(idempotency_key: str) -> str:
    """Deterministic, so a replayed proposal maps to the same action id."""
    return "act_" + hashlib.sha256(idempotency_key.encode("utf-8")).hexdigest()[:24]


@dataclass(frozen=True)
class Action:
    action_id: str
    idempotency_key: str
    actor: str
    run_id: str
    tool: str
    tool_version: str
    schema_digest: str
    args: dict[str, Any]
    authority: str  # the tool's registered Effect: read | write | external
    frame: dict[str, Any] | None  # declared effects (FrameSpec.to_json()), if any
    created_at: float
    deadline: float | None = None
    salt: str = field(default="")

    @property
    def args_digest(self) -> str:
        return args_digest(self.args, self.salt)

    def body(self) -> dict[str, Any]:
        """Everything the digest covers. Arguments are included in full."""
        return {
            "schema": ACTION_SCHEMA, "action_id": self.action_id, "idempotency_key": self.idempotency_key,
            "actor": self.actor, "context": {"run_id": self.run_id},
            "tool": {"name": self.tool, "version": self.tool_version, "schema_digest": self.schema_digest},
            "args": self.args, "args_digest": self.args_digest, "authority": self.authority,
            "frame": self.frame, "created_at": self.created_at, "deadline": self.deadline,
            "salt": self.salt,
        }

    @property
    def digest(self) -> str:
        return sha256_text(canonical_json(self.body()))

    def public(self) -> dict[str, Any]:
        """The envelope without the argument values (for receipts)."""
        b = self.body()
        del b["args"], b["salt"]
        b["digest"] = self.digest
        return b

    @classmethod
    def from_body(cls, b: dict[str, Any]) -> Action:
        if b.get("schema") != ACTION_SCHEMA:
            raise ValueError(f"unsupported action schema {b.get('schema')!r}")
        return cls(action_id=b["action_id"], idempotency_key=b["idempotency_key"], actor=b["actor"],
                   run_id=b["context"]["run_id"], tool=b["tool"]["name"], tool_version=b["tool"]["version"],
                   schema_digest=b["tool"]["schema_digest"], args=b["args"], authority=b["authority"],
                   frame=b["frame"], created_at=b["created_at"], deadline=b["deadline"], salt=b["salt"])
