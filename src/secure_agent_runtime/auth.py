"""Authenticated principals for approvals.

SAR never accepts an approver as a bare string. ``approve``, ``reject`` and ``resolve``
take an opaque *credential* (a signed token, a session assertion, whatever the host
uses) and pass it to the operator's :class:`Authenticator`, which returns an
:class:`AuthContext` or ``None``. The runtime then checks the context:

* ``subject`` must be a principal in the operator's directory with ``can_approve`` and
  must not be the requester;
* ``scope``, if set, must equal the action digest being approved (a credential minted
  for "approve refund(821, 1000)" can't approve anything else);
* ``expires_at``, if set, must be in the future;
* ``credential_id`` is consumed in the same transaction as the approval, so a credential
  can be used once (replay of an approval credential is refused).

The approval record stores the subject, method, issuer, scope and a digest of the
credential id, never the credential itself.

:class:`TokenAuthenticator` is a small in-memory implementation for demos and tests: it
mints random one-time tokens. A real deployment wraps its own identity provider.
"""

from __future__ import annotations

import hashlib
import secrets
import threading
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol

from .errors import SARError


class AuthenticationFailed(SARError):
    pass


@dataclass(frozen=True)
class AuthContext:
    subject: str              # principal id in the runtime's directory
    method: str               # how the host authenticated them, e.g. "oidc", "webauthn"
    issuer: str               # who vouches for it
    credential_id: str        # unique per credential; consumed on use
    scope: str | None = None  # an action digest this credential is limited to
    expires_at: float | None = None

    def __post_init__(self) -> None:
        for name in ("subject", "method", "issuer", "credential_id"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value:
                raise ValueError(f"AuthContext.{name} must be a non-empty string")

    def record(self) -> dict[str, Any]:
        """What goes into the approval record (no credential material)."""
        return {"subject": self.subject, "method": self.method, "issuer": self.issuer, "scope": self.scope,
                "credential": "sha256:" + hashlib.sha256(self.credential_id.encode()).hexdigest()}


class Authenticator(Protocol):
    def authenticate(self, credential: Any) -> AuthContext | None: ...


def demo_token(rt: Any, principal_id: str, *, scope: str | None = None) -> str:
    """Mint a one-time credential from a runtime that uses :class:`TokenAuthenticator`."""
    auth = getattr(rt, "authenticator", None)
    if not isinstance(auth, TokenAuthenticator):
        raise TypeError("this runtime does not use the demo TokenAuthenticator")
    return auth.issue(principal_id, scope=scope)


class TokenAuthenticator:
    """Demo/test authenticator: ``issue(principal_id)`` returns a random one-time token.

    It stands in for the host's real identity system. Do not use it to authenticate
    people in production: anyone who can call ``issue`` can mint approvals.
    """

    def __init__(self, now: Callable[[], float] | None = None, ttl_s: float = 300.0) -> None:
        self._tokens: dict[str, AuthContext] = {}
        self._lock = threading.Lock()
        self._now = now
        self.ttl_s = ttl_s

    def issue(self, principal_id: str, *, scope: str | None = None, method: str = "demo-token") -> str:
        token = secrets.token_urlsafe(24)
        expires = self._now() + self.ttl_s if self._now else None
        with self._lock:
            self._tokens[token] = AuthContext(subject=principal_id, method=method, issuer="demo",
                                              credential_id=token, scope=scope, expires_at=expires)
        return token

    def authenticate(self, credential: Any) -> AuthContext | None:
        if not isinstance(credential, str):
            return None
        with self._lock:
            return self._tokens.get(credential)
