"""Receipt signers.

A signature covers ``{"alg", "key_id", "digest"}`` (canonical JSON), so the algorithm
and key id are authenticated too, and the receipt digest covers everything else.

* :class:`Ed25519Signer` is the public-verifiability option: a verifier needs only the
  public key, so anyone can check a receipt and only the key holder can make one.
  Requires the ``signing`` extra (``pip install 'secure-agent-runtime[signing]'``), which
  pulls in ``cryptography``.
* :class:`HmacSigner` (HMAC-SHA256) is symmetric: anyone who can verify can also forge.
  Use it only inside one trust domain.

Key management (generation, storage, rotation, revocation) is the operator's job; SAR
only uses the keys it is given.
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Any

from .contracts import canonical_json
from .errors import SARError

MIN_HMAC_KEY = 16


def signed_message(alg: str, key_id: str, digest: str) -> bytes:
    return canonical_json({"alg": alg, "digest": digest, "key_id": key_id}).encode("utf-8")


def _check_key_id(key_id: Any) -> str:
    if not isinstance(key_id, str) or not key_id or len(key_id) > 128:
        raise ValueError("key_id must be a non-empty string of at most 128 characters")
    return key_id


class HmacSigner:
    alg = "HMAC-SHA256"

    def __init__(self, key: bytes, key_id: str = "default") -> None:
        if not isinstance(key, bytes) or len(key) < MIN_HMAC_KEY:
            raise ValueError(f"HMAC key must be bytes of at least {MIN_HMAC_KEY} bytes")
        self._key = key
        self.key_id = _check_key_id(key_id)

    def sign(self, digest: str) -> str:
        return hmac.new(self._key, signed_message(self.alg, self.key_id, digest), hashlib.sha256).hexdigest()

    def verify(self, digest: str, key_id: str, value: str) -> bool:
        expected = hmac.new(self._key, signed_message(self.alg, key_id, digest), hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected.encode(), value.encode("utf-8", "replace"))


def _crypto() -> Any:
    try:
        from cryptography.hazmat.primitives.asymmetric import ed25519
    except ImportError as exc:
        raise SARError("Ed25519 receipts need the 'signing' extra: pip install 'secure-agent-runtime[signing]'") \
            from exc
    return ed25519


class Ed25519Signer:
    alg = "Ed25519"

    def __init__(self, private_key: Any, key_id: str) -> None:
        ed25519 = _crypto()
        if not isinstance(private_key, ed25519.Ed25519PrivateKey):
            raise TypeError("private_key must be a cryptography Ed25519PrivateKey")
        self._key = private_key
        self.key_id = _check_key_id(key_id)

    @classmethod
    def generate(cls, key_id: str) -> Ed25519Signer:
        return cls(_crypto().Ed25519PrivateKey.generate(), key_id)

    def public_key_bytes(self) -> bytes:
        from cryptography.hazmat.primitives import serialization

        return self._key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    def sign(self, digest: str) -> str:
        return self._key.sign(signed_message(self.alg, self.key_id, digest)).hex()


def verify_ed25519(public_key: bytes, digest: str, key_id: str, value: str) -> bool:
    ed25519 = _crypto()
    from cryptography.exceptions import InvalidSignature

    try:
        key = ed25519.Ed25519PublicKey.from_public_bytes(public_key)
        key.verify(bytes.fromhex(value), signed_message("Ed25519", key_id, digest))
    except (InvalidSignature, ValueError, TypeError):
        return False
    return True
