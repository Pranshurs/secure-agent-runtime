"""Command line: ``python -m secure_agent_runtime`` (also installed as ``secure-agent-runtime``).

    demo [refund|frame|notes|all]      run the deterministic demos
    verify-receipt FILE [--public-key ID=HEX | --key-env V]
                                       check a receipt's digest and, given a key, its signature
                                       (exit 0 ok, 1 failed verification, 2 could not check)
    schema                             print the Agent Receipt JSON Schema
"""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from typing import Any

MAX_RECEIPT_BYTES = 4 * 1024 * 1024


def _read_receipt(path: str) -> object:
    st = os.stat(path)
    if not stat.S_ISREG(st.st_mode):
        raise ValueError("not a regular file")
    if st.st_size > MAX_RECEIPT_BYTES:
        raise ValueError(f"larger than {MAX_RECEIPT_BYTES} bytes")
    with open(path, "rb") as f:
        data = f.read(MAX_RECEIPT_BYTES + 1)
    return json.loads(data.decode("utf-8"))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="secure-agent-runtime", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    demo = sub.add_parser("demo", help="run a deterministic demo")
    demo.add_argument("name", nargs="?", default="all", choices=["refund", "frame", "notes", "all"])
    ver = sub.add_parser("verify-receipt", help="verify an Agent Receipt JSON file")
    ver.add_argument("file")
    ver.add_argument("--key-env", help="environment variable holding the HMAC key")
    ver.add_argument("--public-key", help="KEY_ID=HEX trusted Ed25519 public key (raw 32 bytes, hex)")
    sub.add_parser("schema", help="print the Agent Receipt JSON Schema")
    ns = ap.parse_args(argv)

    if ns.cmd == "demo":
        from .examples import notes, refund, version_bump

        demos = {"refund": refund.main, "frame": version_bump.main, "notes": notes._demo}
        for name in (["refund", "frame", "notes"] if ns.name == "all" else [ns.name]):
            if ns.name == "all":
                print(f"=== {name} ===")
            demos[name]()
            print()
        return 0
    if ns.cmd == "verify-receipt":
        from .receipts import verify_receipt
        from .signing import MIN_HMAC_KEY

        # Exit codes: 0 verified, 1 the receipt failed verification, 2 could not check.
        try:
            receipt: Any = _read_receipt(ns.file)
        except (OSError, ValueError, RecursionError) as exc:
            print(f"ERROR: cannot read receipt: {exc}", file=sys.stderr)
            return 2
        kwargs: dict[str, object] = {}
        if ns.key_env:
            value = os.environ.get(ns.key_env)
            if not value:
                print(f"ERROR: environment variable {ns.key_env} is not set", file=sys.stderr)
                return 2
            if len(value.encode()) < MIN_HMAC_KEY:  # an unusable key: we could not check, not "it failed"
                print(f"ERROR: the HMAC key in {ns.key_env} is shorter than {MIN_HMAC_KEY} bytes", file=sys.stderr)
                return 2
            kwargs["signing_key"] = value.encode()
        if ns.public_key:
            try:
                key_id, hexkey = ns.public_key.split("=", 1)
                raw = bytes.fromhex(hexkey)
                if len(raw) != 32:
                    raise ValueError("an Ed25519 public key is 32 bytes")
                kwargs["public_keys"] = {key_id: raw}
            except ValueError:
                print("ERROR: --public-key must be KEY_ID=HEX with a 32-byte Ed25519 public key", file=sys.stderr)
                return 2
        problems = verify_receipt(receipt, **kwargs)  # type: ignore[arg-type]
        if problems:
            for p in problems:
                print(f"FAIL: {p}")
            return 1
        signed = "signing_key" in kwargs or "public_keys" in kwargs
        print(f"OK: {receipt.get('receipt_id')} outcome={receipt.get('outcome')}"
              + (" (signature verified)" if signed else " (digest only; pass --public-key or --key-env to "
                                                        "check who signed it)"))
        return 0
    if ns.cmd == "schema":
        from .receipts import receipt_json_schema

        print(json.dumps(receipt_json_schema(), indent=2))
        return 0
    return 2  # pragma: no cover


if __name__ == "__main__":
    sys.exit(main())
