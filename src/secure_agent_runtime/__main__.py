"""Command line: ``python -m secure_agent_runtime`` (also installed as ``secure-agent-runtime``).

    demo [refund|frame|notes|all]      run the deterministic demos
    verify-receipt FILE [--key-env V]  check a receipt's digest (and HMAC, if a key is given)
    schema                             print the Agent Receipt JSON Schema
"""

from __future__ import annotations

import argparse
import json
import os
import sys


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="secure-agent-runtime", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    demo = sub.add_parser("demo", help="run a deterministic demo")
    demo.add_argument("name", nargs="?", default="all", choices=["refund", "frame", "notes", "all"])
    ver = sub.add_parser("verify-receipt", help="verify an Agent Receipt JSON file")
    ver.add_argument("file")
    ver.add_argument("--key-env", help="environment variable holding the HMAC key")
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

        with open(ns.file, encoding="utf-8") as f:
            receipt = json.load(f)
        key = None
        if ns.key_env:
            value = os.environ.get(ns.key_env)
            if not value:
                print(f"environment variable {ns.key_env} is not set", file=sys.stderr)
                return 2
            key = value.encode()
        problems = verify_receipt(receipt, signing_key=key)
        if problems:
            for p in problems:
                print(f"FAIL: {p}")
            return 1
        print(f"OK: {receipt['receipt_id']} outcome={receipt['outcome']}"
              + (" (signature verified)" if key else " (digest only; pass --key-env to check the signature)"))
        return 0
    if ns.cmd == "schema":
        from .receipts import receipt_json_schema

        print(json.dumps(receipt_json_schema(), indent=2))
        return 0
    return 2  # pragma: no cover


if __name__ == "__main__":
    sys.exit(main())
