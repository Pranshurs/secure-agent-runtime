"""The demos and CLI, run as a user would run them (in a subprocess)."""

from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest

from .conftest import cred


def cli(*args, env=None):
    return subprocess.run([sys.executable, "-m", "secure_agent_runtime", *args], capture_output=True, text=True,
                          timeout=60, env={**os.environ, **(env or {})})


def test_refund_demo_shows_double_refund_and_sar_preventing_it():
    p = cli("demo", "refund")
    assert p.returncode == 0, p.stderr
    out = p.stdout
    assert "refunds issued: 2   total refunded: ₹9,000" in out
    assert out.count("refunds issued: 1   total refunded: ₹4,500") == 2
    assert "EFFECT_UNKNOWN, no dispatch" in out and "verification OK" in out


def test_frame_demo_shows_outcome_check_passing_and_frame_failing():
    p = cli("demo", "frame")
    assert p.returncode == 0, p.stderr
    careful, sloppy = p.stdout.split("SLOPPY AGENT")
    assert "OUTCOME:                     VERIFIED" in careful
    assert "conventional outcome check:  PASS" in sloppy
    assert "FORBIDDEN EFFECTS:           1 ['tests/test_pkg.py']" in sloppy
    assert "OUTCOME:                     VIOLATED" in sloppy


def test_notes_demo_and_all():
    p = cli("demo")
    assert p.returncode == 0, p.stderr
    assert "=== refund ===" in p.stdout and "=== frame ===" in p.stdout and "delete_note  denied" in p.stdout


@pytest.fixture
def receipt_file(tmp_path, store):
    from secure_agent_runtime.examples import refund as rf

    rt = rf.build_runtime(rf.PaymentService(), store)
    o = rt.propose(run_id="t", principal_id=rf.AGENT, call_id="c", tool="refund",
                   arguments={"order": 1, "amount_inr": 10})
    rt.approve(o.key, credential=cred(rt, rf.APPROVER), action_digest=o.action_digest)
    rt.execute(o.key)
    path = tmp_path / "receipt.json"
    path.write_text(json.dumps(rt.receipt(o.key, signing_key=b"k3y-0123456789abcdef")))
    return path


def test_verify_receipt_cli(receipt_file):
    ok = cli("verify-receipt", str(receipt_file), "--key-env", "SAR_KEY", env={"SAR_KEY": "k3y-0123456789abcdef"})
    assert ok.returncode == 0 and "signature verified" in ok.stdout
    bad = cli("verify-receipt", str(receipt_file), "--key-env", "SAR_KEY", env={"SAR_KEY": "wrong-key-0123456789"})
    assert bad.returncode == 1 and "signature does not verify" in bad.stdout
    r = json.loads(receipt_file.read_text())
    r["outcome"] = "violated"
    receipt_file.write_text(json.dumps(r))
    assert cli("verify-receipt", str(receipt_file)).returncode == 1
    assert cli("verify-receipt", str(receipt_file), "--key-env", "NOPE_UNSET").returncode == 2


def test_verify_receipt_cli_refuses_unusable_keys_as_could_not_check(receipt_file):
    """A key that can't be used means the receipt wasn't checked (exit 2), not that it failed."""
    short = cli("verify-receipt", str(receipt_file), "--key-env", "SAR_KEY", env={"SAR_KEY": "short"})
    assert short.returncode == 2 and "shorter than" in short.stderr
    for bad in ("k=abcd", "k=" + "00" * 31, "k=zz"):
        assert cli("verify-receipt", str(receipt_file), "--public-key", bad).returncode == 2


def test_verify_receipt_cli_rejects_a_self_consistent_stub(tmp_path):
    from secure_agent_runtime.receipts import receipt_digest

    stub = {"schema": "sar.receipt/v1", "receipt_id": "x", "outcome": "verified"}
    stub["digest"] = receipt_digest(stub)
    path = tmp_path / "stub.json"
    path.write_text(json.dumps(stub))
    p = cli("verify-receipt", str(path))
    assert p.returncode == 1 and "lacks required fields" in p.stdout and "Traceback" not in p.stderr


def test_schema_cli():
    p = cli("schema")
    assert p.returncode == 0 and json.loads(p.stdout)["title"] == "SAR Agent Receipt v1"


def test_readme_quick_start_runs_and_a_rerun_replays_instead_of_refunding_again(tmp_path):
    pytest.importorskip("cryptography")
    script = os.path.join(os.path.dirname(__file__), os.pardir, "examples", "quickstart.py")
    runs = [subprocess.run([sys.executable, script], cwd=tmp_path, capture_output=True, text=True, timeout=120)
            for _ in range(2)]
    assert [r.returncode for r in runs] == [0, 0], runs[0].stderr + runs[1].stderr
    assert runs[0].stdout.split() == ["awaiting_approval", "succeeded", "[]"]
    assert runs[1].stdout.split() == ["succeeded", "succeeded", "[]"]  # replayed from sar.db, not re-run
