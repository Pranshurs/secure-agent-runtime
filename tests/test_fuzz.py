"""Fuzzing the public boundaries with hypothesis.

Every entry point must either return a structured result or raise one of its
documented errors; it must never crash with an arbitrary exception or leave partial
state behind.
"""

from __future__ import annotations

import os

import hypothesis.strategies as st
from hypothesis import HealthCheck, given, settings

from secure_agent_runtime.contracts import canonical_json, plain_json
from secure_agent_runtime.effects import Entry, FrameSpec, Required, check_frame, compile_glob
from secure_agent_runtime.examples.notes import AGENT, build_runtime
from secure_agent_runtime.receipts import verify_receipt
from secure_agent_runtime.runtime import MalformedProposal, ReplayDivergence
from secure_agent_runtime.store import Store

N = int(os.environ.get("SAR_FUZZ_EXAMPLES", "200"))
FUZZ = settings(max_examples=N, deadline=None, suppress_health_check=[HealthCheck.too_slow,
                                                                     HealthCheck.function_scoped_fixture])

# Any text, including lone surrogates, control characters and odd normalisation forms.
any_text = st.text(st.characters(codec=None, min_codepoint=0, max_codepoint=0x10FFFF), max_size=40)
json_scalar = st.none() | st.booleans() | st.integers(-(10**40), 10**40) | st.floats(allow_nan=True) | any_text
json_like = st.recursive(json_scalar, lambda inner: st.lists(inner, max_size=5) |
                         st.dictionaries(any_text, inner, max_size=5), max_leaves=30)
anything = json_like | st.binary(max_size=10) | st.just(object()) | st.tuples(st.integers())


@FUZZ
@given(tool=anything | st.sampled_from(["read_note", "write_note", "delete_note"]), arguments=anything,
       call_id=anything | any_text, run_id=any_text)
def test_propose_never_crashes_and_never_corrupts(tool, arguments, call_id, run_id):
    store = Store()
    rt, app = build_runtime(store)
    try:
        o = rt.propose(run_id=run_id, principal_id=AGENT, call_id=call_id, tool=tool, arguments=arguments)
    except (MalformedProposal, ReplayDivergence):
        assert store.calls() == []  # refused before anything was recorded
    else:
        assert o.state in {"invalid", "denied", "awaiting_approval", "approved"}
        assert rt.execute(o.key).state in {"invalid", "denied", "awaiting_approval", "succeeded",
                                            "failed", "output_rejected"}
    assert store.verify_audit()[0]
    assert sum(app.invocations.values()) <= 1
    store.close()


@FUZZ
@given(receipt=json_like | anything)
def test_verify_receipt_never_raises(receipt):
    problems = verify_receipt(receipt, signing_key=b"k" * 32)
    assert isinstance(problems, list) and problems  # garbage never verifies


@FUZZ
@given(receipt=st.fixed_dictionaries({"schema": st.just("sar.receipt/v1")}, optional={
    "digest": any_text, "signature": json_like, "audit": json_like, "idempotency_key": json_like,
    "action": json_like}))
def test_verify_receipt_never_raises_on_receipt_shaped_garbage(receipt):
    store = Store()
    assert verify_receipt(receipt, store=store, public_keys={"k": b"\x00" * 32})
    store.close()


paths = st.lists(st.sampled_from(["a", "b", ".env", "tests", "x\ny", "é", "*", "[", "\\"]), min_size=1,
                 max_size=4).map("/".join)
globs = st.lists(st.sampled_from(["a", "*", "**", "?", ".env", "tests", "x\ny", "[", "\\"]), min_size=1,
                 max_size=4).map("/".join)


@FUZZ
@given(before=st.dictionaries(paths, st.binary(max_size=4), max_size=6),
       after=st.dictionaries(paths, st.binary(max_size=4), max_size=6),
       allowed=st.lists(globs, max_size=3), forbidden=st.lists(globs, max_size=3),
       required=st.lists(st.tuples(globs, st.sampled_from(["added", "modified", "deleted"])), max_size=2))
def test_frame_check_is_total_and_forbidden_always_fails(before, after, allowed, forbidden, required):
    snap = lambda d: {k: Entry("sha256:" + v.hex(), v) for k, v in d.items()}  # noqa: E731
    spec = FrameSpec(required=tuple(Required(p, c) for p, c in required), allowed=tuple(allowed),
                     forbidden=tuple(forbidden))
    r = check_frame(spec, snap(before), snap(after))
    assert r.verdict in {"verified", "violated", "unverifiable"}
    changed = {c.path for c in r.observed}
    hit = {p for p in changed if any(compile_glob(g).match(p) for g in forbidden)}
    assert set(r.forbidden) == hit
    if hit or r.undeclared:
        assert r.verdict == "violated"
    # every change is accounted for exactly once
    met_paths = changed - set(r.forbidden) - set(r.allowed) - set(r.undeclared)
    assert all(any(compile_glob(rq.path).match(p) for rq in spec.required) for p in met_paths)


@FUZZ
@given(value=json_like)
def test_canonical_json_is_deterministic_or_refuses(value):
    text = plain_json(value)
    if text is not None:
        assert text == canonical_json(value)
        import json
        assert canonical_json(json.loads(text)) == text  # round-trips to the same bytes
