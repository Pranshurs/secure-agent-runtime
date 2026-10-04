"""Frame conditions: required effects present, nothing undeclared or forbidden."""

from __future__ import annotations

import dataclasses
import os

import pytest

from secure_agent_runtime.contracts import Applied, ContractError, Effect, ToolRegistry
from secure_agent_runtime.effects import (
    Entry,
    FileTreeObserver,
    FrameSpec,
    MappingObserver,
    Required,
    check_frame,
    compile_glob,
)
from secure_agent_runtime.examples import version_bump as vb
from secure_agent_runtime.store import Store

from .conftest import cred

# -- globs ---------------------------------------------------------------------------------- #

@pytest.mark.parametrize("pattern,path,match", [
    ("tests/**", "tests/a.py", True), ("tests/**", "tests/x/y.py", True), ("tests/**", "tests", False),
    ("tests/**", "src/tests/a.py", False), ("*.py", "a.py", True), ("*.py", "a/b.py", False),
    ("**/x.py", "x.py", True), ("**/x.py", "a/b/x.py", True), ("a?c", "abc", True), ("a?c", "a/c", False),
    ("uv.lock", "uv.lock", True), ("uv.lock", "uvXlock", False), ("uv.lock", "uv.lock.bak", False),
    ("uv.lock", "x/uv.lock", False), ("a+b(c)", "a+b(c)", True), ("a+b(c)", "aab", False),
    ("refunds/*", "refunds/rf_1", True),
])
def test_glob_semantics(pattern, path, match):
    assert bool(compile_glob(pattern).match(path)) is match


@pytest.mark.parametrize("bad", ["", "/etc/passwd"])
def test_bad_globs_rejected(bad):
    with pytest.raises(ValueError):
        compile_glob(bad)


# -- evaluation ---------------------------------------------------------------------------------- #

BUMP = FrameSpec(required=(Required("pyproject.toml", before_contains="2.1.0", after_contains="2.1.1"),),
                 allowed=("uv.lock",), forbidden=("tests/**",))


def entries(**kw):
    return {k: Entry(f"sha256:{v}", v.encode()) for k, v in kw.items()}


def test_exact_required_change_verifies():
    r = check_frame(BUMP, entries(**{"pyproject.toml": "2.1.0"}), entries(**{"pyproject.toml": "2.1.1"}))
    assert r.verdict == "verified" and r.undeclared == [] and r.forbidden == [] and r.required[0]["met"]


def test_missing_required_effect_violates():
    r = check_frame(BUMP, entries(**{"pyproject.toml": "2.1.0"}), entries(**{"pyproject.toml": "2.1.0"}))
    assert r.verdict == "violated" and not r.required[0]["met"]


def test_wrong_content_violates():
    r = check_frame(BUMP, entries(**{"pyproject.toml": "2.1.0"}), entries(**{"pyproject.toml": "2.2.0"}))
    assert r.verdict == "violated" and "lacks '2.1.1'" in r.required[0]["problems"][0]


def test_forbidden_and_undeclared_changes_violate_even_when_required_is_met():
    before = entries(**{"pyproject.toml": "2.1.0", "tests/t.py": "t", "README.md": "r"})
    after = entries(**{"pyproject.toml": "2.1.1", "README.md": "r2"})
    r = check_frame(BUMP, before, after)
    assert r.required[0]["met"] and r.verdict == "violated"
    assert r.forbidden == ["tests/t.py"] and r.undeclared == ["README.md"]


def test_allowed_changes_are_fine_and_unlisted_ones_are_not():
    before = entries(**{"pyproject.toml": "2.1.0", "uv.lock": "a"})
    after = entries(**{"pyproject.toml": "2.1.1", "uv.lock": "b", "new.txt": "x"})
    r = check_frame(BUMP, before, after)
    assert r.allowed == ["uv.lock"] and r.undeclared == ["new.txt"] and r.verdict == "violated"


def test_forbidden_beats_allowed():
    spec = FrameSpec(allowed=("**",), forbidden=("tests/**",))
    r = check_frame(spec, entries(**{"tests/t.py": "a", "src/x.py": "a"}), entries(**{"src/x.py": "b"}))
    assert r.forbidden == ["tests/t.py"] and r.allowed == ["src/x.py"] and r.verdict == "violated"


def test_required_count_is_exact():
    spec = FrameSpec(required=(Required("refunds/*", "added", count=1),))
    one = check_frame(spec, {}, entries(**{"refunds/1": "x"}))
    two = check_frame(spec, {}, entries(**{"refunds/1": "x", "refunds/2": "y"}))
    assert one.verdict == "verified" and two.verdict == "violated"


def test_forbidden_wins_even_over_a_requirement():
    """A broad requirement must not launder a forbidden change into a verified one."""
    spec = FrameSpec(required=(Required("*.key"),), forbidden=("secret.key",))
    r = check_frame(spec, entries(**{"secret.key": "a"}), entries(**{"secret.key": "b"}))
    assert r.verdict == "violated" and r.forbidden == ["secret.key"]
    spec2 = FrameSpec(required=(Required("**", count=2),), forbidden=("tests/**",))
    r2 = check_frame(spec2, entries(**{"a": "1", "tests/t": "1"}), entries(**{"a": "2", "tests/t": "2"}))
    assert r2.verdict == "violated" and r2.forbidden == ["tests/t"]


def test_one_change_cannot_satisfy_two_requirements():
    spec = FrameSpec(required=(Required("a.txt"), Required("*.txt")))
    one = check_frame(spec, entries(**{"a.txt": "1"}), entries(**{"a.txt": "2"}))
    two = check_frame(spec, entries(**{"a.txt": "1", "b.txt": "1"}), entries(**{"a.txt": "2", "b.txt": "2"}))
    assert one.verdict == "violated" and two.verdict == "verified"


def test_change_kind_must_match():
    spec = FrameSpec(required=(Required("a.txt", "deleted"),))
    assert check_frame(spec, entries(**{"a.txt": "x"}), {}).verdict == "verified"
    assert check_frame(spec, entries(**{"a.txt": "x"}), entries(**{"a.txt": "y"})).verdict == "violated"


def test_missing_content_is_unverifiable_not_guessed():
    before = {"pyproject.toml": Entry("sha256:a")}  # digest only, e.g. after a restart
    after = entries(**{"pyproject.toml": "2.1.1"})
    assert check_frame(BUMP, before, after).verdict == "unverifiable"
    after_bad = {**after, "tests/x": Entry("sha256:z")}
    assert check_frame(BUMP, {**before, "tests/x": Entry("sha256:y")}, after_bad).verdict == "violated"


@pytest.mark.parametrize("bad", [dict(change="renamed"), dict(count=0), dict(change="added", before_contains="x"),
                                 dict(change="deleted", after_contains="x"), dict(path="/abs")])
def test_invalid_requirements_rejected(bad):
    with pytest.raises(ValueError):
        Required(**{"path": "a", **bad})


def test_frame_spec_round_trips():
    assert FrameSpec.from_json(BUMP.to_json()) == BUMP


# -- observers --------------------------------------------------------------------------------- #

def test_file_tree_observer_sees_add_modify_delete_and_symlinks(tmp_path):
    (tmp_path / "a").write_text("1")
    (tmp_path / "d").mkdir()
    (tmp_path / "d" / "b").write_text("2")
    (tmp_path / "cache").mkdir()
    obs = FileTreeObserver(tmp_path, ignore=("cache/**",))
    before = obs.snapshot()
    (tmp_path / "a").write_text("1!")
    (tmp_path / "d" / "b").unlink()
    (tmp_path / "c").write_text("3")
    (tmp_path / "cache" / "junk").write_text("x")
    os.symlink("/etc", tmp_path / "link")
    r = check_frame(FrameSpec(), before, obs.snapshot())
    assert {(c.path, c.change) for c in r.observed} == {("a", "modified"), ("d/b", "deleted"), ("c", "added"),
                                                        ("link", "added")}
    assert "etc/passwd" not in str(obs.snapshot())  # the symlink is not followed


def test_permission_changes_and_empty_directories_are_observed(tmp_path):
    (tmp_path / "run.sh").write_text("echo hi")
    obs = FileTreeObserver(tmp_path)
    before = obs.snapshot()
    os.chmod(tmp_path / "run.sh", 0o777)
    (tmp_path / "newdir").mkdir()
    r = check_frame(FrameSpec(), before, obs.snapshot())
    assert {(c.path, c.change) for c in r.observed} == {("run.sh", "modified"), ("newdir/", "added")}
    assert r.verdict == "violated"


def test_ignored_directories_are_not_descended(tmp_path):
    (tmp_path / "cache").mkdir()
    obs = FileTreeObserver(tmp_path, ignore=("cache/**",))
    before = obs.snapshot()
    (tmp_path / "cache" / "x").write_text("1")
    assert check_frame(FrameSpec(), before, obs.snapshot()).observed == []


def test_mapping_observer_refuses_ambiguous_ids():
    with pytest.raises(TypeError):
        MappingObserver(lambda: {1: "a", "1": "b"}).snapshot()


def test_mapping_observer():
    data = {"x": {"v": 1}}
    obs = MappingObserver(lambda: data)
    before = obs.snapshot()
    data["x"] = {"v": 2}
    data["y"] = {"v": 3}
    r = check_frame(FrameSpec(allowed=("x",)), before, obs.snapshot())
    assert r.allowed == ["x"] and r.undeclared == ["y"]


# -- through the runtime ----------------------------------------------------------------------- #

def test_careful_agent_is_verified(tmp_path, store):
    rt, key = vb.run(vb.careful_agent, tmp_path, store)
    out = rt.execute(key)
    assert out.state == "succeeded" and out.verification == "verified"
    assert out.for_model()["verification"] == "verified"
    assert rt.receipt(key)["outcome"] == "verified"


def test_sloppy_agent_passes_outcome_check_but_fails_frame(tmp_path, store):
    rt, key = vb.run(vb.sloppy_agent, tmp_path, store)
    assert vb.conventional_check(tmp_path) is True
    receipt = rt.receipt(key)
    check = receipt["effects"]["check"]
    assert receipt["outcome"] == "violated"
    assert check["forbidden"] == ["tests/test_pkg.py"] and check["undeclared"] == ["README.md"]
    assert all(r["met"] for r in check["required"])


def test_agent_that_misses_the_requirement_is_violated(tmp_path, store):
    rt, key = vb.run(lambda root, args: [], tmp_path, store)
    assert rt.receipt(key)["outcome"] == "violated"


def test_declared_frame_is_part_of_what_was_approved(tmp_path, store):
    rt = vb.build_runtime(vb.make_workspace(tmp_path), vb.careful_agent, store)
    o = rt.propose(run_id="r", principal_id=vb.AGENT, call_id="c", tool="bump_version",
                   arguments={"from_version": "2.1.0", "to_version": "2.1.1"})
    rt.approve(o.key, credential=cred(rt, vb.APPROVER), action_digest=o.action_digest)
    spec = rt.registry.get("bump_version")
    loosened = dataclasses.replace(spec, frame=lambda a: FrameSpec(allowed=("**",)))
    rt.registry.replace(loosened)
    out = rt.execute(o.key)
    assert out.state == "cancelled" and "declared effects changed" in out.reason
    assert (tmp_path / "pyproject.toml").read_text() == vb.FILES["pyproject.toml"]


def test_failing_frame_builder_makes_the_proposal_invalid(tmp_path, store):
    rt = vb.build_runtime(vb.make_workspace(tmp_path), vb.careful_agent, store)
    spec = rt.registry.get("bump_version")
    rt.registry.replace(dataclasses.replace(spec, frame=lambda a: 1 / 0))
    o = rt.propose(run_id="r", principal_id=vb.AGENT, call_id="c", tool="bump_version",
                   arguments={"from_version": "2.1.0", "to_version": "2.1.1"})
    assert o.state == "invalid" and "ZeroDivisionError" in o.reason


def test_observer_failure_before_dispatch_blocks_the_tool(tmp_path, store):
    calls = []
    rt = vb.build_runtime(vb.make_workspace(tmp_path), lambda root, args: calls.append(1) or [], store)

    class Broken:
        def snapshot(self):
            raise PermissionError("cannot read workspace")

    rt.registry.replace(dataclasses.replace(rt.registry.get("bump_version"), observer=Broken()))
    o = rt.propose(run_id="r", principal_id=vb.AGENT, call_id="c", tool="bump_version",
                   arguments={"from_version": "2.1.0", "to_version": "2.1.1"})
    rt.approve(o.key, credential=cred(rt, vb.APPROVER), action_digest=o.action_digest)
    out = rt.execute(o.key)
    assert out.state == "cancelled" and "could not observe" in out.reason and calls == []


def test_restart_loses_before_content_so_content_checks_are_unverifiable(tmp_path, clock):
    db = str(tmp_path / "sar.db")
    ws = vb.make_workspace(tmp_path / "ws")

    def crash(point, key):
        if point == "after_effect":
            raise SystemExit

    rt = vb.build_runtime(ws, vb.careful_agent, Store(db, now=clock))
    rt._faults = crash
    o = rt.propose(run_id="r", principal_id=vb.AGENT, call_id="c", tool="bump_version",
                   arguments={"from_version": "2.1.0", "to_version": "2.1.1"})
    rt.approve(o.key, credential=cred(rt, vb.APPROVER), action_digest=o.action_digest)
    assert rt.execute(o.key).state == "executing"
    rt.store.close()

    rt2 = vb.build_runtime(ws, vb.careful_agent, Store(db, now=clock))

    @rt2.registry.reconciler("bump_version")
    def check(args, ctx):
        return Applied(vb.BumpOut(files_written=["pyproject.toml", "uv.lock"]))

    rt2.recover()
    out = rt2.reconcile(o.key)
    assert out.state == "succeeded" and out.verification == "unverifiable"
    receipt = rt2.receipt(o.key)
    assert receipt["outcome"] == "unverifiable"
    rt2.store.close()


def test_frame_and_observer_must_come_together():
    from pydantic import BaseModel, ConfigDict

    class M(BaseModel):
        model_config = ConfigDict(extra="forbid")

    with pytest.raises(ContractError):
        ToolRegistry().tool(name="t", input=M, output=M, effect=Effect.WRITE, frame=lambda a: FrameSpec())(
            lambda a: M())


# -- an observer that can't see must never report "verified" ---------------------------------------- #

def test_a_mistyped_observer_root_blocks_the_tool_before_it_runs(tmp_path, store):
    """With a typo in the root, the old observer saw an empty tree before and after, so even
    deleting a forbidden directory read as 'verified'. Now the pre-dispatch snapshot fails."""
    ws = vb.make_workspace(tmp_path / "ws")
    rt = vb.build_runtime(ws, vb.sloppy_agent, store)
    spec = rt.registry.get("bump_version")
    rt.registry.replace(dataclasses.replace(spec, observer=FileTreeObserver(tmp_path / "wss")))  # typo
    o = rt.propose(run_id="r", principal_id=vb.AGENT, call_id="c", tool="bump_version",
                   arguments={"from_version": "2.1.0", "to_version": "2.1.1"})
    if o.state == "awaiting_approval":
        rt.approve(o.key, credential=cred(rt, vb.APPROVER), action_digest=o.action_digest)
    out = rt.execute(o.key)
    assert out.state == "cancelled" and "could not observe" in out.reason
    assert (ws / "tests" / "test_pkg.py").exists()  # the tool never ran


def test_an_observed_root_that_disappears_during_dispatch_is_never_verified(tmp_path, store):
    import shutil

    ws = vb.make_workspace(tmp_path / "ws")

    def wipe(root, args):
        shutil.rmtree(root)
        return []

    rt = vb.build_runtime(ws, wipe, store)
    o = rt.propose(run_id="r", principal_id=vb.AGENT, call_id="c", tool="bump_version",
                   arguments={"from_version": "2.1.0", "to_version": "2.1.1"})
    rt.approve(o.key, credential=cred(rt, vb.APPROVER), action_digest=o.action_digest)
    out = rt.execute(o.key)
    assert out.state == "succeeded" and out.verification == "unverifiable"


def test_an_unreadable_directory_makes_the_snapshot_fail(tmp_path, monkeypatch):
    (tmp_path / "secret").mkdir()
    (tmp_path / "secret" / "a").write_text("x")
    real_scandir = os.scandir

    def deny(path="."):
        if os.fspath(path).endswith("secret"):
            raise PermissionError(13, "Permission denied", os.fspath(path))
        return real_scandir(path)

    monkeypatch.setattr(os, "scandir", deny)  # what os.walk sees for a directory it can't read
    with pytest.raises(PermissionError):
        FileTreeObserver(tmp_path).snapshot()
