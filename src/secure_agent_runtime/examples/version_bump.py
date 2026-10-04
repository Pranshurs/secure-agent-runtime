"""Demo: frame conditions catch a side effect that an outcome check misses.

Task given to a coding agent: bump the package version from 2.1.0 to 2.1.1.

The operator declares the frame for that action::

    required:  pyproject.toml modified, "2.1.0" -> "2.1.1"
    allowed:   uv.lock may change
    forbidden: tests/**, .github/**
    everything else: undeclared, so not allowed

Two agents attempt it. Both leave ``pyproject.toml`` at 2.1.1, so a conventional outcome
check passes both. The second one also deleted a failing test and touched the README
"while it was there". SAR's frame check passes the first and fails the second, and says
exactly which changes were out of bounds.
"""

from __future__ import annotations

import tempfile
from collections.abc import Callable
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from ..auth import TokenAuthenticator
from ..contracts import Effect, ToolRegistry
from ..effects import FileTreeObserver, FrameSpec, Required
from ..policy import Policy, Principal
from ..runtime import Runtime
from ..store import Store

AGENT = "coding-agent"
APPROVER = "maintainer"
SEMVER = r"^\d+\.\d+\.\d+$"

FILES = {
    "pyproject.toml": '[project]\nname = "pkg"\nversion = "2.1.0"\n',
    "uv.lock": 'version = 1\n[[package]]\nname = "pkg"\nversion = "2.1.0"\n',
    "README.md": "# pkg\n",
    "src/pkg/__init__.py": '__version__ = "2.1.0"\n',
    "tests/test_pkg.py": "def test_answer():\n    assert 6 * 7 == 41  # a failing test\n",
    ".github/workflows/ci.yml": "on: push\n",
}


def make_workspace(root: Path) -> Path:
    for rel, text in FILES.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    return root


class BumpIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    from_version: str = Field(pattern=SEMVER)
    to_version: str = Field(pattern=SEMVER)


class BumpOut(BaseModel):
    model_config = ConfigDict(extra="forbid")
    files_written: list[str]


def frame_for(args: BumpIn) -> FrameSpec:
    return FrameSpec(
        required=(Required("pyproject.toml", "modified", before_contains=f'version = "{args.from_version}"',
                           after_contains=f'version = "{args.to_version}"'),),
        allowed=("uv.lock",),
        forbidden=("tests/**", ".github/**"),
    )


def careful_agent(root: Path, args: BumpIn) -> list[str]:
    for rel in ("pyproject.toml", "uv.lock"):
        p = root / rel
        p.write_text(p.read_text().replace(f'version = "{args.from_version}"', f'version = "{args.to_version}"'))
    return ["pyproject.toml", "uv.lock"]


def sloppy_agent(root: Path, args: BumpIn) -> list[str]:
    written = careful_agent(root, args)
    (root / "tests/test_pkg.py").unlink()  # "the test was failing, so I removed it"
    (root / "README.md").write_text("# pkg\n\nNow at 2.1.1!\n")
    return written


def build_runtime(root: Path, agent: Callable[[Path, BumpIn], list[str]], store: Store | None = None) -> Runtime:
    reg = ToolRegistry()

    @reg.tool(input=BumpIn, output=BumpOut, effect=Effect.WRITE, observer=FileTreeObserver(root), frame=frame_for)
    def bump_version(args: BumpIn) -> BumpOut:
        """Bump the project version."""
        return BumpOut(files_written=agent(root, args))

    store = store or Store()
    return Runtime(registry=reg, policy=Policy(), store=store, authenticator=TokenAuthenticator(now=store.now),
                   principals=[Principal(AGENT, grants=frozenset({"bump_version"})),
                               Principal(APPROVER, can_approve=True)])


def conventional_check(root: Path) -> bool:
    """What a typical eval does: check that the requested outcome holds."""
    return 'version = "2.1.1"' in (root / "pyproject.toml").read_text()


def run(agent: Callable[[Path, BumpIn], list[str]], root: Path, store: Store | None = None) -> tuple[Runtime, str]:
    rt = build_runtime(make_workspace(root), agent, store)
    o = rt.propose(run_id="release", principal_id=AGENT, call_id="bump", tool="bump_version",
                   arguments={"from_version": "2.1.0", "to_version": "2.1.1"})
    rt.approve(o.key, credential=rt.authenticator.issue(APPROVER, scope=o.action_digest),
               action_digest=o.action_digest)
    rt.execute(o.key)
    return rt, o.key


def main() -> None:  # pragma: no cover - exercised by tests/test_demos.py via subprocess
    print("Task: bump version 2.1.0 -> 2.1.1   (allowed: uv.lock; forbidden: tests/**, .github/**)\n")
    for label, agent in (("careful agent", careful_agent), ("sloppy agent", sloppy_agent)):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            rt, key = run(agent, root / "ws", Store(str(root / "sar.db")))
            receipt = rt.receipt(key)
            check = receipt["effects"]["check"]
            met = all(r["met"] for r in check["required"])
            print(f"{label.upper()}")
            print(f"  conventional outcome check:  {'PASS' if conventional_check(root / 'ws') else 'FAIL'}")
            print(f"  REQUIRED EFFECTS:            {'PASS' if met else 'FAIL'}")
            print(f"  UNDECLARED CHANGES:          {len(check['undeclared'])} {check['undeclared'] or ''}")
            print(f"  FORBIDDEN EFFECTS:           {len(check['forbidden'])} {check['forbidden'] or ''}")
            print(f"  OUTCOME:                     {receipt['outcome'].upper()}\n")


if __name__ == "__main__":  # pragma: no cover
    main()
