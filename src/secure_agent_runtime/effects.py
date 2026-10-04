"""Effect observation and frame conditions.

An outcome check asks "did the agent do what was asked?". A *frame condition* also asks
"did it leave everything else alone?". For each action the operator declares:

* **required** effects that must be observed (``pyproject.toml`` modified, with the new
  version in it);
* **allowed** effects that may happen (``uv.lock`` may change);
* **forbidden** effects that must not happen (``tests/**``).

Every observed change that is neither required nor allowed is *undeclared*, and an
undeclared change fails the frame just like a forbidden one. Silence means "not allowed".

Observation is done by an :class:`Observer` that snapshots the state the tool may touch,
before and after execution. Two observers ship: :class:`FileTreeObserver` for a
directory, and :class:`MappingObserver` for anything you can present as
``{resource id: JSON-able value}`` (a mock payment ledger, a table, a bucket listing).
A snapshot is ``{resource id: Entry(digest, content)}``. Only digests are persisted or
put into receipts; content is held in memory just long enough to check ``contains``
requirements.

Limits, stated plainly: an observer only sees what it snapshots, and only at the two
instants it is asked to. A change that is made and reverted between the snapshots, or
made outside the observed scope, is invisible to it.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

CHANGES = ("added", "modified", "deleted")
MAX_CONTENT = 1 << 20  # content kept for `contains` checks, per resource


@dataclass(frozen=True)
class Entry:
    digest: str
    content: bytes | None = None  # None when too large, or when restored from storage


Snapshot = dict[str, Entry]


class Observer(Protocol):
    def snapshot(self) -> Snapshot: ...


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


class FileTreeObserver:
    """Snapshots everything under ``root``: regular files (content and permission bits),
    directories (as ``path/``, so creating an empty one is visible) and symlinks (by
    target text, never followed). Paths are POSIX, relative to root.

    ``ignore`` globs are skipped entirely; use it for caches, never to hide what a tool
    may touch. Ownership, timestamps and extended attributes are not observed.
    """

    def __init__(self, root: str | os.PathLike[str], ignore: tuple[str, ...] = ()) -> None:
        self.root = Path(root)
        self._ignore = [compile_glob(g) for g in ignore]

    def snapshot(self) -> Snapshot:
        snap: Snapshot = {}
        for dirpath, dirnames, filenames in os.walk(self.root, followlinks=False):
            dirnames.sort()
            for name in sorted(filenames) + sorted(dirnames):
                full = Path(dirpath, name)
                rel = full.relative_to(self.root).as_posix()
                if any(p.match(rel) or p.match(rel + "/") for p in self._ignore):
                    continue
                st = full.lstat()
                if full.is_symlink():
                    meta, data = b"symlink:", os.readlink(full).encode("utf-8", "surrogateescape")
                elif full.is_dir():
                    snap[rel + "/"] = Entry(_digest(b"dir:%o" % (st.st_mode & 0o7777)))
                    continue
                elif full.is_file():
                    meta, data = b"file:%o:" % (st.st_mode & 0o7777), full.read_bytes()
                else:
                    meta, data = b"special:", b""
                snap[rel] = Entry(_digest(meta + data), data if len(data) <= MAX_CONTENT else None)
            dirnames[:] = [d for d in dirnames if not os.path.islink(os.path.join(dirpath, d))
                           and not any(p.match(Path(dirpath, d).relative_to(self.root).as_posix() + "/")
                                       for p in self._ignore)]
        return snap


class MappingObserver:
    """Snapshots ``source()``: a mapping of resource id -> JSON-serialisable value."""

    def __init__(self, source: Callable[[], Mapping[str, Any]]) -> None:
        self.source = source

    def snapshot(self) -> Snapshot:
        snap: Snapshot = {}
        for rid, value in self.source().items():
            if not isinstance(rid, str):
                raise TypeError(f"resource ids must be strings, got {type(rid).__name__}")
            data = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
            snap[rid] = Entry(_digest(data), data if len(data) <= MAX_CONTENT else None)
        return snap


def digests(snap: Snapshot) -> dict[str, str]:
    return {k: e.digest for k, e in sorted(snap.items())}


def from_digests(d: Mapping[str, str]) -> Snapshot:
    return {k: Entry(v) for k, v in d.items()}


# -- declarations -------------------------------------------------------------------- #

def compile_glob(pattern: str) -> re.Pattern[str]:
    """``**`` matches across ``/``; ``*`` and ``?`` do not. Anchored at both ends."""
    if not pattern or pattern.startswith("/"):
        raise ValueError(f"bad glob {pattern!r}: must be non-empty and relative")
    out, i = [], 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif pattern[i] == "*":
            out.append("[^/]*")
            i += 1
        elif pattern[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(pattern[i]))
            i += 1
    return re.compile("".join(out) + r"\Z")


@dataclass(frozen=True)
class Required:
    """An effect that must be observed.

    ``path`` is a glob. ``count`` is the exact number of matching changes required
    (default 1). ``before_contains`` / ``after_contains`` are substrings that must appear
    in the resource's content before / after the change.
    """

    path: str
    change: str = "modified"
    count: int = 1
    before_contains: str | None = None
    after_contains: str | None = None

    def __post_init__(self) -> None:
        if self.change not in CHANGES:
            raise ValueError(f"change must be one of {CHANGES}")
        if self.count < 1:
            raise ValueError("count must be at least 1")
        compile_glob(self.path)
        if self.change == "added" and self.before_contains is not None:
            raise ValueError("an added resource has no 'before' content")
        if self.change == "deleted" and self.after_contains is not None:
            raise ValueError("a deleted resource has no 'after' content")

    def to_json(self) -> dict[str, Any]:
        return {"path": self.path, "change": self.change, "count": self.count,
                "before_contains": self.before_contains, "after_contains": self.after_contains}


@dataclass(frozen=True)
class FrameSpec:
    required: tuple[Required, ...] = ()
    allowed: tuple[str, ...] = ()
    forbidden: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for g in (*self.allowed, *self.forbidden):
            compile_glob(g)

    def to_json(self) -> dict[str, Any]:
        return {"required": [r.to_json() for r in self.required], "allowed": list(self.allowed),
                "forbidden": list(self.forbidden)}

    @classmethod
    def from_json(cls, d: Mapping[str, Any]) -> FrameSpec:
        return cls(required=tuple(Required(**r) for r in d.get("required", [])),
                   allowed=tuple(d.get("allowed", [])), forbidden=tuple(d.get("forbidden", [])))


# -- evaluation ------------------------------------------------------------------------ #

@dataclass(frozen=True)
class Change:
    path: str
    change: str
    before: str | None  # digest
    after: str | None

    def to_json(self) -> dict[str, Any]:
        return {"path": self.path, "change": self.change, "before": self.before, "after": self.after}


def diff(before: Snapshot, after: Snapshot) -> list[Change]:
    out = []
    for path in sorted(set(before) | set(after)):
        b, a = before.get(path), after.get(path)
        if b is None and a is not None:
            out.append(Change(path, "added", None, a.digest))
        elif a is None and b is not None:
            out.append(Change(path, "deleted", b.digest, None))
        elif a is not None and b is not None and a.digest != b.digest:
            out.append(Change(path, "modified", b.digest, a.digest))
    return out


@dataclass
class FrameResult:
    verdict: str  # verified | violated | unverifiable
    observed: list[Change]
    required: list[dict[str, Any]] = field(default_factory=list)  # per requirement: met / why not
    allowed: list[str] = field(default_factory=list)
    undeclared: list[str] = field(default_factory=list)
    forbidden: list[str] = field(default_factory=list)

    def to_json(self) -> dict[str, Any]:
        return {"verdict": self.verdict, "observed": [c.to_json() for c in self.observed],
                "required": self.required, "allowed": self.allowed, "undeclared": self.undeclared,
                "forbidden": self.forbidden}

    def summary(self) -> str:
        met = all(r["met"] for r in self.required)
        return (f"REQUIRED EFFECTS:        {'PASS' if met else 'FAIL'}\n"
                f"UNDECLARED CHANGES:      {len(self.undeclared)}\n"
                f"FORBIDDEN EFFECTS:       {len(self.forbidden)}\n"
                f"OUTCOME:                 {self.verdict.upper()}")


def _contains(entry: Entry | None, needle: str | None) -> bool | None:
    """True/False if decidable, None if the content isn't available."""
    if needle is None:
        return True
    if entry is None or entry.content is None:
        return None
    return needle.encode() in entry.content


def check_frame(spec: FrameSpec, before: Snapshot, after: Snapshot) -> FrameResult:
    """Classify every observed change against the frame.

    A change matching a forbidden glob is forbidden, whatever else it matches. Each
    change can satisfy at most one requirement (the first that matches it). Changes left
    over are allowed if they match an allowed glob, otherwise undeclared.
    """
    changes = diff(before, after)
    forbidden_pats = [compile_glob(g) for g in spec.forbidden]
    forbidden = [c.path for c in changes if any(p.match(c.path) for p in forbidden_pats)]
    claimed: set[str] = set()
    req_results, unverifiable = [], False
    for r in spec.required:
        pat = compile_glob(r.path)
        matches = [c for c in changes if c.path not in claimed and pat.match(c.path) and c.change == r.change]
        problems = []
        for c in matches:
            for needle, entry, label in ((r.before_contains, before.get(c.path), "before"),
                                         (r.after_contains, after.get(c.path), "after")):
                ok = _contains(entry, needle)
                if ok is None:
                    unverifiable = True
                    problems.append(f"{c.path}: {label} content unavailable")
                elif not ok:
                    problems.append(f"{c.path}: {label} content lacks {needle!r}")
        if len(matches) != r.count:
            problems.append(f"expected {r.count} {r.change} matching {r.path!r}, observed {len(matches)}")
        claimed.update(c.path for c in matches)
        req_results.append({"requirement": r.to_json(), "met": not problems, "problems": problems})

    allowed_pats = [compile_glob(g) for g in spec.allowed]
    allowed, undeclared = [], []
    for c in changes:
        if c.path in claimed or c.path in forbidden:
            continue
        if any(p.match(c.path) for p in allowed_pats):
            allowed.append(c.path)
        else:
            undeclared.append(c.path)

    bad = forbidden or undeclared or any(not r["met"] and not _only_unavailable(r) for r in req_results)
    if bad:
        verdict = "violated"
    elif unverifiable:
        verdict = "unverifiable"
    else:
        verdict = "verified"
    return FrameResult(verdict, changes, req_results, allowed, undeclared, forbidden)


def _only_unavailable(r: dict[str, Any]) -> bool:
    return bool(r["problems"]) and all(p.endswith("content unavailable") for p in r["problems"])
