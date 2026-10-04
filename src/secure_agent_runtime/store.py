"""Durable state: tool calls and the audit log, in one SQLite file.

Three properties carry the runtime's guarantees:

* **Compare-and-set transitions.** A call moves between states only with
  ``UPDATE ... WHERE state = expected``. Two workers racing to execute the same call, or a
  late result arriving after a timeout, can't both win.
* **A closed state machine.** :data:`TRANSITIONS` lists every legal move; anything else
  raises before touching the database.
* **Transition and audit commit together.** Every state change appends an audit event in
  the same transaction, so the log can't miss or invent a transition. Events form a
  SHA-256 hash chain over their full content and sequence number, so editing, deleting or
  reordering a past event is detectable by :meth:`Store.verify_audit`.

The chain is *tamper-evident*, not tamper-proof: someone who can write the file can
rebuild the whole chain, and deleting events from the *end* leaves a valid shorter chain.
Keep :meth:`Store.head` somewhere the attacker can't write and pass it to
:meth:`Store.verify_audit` if that matters to you.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
import time
import weakref
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any

from .contracts import canonical_json
from .errors import CredentialReused, StoreError, StoreLocked

GENESIS = "0" * 64
SCHEMA_VERSION = 1

INITIAL_STATES = frozenset({"invalid", "denied", "awaiting_approval", "approved"})
TRANSITIONS: dict[str, frozenset[str]] = {
    "awaiting_approval": frozenset({"approved", "rejected", "expired", "cancelled"}),
    "approved": frozenset({"executing", "cancelled"}),
    "executing": frozenset({"succeeded", "failed", "effect_unknown", "output_rejected"}),
    # Only reconciliation leaves effect_unknown: applied -> succeeded, not applied ->
    # approved (may be dispatched again) or failed (not dispatched again).
    "effect_unknown": frozenset({"succeeded", "approved", "failed"}),
}
TERMINAL_STATES = frozenset({"invalid", "denied", "rejected", "expired", "cancelled", "succeeded",
                             "failed", "output_rejected"})
_JSON_FIELDS = frozenset({"result", "approval", "before", "frame_result"})
_UPDATABLE = _JSON_FIELDS | {"reason", "result_digest", "dispatches"}

_SCHEMA = """
CREATE TABLE IF NOT EXISTS calls (
    key            TEXT PRIMARY KEY,         -- the idempotency key
    run_id         TEXT NOT NULL,
    call_id        TEXT NOT NULL,
    principal      TEXT NOT NULL,
    tool           TEXT NOT NULL,
    args_json      TEXT NOT NULL,            -- validated args, or the raw proposal if invalid
    action_json    TEXT,                     -- canonical Action body; NULL if invalid
    action_digest  TEXT,                     -- approvals and receipts bind to this
    request_hash   TEXT NOT NULL,            -- over the raw proposal; replay detection only
    state          TEXT NOT NULL,
    reason         TEXT NOT NULL DEFAULT '',
    result_json    TEXT,
    result_digest  TEXT,
    approval_json  TEXT,
    dispatches     INTEGER NOT NULL DEFAULT 0,
    before_json    TEXT,                     -- effect snapshot digests taken before dispatch
    frame_result_json TEXT,
    expires_at     REAL,
    created_at     REAL NOT NULL,
    updated_at     REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS calls_run ON calls(run_id);
CREATE INDEX IF NOT EXISTS calls_state ON calls(state);
CREATE TABLE IF NOT EXISTS events (
    seq        INTEGER PRIMARY KEY,
    ts         REAL NOT NULL,
    run_id     TEXT NOT NULL,
    call_key   TEXT,
    kind       TEXT NOT NULL,
    data_json  TEXT NOT NULL,
    prev_hash  TEXT NOT NULL,
    hash       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS events_call ON events(call_key);
CREATE TABLE IF NOT EXISTS credentials (
    id         TEXT PRIMARY KEY,             -- sha256 of a consumed approval credential id
    call_key   TEXT NOT NULL,
    used_at    REAL NOT NULL
);
"""


class IllegalTransition(RuntimeError):
    pass


@dataclass(frozen=True)
class CallRow:
    key: str
    run_id: str
    call_id: str
    principal: str
    tool: str
    args: Any
    action: dict[str, Any] | None
    action_digest: str | None
    request_hash: str
    state: str
    reason: str
    result: dict[str, Any] | None
    result_digest: str | None
    approval: dict[str, Any] | None
    dispatches: int
    before: dict[str, str] | None
    frame_result: dict[str, Any] | None
    expires_at: float | None
    created_at: float
    updated_at: float


@dataclass(frozen=True)
class Event:
    seq: int
    ts: float
    run_id: str
    call_key: str | None
    kind: str
    data: dict[str, Any]
    prev_hash: str
    hash: str


def approval_digest(approval: dict[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(approval).encode("utf-8")).hexdigest()


def _event_hash(prev_hash: str, seq: int, ts: float, run_id: str, call_key: str | None,
                kind: str, data_json: str) -> str:
    body = canonical_json([seq, ts, run_id, call_key, kind, data_json])
    return hashlib.sha256((prev_hash + body).encode()).hexdigest()


class Store:
    """One SQLite database, owned by exactly one Store object at a time.

    A file-backed store takes an exclusive ``flock`` on ``<path>.lock`` for its lifetime,
    so a second process (or a second Store in this process) opening the same file gets
    :class:`StoreLocked` instead of silently sharing it. The database and lock files are
    created owner-only (0600) because they hold tool arguments and results in plaintext.
    Locking needs POSIX ``fcntl``; Windows is not supported for file-backed stores.
    """

    def __init__(self, path: str = ":memory:", now: Callable[[], float] = time.time,
                 faults: Callable[[str, str], None] | None = None, busy_timeout_ms: int = 5000) -> None:
        """``faults(point, detail)`` is a fault-injection hook; ``before_commit`` is called
        inside every transition's transaction, just before COMMIT, with ``"from->to"``."""
        if not isinstance(path, str) or not path:
            raise ValueError("Store path must be a file path or ':memory:' (an empty path would silently "
                             "create a temporary database and lose all state)")
        self.path = path
        self.now = now
        self._faults = faults or (lambda point, detail: None)
        self._lock = threading.RLock()
        self._lock_fd: int | None = None
        self._owner: Any = None
        self.closed = False
        if path != ":memory:":
            self._take_file_lock()
        try:
            if path != ":memory:":
                os.close(os.open(path, os.O_CREAT | os.O_RDWR, 0o600))
            self._db = sqlite3.connect(path, isolation_level=None, check_same_thread=False)
            self._db.row_factory = sqlite3.Row
            if path != ":memory:":
                self._db.execute("PRAGMA journal_mode=WAL")
            self._db.execute(f"PRAGMA busy_timeout={int(busy_timeout_ms)}")
            self._migrate()
        except (sqlite3.Error, OSError) as exc:
            self._release_file_lock()
            raise StoreError(f"cannot open SAR database {path!r}: {exc}") from exc
        except BaseException:
            self._release_file_lock()
            raise

    def _take_file_lock(self) -> None:
        try:
            import fcntl
        except ImportError as exc:  # pragma: no cover - non-POSIX
            raise StoreError("file-backed stores need POSIX fcntl locking; Windows is not supported") from exc
        try:
            fd = os.open(self.path + ".lock", os.O_CREAT | os.O_RDWR, 0o600)
        except OSError as exc:
            raise StoreError(f"cannot create lock file for {self.path!r}: {exc}") from exc
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            os.close(fd)
            raise StoreLocked(f"{self.path} is already owned by another Store (this or another process); "
                              "SAR supports one owner per database") from exc
        self._lock_fd = fd

    def _release_file_lock(self) -> None:
        if self._lock_fd is not None:
            os.close(self._lock_fd)  # closing the descriptor releases the flock
            self._lock_fd = None

    def _migrate(self) -> None:
        version = self._db.execute("PRAGMA user_version").fetchone()[0]
        tables = {r[0] for r in self._db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if version == 0 and not tables & {"calls", "events"}:
            self._db.executescript(_SCHEMA)
            self._db.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
        elif version != SCHEMA_VERSION:
            raise StoreError(f"database schema version {version} is not supported by this SAR "
                             f"(expects {SCHEMA_VERSION}); refusing to guess")

    def attach(self, owner: Any) -> None:
        """Bind this store to one Runtime; a second live Runtime is refused (StoreLocked)."""
        with self._lock:
            current = self._owner() if self._owner is not None else None
            if current is not None and current is not owner:
                raise StoreLocked("this Store already belongs to another live Runtime; close() it first")
            self._owner = weakref.ref(owner)

    def detach(self, owner: Any) -> None:
        with self._lock:
            if self._owner is not None and self._owner() is owner:
                self._owner = None

    def close(self) -> None:
        with self._lock:
            if not self.closed:
                self.closed = True
                self._db.close()
                self._release_file_lock()

    @contextmanager
    def _guard(self) -> Iterator[None]:
        try:
            yield
        except sqlite3.Error as exc:
            raise StoreError(f"SAR database error: {exc}") from exc

    @contextmanager
    def tx(self) -> Iterator[sqlite3.Connection]:
        with self._lock, self._guard():
            self._db.execute("BEGIN IMMEDIATE")
            try:
                yield self._db
                self._db.execute("COMMIT")
            except BaseException:
                if self._db.in_transaction:  # also covers a failed COMMIT (disk full, busy)
                    self._db.execute("ROLLBACK")
                raise

    # -- audit ------------------------------------------------------------------ #
    def _append(self, db: sqlite3.Connection, run_id: str, call_key: str | None, kind: str,
                data: dict[str, Any]) -> None:
        last = db.execute("SELECT seq, hash FROM events ORDER BY seq DESC LIMIT 1").fetchone()
        seq, prev = (last["seq"] + 1, last["hash"]) if last else (1, GENESIS)
        ts = float(self.now())
        data_json = canonical_json(data)
        h = _event_hash(prev, seq, ts, run_id, call_key, kind, data_json)
        db.execute("INSERT INTO events VALUES (?,?,?,?,?,?,?,?)",
                   (seq, ts, run_id, call_key, kind, data_json, prev, h))

    def record(self, run_id: str, kind: str, data: dict[str, Any], call_key: str | None = None) -> None:
        """Append an audit event that is not a state transition."""
        with self.tx() as db:
            self._append(db, run_id, call_key, kind, data)

    def events(self, run_id: str | None = None, kind: str | None = None,
               call_key: str | None = None) -> list[Event]:
        q, p = "SELECT * FROM events WHERE 1=1", list[Any]()
        if call_key is not None:
            q, p = q + " AND call_key=?", p + [call_key]
        if run_id is not None:
            q, p = q + " AND run_id=?", p + [run_id]
        if kind is not None:
            q, p = q + " AND kind=?", p + [kind]
        with self._lock, self._guard():
            rows = self._db.execute(q + " ORDER BY seq", p).fetchall()
        return [Event(r["seq"], r["ts"], r["run_id"], r["call_key"], r["kind"],
                      json.loads(r["data_json"]), r["prev_hash"], r["hash"]) for r in rows]

    def head(self) -> tuple[int, str]:
        """(seq, hash) of the latest event; (0, GENESIS) if empty. Store it externally."""
        with self._lock, self._guard():
            r = self._db.execute("SELECT seq, hash FROM events ORDER BY seq DESC LIMIT 1").fetchone()
        return (r["seq"], r["hash"]) if r else (0, GENESIS)

    def verify_audit(self, anchor: tuple[int, str] | None = None) -> tuple[bool, str]:
        """Recompute the chain. Returns (ok, explanation of the first problem).

        ``anchor`` is a ``(seq, hash)`` from :meth:`head` taken earlier; if given, the
        chain must still contain that event with that hash, which detects truncation.
        """
        prev, expected_seq = GENESIS, 1
        with self._lock, self._guard():
            rows = self._db.execute("SELECT * FROM events ORDER BY seq").fetchall()
        hashes: dict[int, str] = {0: GENESIS}
        for r in rows:
            if r["seq"] != expected_seq:
                return False, f"sequence gap: expected {expected_seq}, found {r['seq']}"
            if r["prev_hash"] != prev:
                return False, f"event {r['seq']}: prev_hash does not match event {r['seq'] - 1}"
            h = _event_hash(prev, r["seq"], r["ts"], r["run_id"], r["call_key"], r["kind"], r["data_json"])
            if h != r["hash"]:
                return False, f"event {r['seq']}: content does not match its hash"
            hashes[r["seq"]] = h
            prev, expected_seq = h, expected_seq + 1
        if anchor is not None:
            seq, h = anchor
            if hashes.get(seq) != h:
                return False, f"anchor event {seq} is missing or differs (truncated or rewritten)"
        return True, f"{len(rows)} events verified"

    # -- calls ------------------------------------------------------------------ #
    def insert_call(self, *, key: str, run_id: str, call_id: str, principal: str, tool: str,
                    args: Any, action: dict[str, Any] | None, action_digest: str | None,
                    request_hash: str, state: str, reason: str, expires_at: float | None,
                    created_at: float, event: dict[str, Any], approval: dict[str, Any] | None = None) -> bool:
        """Insert a new call with its first events. False if the key already exists."""
        if state not in INITIAL_STATES:
            raise IllegalTransition(f"a call cannot start in {state!r}")
        with self.tx() as db:
            try:
                db.execute(
                    "INSERT INTO calls (key, run_id, call_id, principal, tool, args_json, action_json,"
                    " action_digest, request_hash, state, reason, approval_json, expires_at, created_at,"
                    " updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (key, run_id, call_id, principal, tool, canonical_json(args),
                     None if action is None else canonical_json(action), action_digest, request_hash,
                     state, reason, None if approval is None else canonical_json(approval), expires_at,
                     created_at, created_at))
            except sqlite3.IntegrityError:
                return False
            self._append(db, run_id, key, "call.requested", event)
            first = {"reason": reason}
            if approval is not None:  # the audit log carries the approval, so the row can't invent one
                first["approval_digest"] = approval_digest(approval)
            self._append(db, run_id, key, f"call.{state}", first)
        return True

    def transition(self, key: str, from_state: str, to_state: str, *,
                   event: dict[str, Any] | None = None, attempt: int | None = None,
                   unexpired_at: float | None = None, consume_credential: str | None = None,
                   **fields: Any) -> bool:
        """Compare-and-set ``state``; on success also update ``fields`` and append the event.

        Returns False, changing nothing, if the call is not currently in ``from_state`` or,
        when ``attempt`` is given, if its dispatch count is not ``attempt``. The attempt
        fence stops a late worker or a slow reconciler of attempt N from deciding the
        outcome of attempt N+1.
        """
        if to_state not in TRANSITIONS.get(from_state, frozenset()):
            raise IllegalTransition(f"{from_state} -> {to_state} is not a legal transition")
        unknown = set(fields) - _UPDATABLE
        if unknown:
            raise ValueError(f"cannot update {sorted(unknown)}")
        cols = ["state=?", "updated_at=?"]
        values: list[Any] = [to_state, self.now()]
        for k, v in fields.items():
            if k in _JSON_FIELDS:
                cols.append(f"{k}_json=?")
                values.append(None if v is None else canonical_json(v))
            else:
                cols.append(f"{k}=?")
                values.append(v)
        with self.tx() as db:
            fence, fence_args = ("", ()) if attempt is None else (" AND dispatches=?", (attempt,))
            if unexpired_at is not None:  # the approval window is re-checked inside the CAS
                fence += " AND (expires_at IS NULL OR expires_at > ?)"
                fence_args = (*fence_args, unexpired_at)
            if consume_credential is not None:  # one use per credential, atomically with the change
                try:
                    db.execute("INSERT INTO credentials VALUES (?,?,?)", (consume_credential, key, self.now()))
                except sqlite3.IntegrityError as exc:
                    raise CredentialReused("this approval credential has already been used") from exc
            cur = db.execute(f"UPDATE calls SET {', '.join(cols)} WHERE key=? AND state=?{fence}",
                             (*values, key, from_state, *fence_args))
            if cur.rowcount != 1:
                return False
            run_id = db.execute("SELECT run_id FROM calls WHERE key=?", (key,)).fetchone()["run_id"]
            self._append(db, run_id, key, f"call.{to_state}", event or {})
            self._faults("before_commit", f"{from_state}->{to_state}")
        return True

    def get_call(self, key: str) -> CallRow | None:
        with self._lock, self._guard():
            r = self._db.execute("SELECT * FROM calls WHERE key=?", (key,)).fetchone()
        return _row(r) if r else None

    def calls(self, *, run_id: str | None = None, state: str | None = None) -> list[CallRow]:
        q, p = "SELECT * FROM calls WHERE 1=1", list[Any]()
        if run_id is not None:
            q, p = q + " AND run_id=?", p + [run_id]
        if state is not None:
            q, p = q + " AND state=?", p + [state]
        with self._lock, self._guard():
            return [_row(r) for r in self._db.execute(q + " ORDER BY created_at, key", p).fetchall()]


def _j(text: str | None) -> Any:
    return None if text is None else json.loads(text)


def _row(r: sqlite3.Row) -> CallRow:
    return CallRow(
        key=r["key"], run_id=r["run_id"], call_id=r["call_id"], principal=r["principal"], tool=r["tool"],
        args=json.loads(r["args_json"]), action=_j(r["action_json"]), action_digest=r["action_digest"],
        request_hash=r["request_hash"], state=r["state"], reason=r["reason"], result=_j(r["result_json"]),
        result_digest=r["result_digest"], approval=_j(r["approval_json"]), dispatches=r["dispatches"],
        before=_j(r["before_json"]), frame_result=_j(r["frame_result_json"]), expires_at=r["expires_at"],
        created_at=r["created_at"], updated_at=r["updated_at"],
    )
