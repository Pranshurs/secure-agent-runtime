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
import sqlite3
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any

from .contracts import canonical_json

GENESIS = "0" * 64

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


def _event_hash(prev_hash: str, seq: int, ts: float, run_id: str, call_key: str | None,
                kind: str, data_json: str) -> str:
    body = canonical_json([seq, ts, run_id, call_key, kind, data_json])
    return hashlib.sha256((prev_hash + body).encode()).hexdigest()


class Store:
    def __init__(self, path: str = ":memory:", now: Callable[[], float] = time.time) -> None:
        self.path = path
        self.now = now
        self._lock = threading.RLock()
        self._db = sqlite3.connect(path, isolation_level=None, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        if path != ":memory:":
            self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA busy_timeout=5000")
        self._db.executescript(_SCHEMA)

    def close(self) -> None:
        with self._lock:
            self._db.close()

    @contextmanager
    def tx(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
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
        q, p = "SELECT * FROM events WHERE 1=1", []
        if call_key is not None:
            q, p = q + " AND call_key=?", p + [call_key]
        if run_id is not None:
            q, p = q + " AND run_id=?", p + [run_id]
        if kind is not None:
            q, p = q + " AND kind=?", p + [kind]
        with self._lock:
            rows = self._db.execute(q + " ORDER BY seq", p).fetchall()
        return [Event(r["seq"], r["ts"], r["run_id"], r["call_key"], r["kind"],
                      json.loads(r["data_json"]), r["prev_hash"], r["hash"]) for r in rows]

    def head(self) -> tuple[int, str]:
        """(seq, hash) of the latest event; (0, GENESIS) if empty. Store it externally."""
        with self._lock:
            r = self._db.execute("SELECT seq, hash FROM events ORDER BY seq DESC LIMIT 1").fetchone()
        return (r["seq"], r["hash"]) if r else (0, GENESIS)

    def verify_audit(self, anchor: tuple[int, str] | None = None) -> tuple[bool, str]:
        """Recompute the chain. Returns (ok, explanation of the first problem).

        ``anchor`` is a ``(seq, hash)`` from :meth:`head` taken earlier; if given, the
        chain must still contain that event with that hash, which detects truncation.
        """
        prev, expected_seq = GENESIS, 1
        with self._lock:
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
            self._append(db, run_id, key, f"call.{state}", {"reason": reason})
        return True

    def transition(self, key: str, from_state: str, to_state: str, *,
                   event: dict[str, Any] | None = None, attempt: int | None = None, **fields: Any) -> bool:
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
            cur = db.execute(f"UPDATE calls SET {', '.join(cols)} WHERE key=? AND state=?{fence}",
                             (*values, key, from_state, *fence_args))
            if cur.rowcount != 1:
                return False
            run_id = db.execute("SELECT run_id FROM calls WHERE key=?", (key,)).fetchone()["run_id"]
            self._append(db, run_id, key, f"call.{to_state}", event or {})
        return True

    def get_call(self, key: str) -> CallRow | None:
        with self._lock:
            r = self._db.execute("SELECT * FROM calls WHERE key=?", (key,)).fetchone()
        return _row(r) if r else None

    def calls(self, *, run_id: str | None = None, state: str | None = None) -> list[CallRow]:
        q, p = "SELECT * FROM calls WHERE 1=1", []
        if run_id is not None:
            q, p = q + " AND run_id=?", p + [run_id]
        if state is not None:
            q, p = q + " AND state=?", p + [state]
        with self._lock:
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
