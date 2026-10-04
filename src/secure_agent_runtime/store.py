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

INITIAL_STATES = frozenset({"invalid", "denied", "pending_approval", "approved"})
TRANSITIONS: dict[str, frozenset[str]] = {
    "pending_approval": frozenset({"approved", "rejected", "expired", "cancelled"}),
    "approved": frozenset({"executing", "cancelled"}),
    "executing": frozenset({"succeeded", "failed", "timed_out", "output_rejected", "outcome_unknown"}),
}
TERMINAL_STATES = frozenset({"invalid", "denied", "rejected", "expired", "cancelled", "succeeded",
                             "failed", "timed_out", "output_rejected", "outcome_unknown"})
_UPDATABLE = frozenset({"reason", "result", "approved_by", "approved_hash"})

_SCHEMA = """
CREATE TABLE IF NOT EXISTS calls (
    key            TEXT PRIMARY KEY,         -- run_id ':' call_id
    run_id         TEXT NOT NULL,
    call_id        TEXT NOT NULL,
    principal      TEXT NOT NULL,
    tool           TEXT NOT NULL,
    args_json      TEXT NOT NULL,
    args_hash      TEXT NOT NULL,            -- over validated args; approvals bind to it
    request_hash   TEXT NOT NULL,            -- over the raw proposal; replay detection only
    state          TEXT NOT NULL,
    reason         TEXT NOT NULL DEFAULT '',
    result_json    TEXT,
    approved_by    TEXT,
    approved_hash  TEXT,
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
    args_hash: str
    request_hash: str
    state: str
    reason: str
    result: dict[str, Any] | None
    approved_by: str | None
    approved_hash: str | None
    expires_at: float | None


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
            except BaseException:
                self._db.execute("ROLLBACK")
                raise
            self._db.execute("COMMIT")

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

    def events(self, run_id: str | None = None, kind: str | None = None) -> list[Event]:
        q, p = "SELECT * FROM events WHERE 1=1", []
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
                    args: Any, args_hash: str, request_hash: str, state: str, reason: str,
                    expires_at: float | None, event: dict[str, Any],
                    approved_by: str | None = None, approved_hash: str | None = None) -> bool:
        """Insert a new call with its first events. False if the key already exists."""
        if state not in INITIAL_STATES:
            raise IllegalTransition(f"a call cannot start in {state!r}")
        now = self.now()
        with self.tx() as db:
            try:
                db.execute(
                    "INSERT INTO calls (key, run_id, call_id, principal, tool, args_json, args_hash,"
                    " request_hash, state, reason, approved_by, approved_hash, expires_at, created_at,"
                    " updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (key, run_id, call_id, principal, tool, canonical_json(args), args_hash,
                     request_hash, state, reason, approved_by, approved_hash, expires_at, now, now))
            except sqlite3.IntegrityError:
                return False
            self._append(db, run_id, key, "call.requested", event)
            self._append(db, run_id, key, f"call.{state}", {"reason": reason})
        return True

    def transition(self, key: str, from_state: str, to_state: str, *,
                   event: dict[str, Any] | None = None, **fields: Any) -> bool:
        """Compare-and-set ``state``; on success also update ``fields`` and append the event.

        Returns False, changing nothing, if the call is not currently in ``from_state``.
        """
        if to_state not in TRANSITIONS.get(from_state, frozenset()):
            raise IllegalTransition(f"{from_state} -> {to_state} is not a legal transition")
        unknown = set(fields) - _UPDATABLE
        if unknown:
            raise ValueError(f"cannot update {sorted(unknown)}")
        cols = ["state=?", "updated_at=?"]
        values: list[Any] = [to_state, self.now()]
        for k, v in fields.items():
            cols.append("result_json=?" if k == "result" else f"{k}=?")
            values.append(canonical_json(v) if k == "result" else v)
        with self.tx() as db:
            cur = db.execute(f"UPDATE calls SET {', '.join(cols)} WHERE key=? AND state=?",
                             (*values, key, from_state))
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


def _row(r: sqlite3.Row) -> CallRow:
    return CallRow(
        key=r["key"], run_id=r["run_id"], call_id=r["call_id"], principal=r["principal"], tool=r["tool"],
        args=json.loads(r["args_json"]), args_hash=r["args_hash"], request_hash=r["request_hash"],
        state=r["state"], reason=r["reason"],
        result=json.loads(r["result_json"]) if r["result_json"] is not None else None,
        approved_by=r["approved_by"], approved_hash=r["approved_hash"], expires_at=r["expires_at"],
    )
