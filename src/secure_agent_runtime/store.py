"""Durable state: tool calls, the audit log and agent runs, in one SQLite file.

Two properties carry the runtime's guarantees:

* **Compare-and-set transitions.** A call moves between states only with
  ``UPDATE ... WHERE state IN (expected)``. Two workers racing to execute the same call,
  or a late result arriving after a timeout, can't both win.
* **Transition and audit commit together.** Every state change appends an audit event in
  the same transaction, so the log can't miss or invent a transition. Events form a
  SHA-256 hash chain over their full content and sequence number, so editing, deleting or
  reordering a past event is detectable by :meth:`Store.verify_audit`.

The chain is *tamper-evident*, not tamper-proof: someone who can write the file can
rebuild the whole chain. Anchor the latest hash elsewhere if that matters to you.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Callable, Iterable, Iterator

from .contracts import canonical_json

GENESIS = "0" * 64

_SCHEMA = """
CREATE TABLE IF NOT EXISTS calls (
    key            TEXT PRIMARY KEY,         -- run_id ':' call_id
    run_id         TEXT NOT NULL,
    call_id        TEXT NOT NULL,
    principal      TEXT NOT NULL,
    tool           TEXT NOT NULL,
    args_json      TEXT NOT NULL,
    args_hash      TEXT NOT NULL,
    state          TEXT NOT NULL,
    reason         TEXT NOT NULL DEFAULT '',
    result_json    TEXT,
    attempts       INTEGER NOT NULL DEFAULT 0,
    approved_by    TEXT,
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
CREATE TABLE IF NOT EXISTS runs (
    run_id         TEXT PRIMARY KEY,
    principal      TEXT NOT NULL,
    status         TEXT NOT NULL,
    messages_json  TEXT NOT NULL,
    output_json    TEXT,
    updated_at     REAL NOT NULL
);
"""


@dataclass(frozen=True)
class CallRow:
    key: str
    run_id: str
    call_id: str
    principal: str
    tool: str
    args: dict[str, Any]
    args_hash: str
    state: str
    reason: str
    result: dict[str, Any] | None
    attempts: int
    approved_by: str | None
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
        self._db.execute("PRAGMA journal_mode=WAL" if path != ":memory:" else "PRAGMA journal_mode=MEMORY")
        self._db.execute("PRAGMA busy_timeout=5000")
        self._db.executescript(_SCHEMA)

    def close(self) -> None:
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
        ts = self.now()
        data_json = canonical_json(data)
        h = _event_hash(prev, seq, ts, run_id, call_key, kind, data_json)
        db.execute("INSERT INTO events VALUES (?,?,?,?,?,?,?,?)",
                   (seq, ts, run_id, call_key, kind, data_json, prev, h))

    def record(self, run_id: str, kind: str, data: dict[str, Any], call_key: str | None = None) -> None:
        with self.tx() as db:
            self._append(db, run_id, call_key, kind, data)

    def events(self, run_id: str | None = None) -> list[Event]:
        q = "SELECT * FROM events" + (" WHERE run_id=?" if run_id else "") + " ORDER BY seq"
        with self._lock:
            rows = self._db.execute(q, (run_id,) if run_id else ()).fetchall()
        return [Event(r["seq"], r["ts"], r["run_id"], r["call_key"], r["kind"],
                      json.loads(r["data_json"]), r["prev_hash"], r["hash"]) for r in rows]

    def verify_audit(self) -> tuple[bool, str]:
        """Recompute the chain. Returns (ok, explanation of the first problem)."""
        prev, expected_seq = GENESIS, 1
        with self._lock:
            rows = self._db.execute("SELECT * FROM events ORDER BY seq").fetchall()
        for r in rows:
            if r["seq"] != expected_seq:
                return False, f"sequence gap: expected {expected_seq}, found {r['seq']}"
            if r["prev_hash"] != prev:
                return False, f"event {r['seq']}: prev_hash does not match event {r['seq'] - 1}"
            h = _event_hash(prev, r["seq"], r["ts"], r["run_id"], r["call_key"], r["kind"], r["data_json"])
            if h != r["hash"]:
                return False, f"event {r['seq']}: content does not match its hash"
            prev, expected_seq = h, expected_seq + 1
        return True, f"{len(rows)} events verified"

    # -- calls ------------------------------------------------------------------ #
    def insert_call(self, *, key: str, run_id: str, call_id: str, principal: str, tool: str,
                    args: dict[str, Any], args_hash: str, state: str, reason: str,
                    expires_at: float | None, event: dict[str, Any]) -> bool:
        """Insert a new call with its first event. False if the key already exists."""
        now = self.now()
        with self.tx() as db:
            try:
                db.execute(
                    "INSERT INTO calls (key, run_id, call_id, principal, tool, args_json, args_hash, state,"
                    " reason, expires_at, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                    (key, run_id, call_id, principal, tool, canonical_json(args), args_hash, state,
                     reason, expires_at, now, now))
            except sqlite3.IntegrityError:
                return False
            self._append(db, run_id, key, "call.requested", event)
            self._append(db, run_id, key, f"call.{state}", {"reason": reason})
        return True

    def transition(self, key: str, from_states: Iterable[str], to_state: str, *,
                   event: dict[str, Any] | None = None, **fields: Any) -> bool:
        """Compare-and-set ``state``; on success also update ``fields`` and append the event."""
        from_states = list(from_states)
        sets = ["state=?", "updated_at=?"] + [f"{k}=?" for k in fields]
        values = [to_state, self.now()] + [canonical_json(v) if k == "result_json" else v
                                           for k, v in fields.items()]
        marks = ",".join("?" * len(from_states))
        with self.tx() as db:
            cur = db.execute(f"UPDATE calls SET {', '.join(sets)} WHERE key=? AND state IN ({marks})",
                             (*values, key, *from_states))
            if cur.rowcount != 1:
                return False
            run_id = db.execute("SELECT run_id FROM calls WHERE key=?", (key,)).fetchone()["run_id"]
            self._append(db, run_id, key, f"call.{to_state}", event or {})
        return True

    def bump_attempts(self, key: str) -> None:
        with self.tx() as db:
            db.execute("UPDATE calls SET attempts = attempts + 1 WHERE key=?", (key,))

    def get_call(self, key: str) -> CallRow | None:
        with self._lock:
            r = self._db.execute("SELECT * FROM calls WHERE key=?", (key,)).fetchone()
        return _row(r) if r else None

    def calls(self, *, run_id: str | None = None, state: str | None = None) -> list[CallRow]:
        q, p = "SELECT * FROM calls WHERE 1=1", []
        if run_id:
            q, p = q + " AND run_id=?", p + [run_id]
        if state:
            q, p = q + " AND state=?", p + [state]
        with self._lock:
            return [_row(r) for r in self._db.execute(q + " ORDER BY created_at, key", p).fetchall()]

    # -- runs ------------------------------------------------------------------- #
    def save_run(self, run_id: str, principal: str, status: str, messages: list[dict[str, Any]],
                 output: dict[str, Any] | None = None) -> None:
        with self.tx() as db:
            db.execute(
                "INSERT INTO runs VALUES (?,?,?,?,?,?) ON CONFLICT(run_id) DO UPDATE SET"
                " status=excluded.status, messages_json=excluded.messages_json,"
                " output_json=excluded.output_json, updated_at=excluded.updated_at",
                (run_id, principal, status, json.dumps(messages), None if output is None else canonical_json(output),
                 self.now()))
            self._append(db, run_id, None, f"run.{status}", {"messages": len(messages)})

    def load_run(self, run_id: str) -> dict[str, Any] | None:
        with self._lock:
            r = self._db.execute("SELECT * FROM runs WHERE run_id=?", (run_id,)).fetchone()
        if not r:
            return None
        return {"run_id": r["run_id"], "principal": r["principal"], "status": r["status"],
                "messages": json.loads(r["messages_json"]),
                "output": json.loads(r["output_json"]) if r["output_json"] else None}


def _row(r: sqlite3.Row) -> CallRow:
    return CallRow(
        key=r["key"], run_id=r["run_id"], call_id=r["call_id"], principal=r["principal"], tool=r["tool"],
        args=json.loads(r["args_json"]), args_hash=r["args_hash"], state=r["state"], reason=r["reason"],
        result=json.loads(r["result_json"]) if r["result_json"] else None, attempts=r["attempts"],
        approved_by=r["approved_by"], expires_at=r["expires_at"],
    )
