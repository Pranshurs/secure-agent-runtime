# Operating SAR

## Deployment model

* **One process owns one database file.** `Store(path)` takes an exclusive `flock` on
  `<path>.lock`. A second owner, in this or another process, gets `StoreLocked`. Run one
  SAR runtime per database. For more throughput, shard by database (for example one per
  tenant or per agent pool), not by sharing one.
* **Platforms.** Linux is the primary target and the only one where a killed runtime
  also kills its worker processes (`PR_SET_PDEATHSIG`). macOS works, and CI runs the
  test suite there, but an orphaned worker can outlive a killed runtime; reconcile again
  after a crash. Keep the database on a local file system, and open it by one path:
  the lock follows symlinks, but hard links, bind mounts and network file systems
  are not detected. **Windows is not supported** for file-backed stores (no `fcntl`).
* **Python 3.10–3.13.** The only runtime dependency is pydantic. Ed25519 receipts need the
  `signing` extra (`cryptography`); telemetry needs the `otel` extra.

## Lifecycle

`with Store(path) as store:` and `with Runtime(...) as rt:` close what they opened. A
`Runtime` closes its store only if it created it (`owns_store=True`, as the example
factories do); a store you pass in stays yours. A closed `Runtime` refuses every
operation. A `Store` dropped without `close()` keeps its file lock until the process
exits.

## Start-up and recovery

Constructing a `Runtime` attaches it to its store and, by default, runs `recover()`.
Any action left `executing` by a crash becomes `effect_unknown`. `runtime.recovered`
lists them, and a warning is logged. Nothing is re-dispatched automatically. Settle them
by reconciling:

```python
for key in rt.recovered:
    o = rt.reconcile(key)              # asks the tool's reconciler
    if o.state == "approved":          # it said "not applied"
        rt.execute(key)                # another dispatch, re-checked (within the approval's TTL)
    elif o.state == "effect_unknown":  # no reconciler, or it couldn't decide
        ...                            # a person decides: rt.resolve(key, credential=..., applied=...)
```

## Approvals in production

Give the runtime your own `Authenticator`; the demo `TokenAuthenticator` is not for
people. Mint one credential per approval click, scoped to the digest you showed the
approver. Keep `approval_ttl_s` short enough that an approval can't be used long after
it was given (the default is one hour).

## What to watch

* **Logs** (logger `secure_agent_runtime`; silent unless you configure logging):
  * WARNING for `effect_unknown`, timeouts, discarded late results, throttled dispatches,
    recovered orphans and results that couldn't be recorded;
  * INFO for reconciliation outcomes.
* **Metrics** (with the `otel` extra): `sar.action.transitions` by tool and state, and
  `sar.dispatch.duration`. Alert on a rising `effect_unknown` count, and on actions that
  stay `effect_unknown`.
* **Traces**: one `sar.action_id` correlates proposal, approval, dispatch,
  reconciliation and receipt.
* **Audit**: `store.verify_audit(anchor=...)`. Copy `store.head()` somewhere else
  periodically, so that truncation can be detected.

## Data and backups

* The database holds tool arguments, results and the audit log in plaintext. It and its
  lock file are created 0600. Encrypt the volume if that matters to you.
* SQLite runs in WAL mode. For a backup, use SQLite's online backup (for example
  `sqlite3 sar.db ".backup copy.db"`). It reads concurrently, but a long write lock held
  by another tool makes SAR's writes fail with `StoreError` after `busy_timeout_ms`
  (default 5 s). Nothing is half-applied when that happens.
* The schema is versioned (`PRAGMA user_version`). A database from an unknown version
  is refused rather than guessed at.
* The database and audit log grow with every action and replay. There is no compaction
  yet.

## Keys

SAR uses the keys you give it (an `Ed25519Signer` for receipts, or HMAC keys of at
least 16 bytes). Store private keys in your KMS or HSM, and publish public keys with
their `key_id`. Rotation means a new `key_id`; verifiers keep old public keys for old
receipts.

## Capacity

Measure with `python scripts/bench.py` on your hardware. A thread-isolated dispatch
costs a few SQLite transactions and a thread. A process-isolated dispatch adds a process
start (hundreds of milliseconds with `spawn`). Use process isolation for consequential
tools, where that cost is small next to the action itself, and thread isolation for
cheap reads.
