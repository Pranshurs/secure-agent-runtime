# Good first issues

These are candidates. None has been filed on GitHub yet. Each is small, self-contained,
and has an obvious test.

1. **`Store.head()` export helper.** Add `secure-agent-runtime head --db sar.db` to print
   the chain head, so users can anchor it somewhere else. Test: the CLI output equals
   `Store.head()`.
2. **`verify-receipt --db`.** Let the CLI verify a receipt against a store file, as
   `verify_receipt(..., store=)` already does. Test: a tampered event is reported.
3. **`FileTreeObserver` size guard.** Add an option to refuse (or mark unverifiable)
   snapshots of trees over N files or bytes, so a frame check can't stall on a huge
   directory.
4. **Frame spec from a dict/YAML-like mapping.** `FrameSpec.from_json` exists. Add a
   loader for a plain mapping with `required` given as strings like
   `"pyproject.toml modified"`, with clear errors.
5. **Receipt pretty-printer.** Add `secure-agent-runtime show-receipt FILE` that prints
   the REQUIRED / UNDECLARED / FORBIDDEN / OUTCOME summary used in the demo.
6. **More hostile-input cases.** Extend `tests/test_hostile_inputs.py` (for example
   huge key counts, or keys that differ only by Unicode normalisation) and record the
   behaviour.
7. **`Policy` constraint helpers.** Add small reusable constraints such as
   `max_value("amount_inr", 10_000)` or `one_of("currency", {...})`, each with a mutant.

Larger, discuss first: an Ed25519 receipt signer, an MCP client adapter, a
subprocess-isolated tool runner.
