# Contributing

Thanks for looking. SAR is small on purpose: authority, transaction semantics,
reconciliation, frame conditions and receipts. Please keep changes inside that scope
(see "Not in scope" below).

## Setup

```bash
git clone https://github.com/Pranshurs/secure-agent-runtime && cd secure-agent-runtime
python -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'
pytest && ruff check .
```

## The bar for a change

1. **Every safety rule has a test that fails without it.** If you add or change a rule,
   add a mutant to `scripts/mutation_test.py` that disables it, and check that
   `python scripts/mutation_test.py -k <ID>` reports it killed. A surviving mutant
   means a test is missing. If you are sure the mutant is unreachable, declare it
   `equivalent=` and say why.
2. **Test through the public API** (`Runtime`, `Agent`, `verify_receipt`,
   `check_frame`), not private helpers. Never write a test that only greps the source.
3. **Concurrency and crashes are part of the API.** Use barriers for races and the
   `faults=` hook for crash points.
4. **No claims without a command.** Any number in the README must come from a script
   anyone can rerun.
5. Supported Python versions are 3.10 and 3.12 in CI. Run `ruff check .` before pushing.

## Layout

```
src/secure_agent_runtime/
  action.py      canonical action envelope        effects.py   observers + frame checks
  contracts.py   tool contracts, validation        receipts.py  Agent Receipts
  policy.py      authority                         runtime.py   the governor
  store.py       SQLite state machine + audit      agent.py     minimal agent loop
  examples/      notes, refund, version_bump       schemas/     receipt JSON Schema
tests/           one file per concern
scripts/         mutation_test.py, bench.py
docs/            architecture and semantics
```

## Not in scope

RAG, memory or vector stores, multi-agent orchestration, chat UIs, a policy DSL,
Kubernetes, a hosted control plane, model routing, generic observability. Thin
framework adapters are welcome as optional extras once they have tests.

## Good first issues

See [docs/GOOD_FIRST_ISSUES.md](docs/GOOD_FIRST_ISSUES.md).

## Licence

By contributing you agree that your contributions are licensed under Apache-2.0.
