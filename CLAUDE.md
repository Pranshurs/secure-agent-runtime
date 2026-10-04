# CLAUDE.md: standing rules for this repository

Read `docs/ARCHITECTURE.md` and `docs/TRANSACTION_SEMANTICS.md` before changing code.
Thesis: the model proposes, the runtime disposes. Policy uses only the principal, the
operator-registered tool spec and validated arguments, never model text.

Identity: a framework-neutral **transactional execution layer** for AI agents (authority,
transaction semantics, uncertain-effect reconciliation, frame conditions, Agent
Receipts). Not a generic sandbox, MCP firewall, policy proxy or framework wrapper. Out of
scope for now: RAG, memory/vector DBs, multi-agent, chat UI, marketplace, policy DSL,
Kubernetes, hosted control plane, billing, observability platform, model routing.

## Why this project exists
- A public portfolio piece for Applied AI / Agentic AI / AI infrastructure roles (India, EU,
  UK, US).
- Story: coding agents were used to build a runtime that stops AI agents from bypassing
  permissions, double-executing tools, corrupting state or escaping approval. The repo is
  openly AI-assisted; that is intended.
- A senior engineer will read the code and tests. It must show real understanding, not
  just volume.

## Truth rules
- Never claim anything not demonstrated: no invented users, deployments, benchmarks,
  latency figures or "production-ready" wording.
- README has a Limitations section (e.g. Python threads cannot be killed; real isolation
  needs a subprocess).
- Every number in the README must come from a command anyone can rerun.

## Test rules
- Tests must be able to fail. For every safety rule, break it on purpose (mutation) and
  confirm a test fails. A surviving mutant is a bug: strengthen the test or prove the
  mutant is unreachable.
- Run mutants only against a passing baseline, and report them honestly: killed /
  survived / equivalent, never a bare N/N that hides any.
- Never write tests that only grep the source code.
- Test at the real entry point (the runtime's public API), not just inner helpers.
- Authority is proven at the boundary: never trust caller-supplied labels, model text or
  tool annotations for a policy decision.

## Product rules
- Plug and play: `pip install -e .` plus one command runs the demo. Add Docker only if it
  helps.
- README in plain English: what it does, a quick start, how it works, security model,
  tests, limitations, licence.
- Licence: Apache-2.0 (owner decided).

## Process
- Feature branch, PR, green CI on Python 3.10 and 3.12. Self-review the diff before asking.
- Do not merge and do not make the repo public; the owner decides both.
- No force-push, no history rewrite, no secrets in code or logs.
- Do not touch any other repository. Do not host demos on ylemis.com.
- Subagents: Sonnet only, at most 2 at a time.
- When a slice is done, report: what works, test and mutation counts, what is not done.
- Commit author: Pranshu Raj <Pranshurs@users.noreply.github.com>. AI attribution trailers
  are fine.

## Commands
- Install: `pip install -e '.[dev]'`
- Tests: `pytest`
- Lint: `ruff check .`
- Demos: `secure-agent-runtime demo` (refund, frame, notes)
- Safety-rule mutation run: `python scripts/mutation_test.py`
- Overhead benchmark: `python scripts/bench.py`
