# Where SAR fits

**SAR's thesis.** Authorisation and approval are not enough for consequential agent
actions. Execution must stay safe when the outcome becomes uncertain: a timeout, a lost
response or a crash. Afterwards there must be evidence of what was authorised and what
actually changed.

Several mature systems cover parts of this. SAR is meant to complement them, not
replace them. The descriptions below were compiled in October 2026 from each project's
public documentation as surfaced by web search. Direct fetches of three of the pages
(OWASP GenAI, OpenAI Agents SDK, Dapr docs) were blocked in the environment where this
was written, so those summaries are second-hand. Check them yourself before relying on
a detail, because these projects move quickly.

## Agent SDKs with human-in-the-loop approvals

The **OpenAI Agents SDK** can mark tools as needing approval. A run is interrupted at
such a call, its state can be serialised, and it resumes after an approve or reject
decision.

*Overlap:* pausing for a human before a sensitive tool runs.

*What SAR adds:*
* the approval is bound to a digest of the whole canonical action (arguments, tool
  version and schema, declared effects, deadline), re-checked just before dispatch;
* one-time, scopable approval credentials;
* a durable per-action state machine, including `effect_unknown`;
* reconciliation before any re-dispatch;
* frame conditions and signed receipts.

SAR can sit underneath such an SDK as the executor of its approved tool calls; see
INTEGRATIONS.md.

## Durable workflow engines (Temporal, Dapr Workflow, AWS durable execution, Restate)

Temporal and Dapr document that activities run *at least once*. They recommend
idempotent activities, and provide identifiers per execution or attempt (for example
Dapr's `task_execution_id`) to build deduplication. Temporal's guidance sums it up as
at-least-once plus idempotency giving "effectively once".

*Overlap:* durable state, retries, crash recovery, fencing of attempts.

*What SAR adds:*
* the inverse default for consequential actions: *at most one dispatch per approval*,
  never a blind retry of an uncertain outcome, and an explicit `effect_unknown` that only
  reconciliation or a human can leave;
* authority coupled to the action: policy, digest-bound approval, re-check at dispatch;
* frame conditions on what changed;
* receipts.

*What they do that SAR doesn't:* distributed, multi-node orchestration of long
workflows, timers, scaling, operational tooling. SAR is a single-node library. For a
large workflow, run SAR inside an activity; that activity is then at-most-once with
reconciliation.

## Agent governance toolkits and standards

The **Microsoft Agent Governance Toolkit** (open source, released April 2026) describes
deterministic policy enforcement that intercepts agent actions before execution. It
also offers cryptographic agent identities, inter-agent trust, sandboxing and
compliance mapping, with integrations for several agent frameworks.

The **OWASP Agent Control Standard (ACS)** describes three pillars: instrument (runtime
hooks across the agent lifecycle), trace (structured observability in OpenTelemetry and
OCSF) and inspect (a dynamic agent bill of materials).

*Overlap:* policy before execution, identity, audit, OpenTelemetry tracing.

*What SAR adds:* depth on one action's transactional effect lifecycle, which these
frameworks treat as one step:
* what happens when a permitted action's outcome is unknown;
* how a retry is kept from becoming a second refund;
* how a stale worker is kept from deciding a newer attempt;
* how to prove afterwards what the action changed beyond its task.

SAR's spans follow the OpenTelemetry GenAI `execute_tool` convention, so its events can
flow into the same pipelines.

## Sandboxes (containers, seccomp, gVisor, VMs, network policy)

Sandboxes limit **what a tool can touch**. SAR decides **whether and how many times** a
tool runs, and records **what it changed**. A `FileTreeObserver` pointed at a sandbox's
writable mount gives frame checks over exactly that scope.

## Summary

| concern | agent SDK HITL | workflow engines | governance toolkits / ACS | sandboxes | SAR |
|---|---|---|---|---|---|
| pause for human approval | yes | via signals | yes | – | yes, bound to the action digest |
| deterministic policy before execution | partly | – | yes | – | yes (small, not a DSL) |
| durable execution state | run state | yes, distributed | – | – | yes, single node |
| uncertain outcome as a first-class state | – | at-least-once retries | – | – | `effect_unknown` + reconciliation |
| attempt fencing | – | yes | – | – | yes |
| what changed versus what was allowed | – | – | partly (audit) | limits scope | frame conditions |
| verifiable per-action evidence | traces | history | audit logs | – | Ed25519 Agent Receipts |
| isolation of tool code | – | worker processes | sandboxing | yes | killable worker processes only |

Sources:
* [OWASP Top 10 for Agentic Applications (via Giskard summary)](https://www.giskard.ai/knowledge/owasp-top-10-for-agentic-application-2026)
* [OWASP Agent Control Standard](https://genai.owasp.org/resource/agent-control-standard/)
* [Microsoft Agent Governance Toolkit (overview)](https://www.i-programmer.info/news/105-artificial-intelligence/18796-microsoft-releases-open-source-agent-governance-toolkit-.html)
* [Temporal: idempotency and durable execution](https://temporal.io/blog/idempotency-and-durable-execution)
* [Dapr workflow features and concepts](https://docs.dapr.io/developing-applications/building-blocks/workflow/workflow-features-concepts/)
* [OpenAI Agents SDK human-in-the-loop](https://openai.github.io/openai-agents-python/human_in_the_loop/)
