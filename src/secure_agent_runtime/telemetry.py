"""Optional OpenTelemetry traces and metrics, privacy-safe and failure-isolated.

If ``opentelemetry-api`` is installed (the ``otel`` extra), the runtime emits spans and
metrics through the global providers, which are no-ops until the application installs
an SDK. Pass ``Telemetry(tracer=..., meter=...)`` to use specific providers, or
``Telemetry.disabled()`` to turn it off.

What is recorded: operation names, tool name and version, action id, run id, state,
policy verdict, attempt number, isolation mode, reconciliation finding, frame verdict,
signature algorithm, durations. What is never recorded: argument values, tool results,
reasons that may quote them, credentials, idempotency keys (they may be built from user
data).

Span names: ``sar.propose``, ``sar.approve``, ``sar.reject``, ``sar.cancel``,
``sar.reconcile``, ``sar.resolve``, ``sar.receipt`` and ``execute_tool <tool>`` for
dispatches (with ``gen_ai.operation.name=execute_tool`` and ``gen_ai.tool.name``, from
the OpenTelemetry GenAI conventions, which are still in Development status).

Metrics: ``sar.action.transitions`` (counter, by tool and resulting state) and
``sar.dispatch.duration`` (histogram, seconds).

Instrumentation can never change a safety decision: every call into OpenTelemetry is
wrapped, and an exception from it is logged at DEBUG and dropped.
"""

from __future__ import annotations

import logging
import sys
import time
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

log = logging.getLogger(__name__)

_ALLOWED = frozenset({
    "sar.tool", "sar.tool.version", "sar.action_id", "sar.run_id", "sar.state", "sar.verdict", "sar.attempt",
    "sar.isolation", "sar.reconcile.finding", "sar.frame.verdict", "sar.signature.alg", "sar.outcome",
    "gen_ai.operation.name", "gen_ai.tool.name",
})


class _Span:
    def __init__(self, span: Any) -> None:
        self._span = span

    def set(self, key: str, value: Any) -> None:
        if self._span is None or key not in _ALLOWED or value is None:
            return
        try:
            self._span.set_attribute(key, value if isinstance(value, (str, int, float, bool)) else str(value))
        except Exception:  # pragma: no cover - defensive
            log.debug("telemetry: set_attribute failed", exc_info=True)


class Telemetry:
    def __init__(self, tracer: Any = None, meter: Any = None) -> None:
        self._tracer = tracer
        self._counter = self._histogram = None
        if meter is not None:
            try:
                self._counter = meter.create_counter("sar.action.transitions", unit="1",
                                                     description="actions reaching a state")
                self._histogram = meter.create_histogram("sar.dispatch.duration", unit="s",
                                                         description="time from claim to recorded outcome")
            except Exception:
                log.debug("telemetry: could not create instruments", exc_info=True)

    @classmethod
    def from_global(cls) -> Telemetry:
        try:
            from opentelemetry import metrics, trace
        except ImportError:
            return cls()
        try:
            return cls(trace.get_tracer("secure_agent_runtime"), metrics.get_meter("secure_agent_runtime"))
        except Exception:  # pragma: no cover - defensive
            return cls()

    @classmethod
    def disabled(cls) -> Telemetry:
        return cls()

    @contextmanager
    def span(self, name: str, **attrs: Any) -> Iterator[_Span]:
        cm = None
        span = None
        if self._tracer is not None:
            try:
                cm = self._tracer.start_as_current_span(name)
                span = cm.__enter__()
            except Exception:
                log.debug("telemetry: could not start span %s", name, exc_info=True)
                cm = span = None
        proxy = _Span(span)
        for k, v in attrs.items():
            proxy.set(k, v)
        try:
            yield proxy
        finally:
            if cm is not None:
                try:
                    cm.__exit__(*sys.exc_info())
                except Exception:
                    log.debug("telemetry: could not end span %s", name, exc_info=True)

    def transition(self, tool: str, state: str) -> None:
        if self._counter is None:
            return
        try:
            self._counter.add(1, {"sar.tool": tool, "sar.state": state})
        except Exception:
            log.debug("telemetry: counter failed", exc_info=True)

    def dispatch_duration(self, tool: str, state: str, started: float) -> None:
        if self._histogram is None:
            return
        try:
            self._histogram.record(time.monotonic() - started, {"sar.tool": tool, "sar.state": state})
        except Exception:
            log.debug("telemetry: histogram failed", exc_info=True)
