"""OpenTelemetry instrumentation: useful, privacy-safe, and unable to change a decision."""

from __future__ import annotations

import pytest
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import InMemoryMetricReader
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from secure_agent_runtime.examples import refund as rf
from secure_agent_runtime.telemetry import Telemetry

SECRET_ORDER = 987654321


@pytest.fixture
def otel():
    exporter = InMemorySpanExporter()
    tp = TracerProvider()
    tp.add_span_processor(SimpleSpanProcessor(exporter))
    reader = InMemoryMetricReader()
    mp = MeterProvider(metric_readers=[reader])
    return Telemetry(tp.get_tracer("test"), mp.get_meter("test")), exporter, reader


def run_lost_response(telemetry, store):
    service = rf.PaymentService()
    rt = rf.build_runtime(service, store, isolation="thread", telemetry=telemetry)
    o = rt.propose(run_id="ticket-1", principal_id=rf.AGENT, call_id="c", tool="refund",
                   arguments={"order": SECRET_ORDER, "amount_inr": 4500})
    rf.approve_as_finance(rt, o)
    service.fail_next = "after_effect"
    first = rt.execute(o.key)
    settled = rt.reconcile(o.key)
    rt.receipt(o.key, signing_key=b"k" * 32)
    return rt, o, first, settled, service


def test_lifecycle_is_traced(otel, store):
    telemetry, exporter, reader = otel
    rt, o, first, settled, _ = run_lost_response(telemetry, store)
    spans = {s.name: s for s in exporter.get_finished_spans()}
    assert {"sar.propose", "sar.approve", "execute_tool refund", "sar.reconcile", "sar.receipt"} <= set(spans)
    ex = spans["execute_tool refund"].attributes
    assert ex["gen_ai.operation.name"] == "execute_tool" and ex["gen_ai.tool.name"] == "refund"
    assert ex["sar.state"] == "effect_unknown" and ex["sar.attempt"] == 1 and ex["sar.isolation"] == "thread"
    assert spans["sar.reconcile"].attributes["sar.reconcile.finding"] == "applied"
    assert spans["sar.receipt"].attributes["sar.signature.alg"] == "HMAC-SHA256"
    action_ids = {s.attributes.get("sar.action_id") for s in spans.values()}
    assert len(action_ids - {None}) == 1  # one correlation id across the whole lifecycle


def test_metrics_count_transitions_and_time_dispatches(otel, store):
    telemetry, exporter, reader = otel
    run_lost_response(telemetry, store)
    data = reader.get_metrics_data()
    metrics = {m.name: m for rm in data.resource_metrics for sm in rm.scope_metrics for m in sm.metrics}
    states = {dict(p.attributes)["sar.state"]: p.value for p in metrics["sar.action.transitions"].data.data_points}
    assert states["effect_unknown"] >= 1 and states["succeeded"] >= 1
    assert metrics["sar.dispatch.duration"].data.data_points[0].count == 1


def test_no_argument_values_or_credentials_in_telemetry(otel, store):
    telemetry, exporter, reader = otel
    rt, o, *_ = run_lost_response(telemetry, store)
    dumped = repr([dict(s.attributes) for s in exporter.get_finished_spans()])
    assert str(SECRET_ORDER) not in dumped and "4500" not in dumped
    assert o.key not in dumped  # idempotency keys may embed user data; only action ids are emitted


class ExplodingTracer:
    def start_as_current_span(self, *a, **k):
        raise RuntimeError("collector down")


class ExplodingMeter:
    def create_counter(self, *a, **k):
        raise RuntimeError("no metrics")

    create_histogram = create_counter


def test_broken_telemetry_cannot_change_decisions(store):
    rt, o, first, settled, service = run_lost_response(Telemetry(ExplodingTracer(), ExplodingMeter()), store)
    assert first.state == "effect_unknown" and settled.state == "succeeded"
    assert len(service.refunds) == 1 and service.calls == 1


def test_span_exit_failure_is_contained(store):
    class BadCM:
        def __enter__(self):
            class S:
                def set_attribute(self, *a):
                    raise RuntimeError("bad attribute")
            return S()

        def __exit__(self, *a):
            raise RuntimeError("bad exit")

    class Tracer:
        def start_as_current_span(self, name):
            return BadCM()

    rt, o, first, settled, service = run_lost_response(Telemetry(Tracer()), store)
    assert settled.state == "succeeded" and len(service.refunds) == 1


def test_disabled_telemetry_is_a_no_op(store):
    rt, o, first, settled, _ = run_lost_response(Telemetry.disabled(), store)
    assert settled.state == "succeeded"
