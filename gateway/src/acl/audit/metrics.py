"""Prometheus metrics (concept §13). One registry per app so test apps do not collide.

acl_decisions_total{point,action}
acl_control_latency_seconds{control}                histogram, per control
acl_upstream_latency_seconds{connector,model}       histogram
acl_tokens_total{direction,model}                   input / output / reasoning
acl_spend_usd_total{connector,model}
acl_gpu_seconds_total{connector,model}
acl_audit_events_total{event_type}
acl_audit_chain_head_seq
"""

from __future__ import annotations

from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram, generate_latest

from acl.contracts.audit import AuditEvent

_LATENCY_BUCKETS = (0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0)


class GatewayMetrics:
    def __init__(self) -> None:
        self.registry = CollectorRegistry()
        self.decisions = Counter(
            "acl_decisions_total", "Decisions by action", ["point", "action"], registry=self.registry
        )
        self.control_latency = Histogram(
            "acl_control_latency_seconds",
            "Per-control inspection latency",
            ["control"],
            buckets=_LATENCY_BUCKETS,
            registry=self.registry,
        )
        self.upstream_latency = Histogram(
            "acl_upstream_latency_seconds",
            "Upstream model call latency",
            ["connector", "model"],
            buckets=_LATENCY_BUCKETS,
            registry=self.registry,
        )
        self.tokens = Counter("acl_tokens_total", "Tokens metered", ["direction", "model"], registry=self.registry)
        self.spend = Counter("acl_spend_usd_total", "Spend in USD", ["connector", "model"], registry=self.registry)
        self.gpu = Counter(
            "acl_gpu_seconds_total", "GPU-seconds metered", ["connector", "model"], registry=self.registry
        )
        self.events = Counter("acl_audit_events_total", "Audit events written", ["event_type"], registry=self.registry)
        self.head_seq = Gauge(
            "acl_audit_chain_head_seq", "Sequence number of the audit chain head", registry=self.registry
        )

    def observe_event(self, event: AuditEvent) -> None:
        self.events.labels(event.event_type.value).inc()
        self.head_seq.set(event.seq)
        if event.decision is not None and event.point is not None:
            self.decisions.labels(event.point.value, event.decision.action.value).inc()
        for v in event.verdicts:
            if v.status.value != "cached":
                self.control_latency.labels(v.control_id).observe(v.latency_ms / 1000.0)
        model = event.model or "none"
        connector = event.connector or "none"
        if event.latency and event.latency.upstream_ms and event.model:
            self.upstream_latency.labels(connector, model).observe(event.latency.upstream_ms / 1000.0)
        u = event.usage
        if u is not None:
            if u.input_tokens:
                self.tokens.labels("input", model).inc(u.input_tokens)
            if u.output_tokens:
                self.tokens.labels("output", model).inc(u.output_tokens)
            if u.reasoning_tokens:
                self.tokens.labels("reasoning", model).inc(u.reasoning_tokens)
            if u.usd:
                self.spend.labels(connector, model).inc(u.usd)
            if u.gpu_seconds:
                self.gpu.labels(connector, model).inc(u.gpu_seconds)

    def render(self) -> bytes:
        return generate_latest(self.registry)
