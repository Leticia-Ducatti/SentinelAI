"""Observability exports: Prometheus text and optional OpenTelemetry.

Two paths, mirroring the rest of the project's optional-with-fallback design:

    * ``prometheus_text`` renders the running counters in the Prometheus / OpenMetrics
      exposition format, served at ``GET /metrics/prometheus``. No dependency, so it
      always works and is the demonstrable artifact a scraper consumes.
    * ``configure_otel`` pushes the same metrics over OTLP when the OpenTelemetry SDK
      is installed (the ``[otel]`` extra) and ``OTEL_EXPORTER_OTLP_ENDPOINT`` is set;
      otherwise it is a no-op.
"""

from __future__ import annotations

import importlib.util
import os
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sentinel.governance import AuditLog
    from sentinel.service.metrics import Metrics


def prometheus_text(metrics: "Metrics", audit: "AuditLog") -> str:
    """Render metrics in the Prometheus exposition format."""
    lines = [
        "# HELP sentinel_prompts_assessed Total prompts assessed.",
        "# TYPE sentinel_prompts_assessed counter",
        f"sentinel_prompts_assessed {metrics.prompts_assessed}",
        "# HELP sentinel_alerts_total Prompts that raised an alert.",
        "# TYPE sentinel_alerts_total counter",
        f"sentinel_alerts_total {metrics.alerts}",
        "# HELP sentinel_decisions_total Decisions by outcome.",
        "# TYPE sentinel_decisions_total counter",
        f'sentinel_decisions_total{{decision="allow"}} {metrics.allowed}',
        f'sentinel_decisions_total{{decision="flag"}} {metrics.flagged}',
        f'sentinel_decisions_total{{decision="block"}} {metrics.blocked}',
        "# HELP sentinel_block_rate Fraction of prompts blocked.",
        "# TYPE sentinel_block_rate gauge",
        f"sentinel_block_rate {metrics.block_rate}",
        "# HELP sentinel_mean_risk Mean fused risk score.",
        "# TYPE sentinel_mean_risk gauge",
        f"sentinel_mean_risk {metrics.mean_risk}",
        "# HELP sentinel_audit_entries Entries currently in the audit log.",
        "# TYPE sentinel_audit_entries gauge",
        f"sentinel_audit_entries {len(audit)}",
    ]
    return "\n".join(lines) + "\n"


def otel_available() -> bool:
    return importlib.util.find_spec("opentelemetry") is not None


def instrument_metrics(reader, metrics: "Metrics", audit: "AuditLog"):
    """Build a MeterProvider whose observable gauges read live from the app state.

    Takes the metric reader as an argument so production (OTLP) and tests
    (in-memory) share the same instrument wiring.
    """
    from opentelemetry.metrics import Observation
    from opentelemetry.sdk.metrics import MeterProvider

    provider = MeterProvider(metric_readers=[reader])
    meter = provider.get_meter("sentinelai")
    meter.create_observable_gauge(
        "sentinel.prompts_assessed", callbacks=[lambda _: [Observation(metrics.prompts_assessed)]]
    )
    meter.create_observable_gauge("sentinel.alerts", callbacks=[lambda _: [Observation(metrics.alerts)]])
    meter.create_observable_gauge("sentinel.block_rate", callbacks=[lambda _: [Observation(metrics.block_rate)]])
    meter.create_observable_gauge("sentinel.mean_risk", callbacks=[lambda _: [Observation(metrics.mean_risk)]])
    meter.create_observable_gauge("sentinel.audit_entries", callbacks=[lambda _: [Observation(len(audit))]])
    return provider


def configure_otel(metrics: "Metrics", audit: "AuditLog") -> bool:
    """Push metrics over OTLP if the SDK is installed and an endpoint is set."""
    endpoint = os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT")
    if not endpoint or not otel_available():
        return False
    try:
        from opentelemetry import metrics as otel_metrics
        from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter
        from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader

        reader = PeriodicExportingMetricReader(OTLPMetricExporter())
        provider = instrument_metrics(reader, metrics, audit)
        otel_metrics.set_meter_provider(provider)
        return True
    except Exception:
        return False
