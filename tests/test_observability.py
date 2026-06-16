import pytest
from fastapi.testclient import TestClient

from sentinel.governance import AuditLog
from sentinel.service.app import create_app
from sentinel.service.metrics import Metrics
from sentinel.service.observability import configure_otel, otel_available, prometheus_text


def _metrics_with_decisions():
    m = Metrics()
    m.record(0.1, False, "allow")
    m.record(0.9, True, "block")
    return m


def test_prometheus_text_format():
    m = _metrics_with_decisions()
    text = prometheus_text(m, AuditLog())
    assert "# TYPE sentinel_prompts_assessed counter" in text
    assert "sentinel_prompts_assessed 2" in text
    assert 'sentinel_decisions_total{decision="block"} 1' in text
    assert "sentinel_block_rate 0.5" in text


def test_prometheus_endpoint_served():
    client = TestClient(create_app(benign_n=200))
    client.post("/assess", json={"prompt": "What time does the office open?"})
    resp = client.get("/metrics/prometheus")
    assert resp.status_code == 200
    assert "text/plain" in resp.headers["content-type"]
    assert "sentinel_prompts_assessed" in resp.text


def test_otel_disabled_without_endpoint(monkeypatch):
    monkeypatch.delenv("OTEL_EXPORTER_OTLP_ENDPOINT", raising=False)
    assert configure_otel(Metrics(), AuditLog()) is False


@pytest.mark.skipif(not otel_available(), reason="opentelemetry not installed")
def test_otel_instruments_export_metrics():
    from opentelemetry.sdk.metrics.export import InMemoryMetricReader

    from sentinel.service.observability import instrument_metrics

    metrics = _metrics_with_decisions()
    reader = InMemoryMetricReader()
    instrument_metrics(reader, metrics, AuditLog())
    data = reader.get_metrics_data()

    names = {
        metric.name
        for rm in data.resource_metrics
        for sm in rm.scope_metrics
        for metric in sm.metrics
    }
    assert "sentinel.prompts_assessed" in names
    assert "sentinel.block_rate" in names
