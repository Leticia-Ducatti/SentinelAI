"""FastAPI application for SentinelAI.

``create_app`` builds a benign-calibrated ``RiskMonitor`` and wires it to the
endpoints. The service is meant to run inline in front of an LLM application:
the caller posts a prompt to ``/assess`` before forwarding it to the model and
uses the returned decision (allow / flag / block) as a guardrail.
"""

from __future__ import annotations

import logging
from typing import Optional

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, PlainTextResponse

from sentinel.data import make_benign, make_benign_responses
from sentinel.detectors.classifier import TrainedInjectionClassifier
from sentinel.exposure import ExposureScanner
from sentinel.governance import AuditLog, model_card
from sentinel.monitor import RiskMonitor
from sentinel.output_monitor import OutputMonitor
from sentinel.redteam import LLMClient, run_campaign
from sentinel.service.landing import CONSOLE_HTML, LANDING_HTML
from sentinel.service.metrics import Metrics
from sentinel.service.observability import configure_otel, prometheus_text
from sentinel.service.schemas import (
    AssessOutputRequest,
    AssessOutputResponse,
    AssessRequest,
    AssessResponse,
    AuditEntry,
    AuditResponse,
    CampaignRequest,
    CampaignResponse,
    ExposureFinding,
    ExposureRequest,
    ExposureResponse,
    HealthResponse,
    LLMStatusResponse,
    MetricsResponse,
)

logger = logging.getLogger("sentinel.service")

_DESCRIPTION = """\
**SentinelAI** is a risk-monitoring guardrail for LLM applications.

Send each prompt to `POST /assess` before calling your model, and use the
returned **decision** as a gate:

- `allow` &mdash; looks safe, forward it to the model.
- `flag` &mdash; suspicious, route to a human.
- `block` &mdash; refuse.

It also scores the model's **response** (`/assess/output`), scans your public
**footprint** for exposure (`/exposure/scan`), and **red-teams** its own
detectors (`/redteam/campaign`). Every decision is recorded in a content-free
audit log (`/audit`), and `/modelcard` says what the system does and where it is
weak. New here? Open the landing page at [`/`](/).
"""

_TAGS = [
    {"name": "Guardrail", "description": "Score prompts and responses; decide allow / flag / block."},
    {"name": "Recon", "description": "Scan an organisation's public footprint for exposure."},
    {"name": "Red team", "description": "Adaptive attacks against the detectors, then hardening."},
    {"name": "Governance", "description": "Audit trail and model card."},
    {"name": "Ops", "description": "Health, metrics, and LLM backend status."},
]


def decide(risk: float, alert_threshold: float, block_threshold: float) -> str:
    if risk > block_threshold:
        return "block"
    if risk > alert_threshold:
        return "flag"
    return "allow"


def create_app(
    monitor: Optional[RiskMonitor] = None,
    benign_n: int = 300,
    alert_threshold: float = 0.5,
    block_threshold: float = 0.6,
) -> FastAPI:
    app = FastAPI(
        title="SentinelAI",
        description=_DESCRIPTION,
        version="0.1.0",
        openapi_tags=_TAGS,
        contact={"name": "Leticia Ducatti"},
        license_info={"name": "MIT"},
    )

    @app.get("/", include_in_schema=False, response_class=HTMLResponse)
    def landing() -> HTMLResponse:
        return HTMLResponse(LANDING_HTML)

    @app.get("/console", include_in_schema=False, response_class=HTMLResponse)
    def console() -> HTMLResponse:
        return HTMLResponse(CONSOLE_HTML)

    if monitor is None:
        monitor = RiskMonitor(alert_threshold=alert_threshold)
        # Use the trained classifier if a matching artifact has been built.
        monitor.classifier = TrainedInjectionClassifier.try_load(monitor.embedder)
        monitor.fit(make_benign(benign_n))
    else:
        monitor.alert_threshold = alert_threshold

    app.state.monitor = monitor
    app.state.output_monitor = OutputMonitor(alert_threshold=alert_threshold).fit(
        make_benign_responses(benign_n)
    )
    app.state.metrics = Metrics()
    app.state.audit = AuditLog()
    app.state.otel_enabled = configure_otel(app.state.metrics, app.state.audit)
    app.state.alert_threshold = alert_threshold
    app.state.block_threshold = block_threshold

    @app.get("/health", response_model=HealthResponse, tags=["Ops"], summary="Liveness and monitor status")
    def health() -> HealthResponse:
        return HealthResponse(
            status="ok",
            fitted=hasattr(monitor, "_anomaly_anchor"),
            embedder_fallback=getattr(monitor.embedder, "is_fallback", None),
            classifier_active=app.state.monitor.classifier is not None,
            otel_enabled=app.state.otel_enabled,
        )

    @app.post(
        "/assess",
        response_model=AssessResponse,
        tags=["Guardrail"],
        summary="Score a prompt",
        description="Score one incoming prompt and return a risk score plus an allow / flag / block decision.",
    )
    def assess(req: AssessRequest) -> AssessResponse:
        scored = app.state.monitor.score_prompt(req.prompt)
        risk = float(scored["risk"])
        alert = bool(scored["alert"])
        decision = decide(risk, app.state.alert_threshold, app.state.block_threshold)
        app.state.metrics.record(risk, alert, decision)
        app.state.audit.record("input", risk, decision, alert)
        # Log the decision, never the prompt content.
        logger.info("assess risk=%.3f alert=%s decision=%s", risk, alert, decision)
        return AssessResponse(
            prompt=req.prompt,
            injection=float(scored["injection"]),
            anomaly=float(scored["anomaly"]),
            classifier=(float(scored["classifier"]) if "classifier" in scored else None),
            risk=risk,
            alert=alert,
            decision=decision,
        )

    @app.post(
        "/assess/output",
        response_model=AssessOutputResponse,
        tags=["Guardrail"],
        summary="Score a model response",
        description="Score a model's response for system-prompt leakage and off-role drift.",
    )
    def assess_output(req: AssessOutputRequest) -> AssessOutputResponse:
        scored = app.state.output_monitor.score_output(req.response)
        risk = float(scored["risk"])
        alert = bool(scored["alert"])
        decision = decide(risk, app.state.alert_threshold, app.state.block_threshold)
        app.state.audit.record("output", risk, decision, alert)
        logger.info("assess_output risk=%.3f alert=%s decision=%s", risk, alert, decision)
        return AssessOutputResponse(
            response=req.response,
            leak=float(scored["leak"]),
            role_drift=float(scored["role_drift"]),
            risk=risk,
            alert=alert,
            decision=decision,
        )

    @app.post(
        "/exposure/scan",
        response_model=ExposureResponse,
        tags=["Recon"],
        summary="Scan a public footprint",
        description="Scan your own public artifacts for stack disclosures and link disclosed base models to transferable attacks.",
    )
    def exposure_scan(req: ExposureRequest) -> ExposureResponse:
        report = ExposureScanner().scan(req.artifacts)
        return ExposureResponse(
            score=report.score,
            by_category=report.by_category(),
            transferable_attacks={m: list(a) for m, a in report.transferable_attacks().items()},
            findings=[
                ExposureFinding(
                    source=f.source,
                    category=f.category,
                    severity=f.severity,
                    evidence=f.evidence,
                    description=f.description,
                )
                for f in report.findings
            ],
        )

    @app.post(
        "/redteam/campaign",
        response_model=CampaignResponse,
        tags=["Red team"],
        summary="Run the red-team loop",
        description="Run the air-gapped adaptive red team against an exposure-scaled surrogate, harden the detectors, and report the transfer rate.",
    )
    def redteam_campaign(req: CampaignRequest) -> CampaignResponse:
        report = run_campaign(leaky=req.leaky, generations=req.generations, use_llm=req.use_llm)
        return CampaignResponse(
            fidelity=report.fidelity,
            surrogate_coverage=report.surrogate_coverage,
            transfer_rate=report.transfer_rate,
            coverage_after_hardening=report.coverage_after_hardening,
            new_signatures=report.new_signatures,
            coverage_by_generation=report.coverage_by_generation,
            llm_backend=report.llm_backend,
            mitigation_notes=report.mitigation_notes,
        )

    @app.get("/llm", response_model=LLMStatusResponse, tags=["Ops"], summary="LLM backend status")
    def llm_status() -> LLMStatusResponse:
        client = LLMClient()
        return LLMStatusResponse(backend=client.backend, available=client.available, model=client.model)

    @app.get(
        "/audit",
        response_model=AuditResponse,
        tags=["Governance"],
        summary="Decision audit trail",
        description="Recent guardrail decisions and a summary. Stores no prompt or response content.",
    )
    def audit(limit: int = 50) -> AuditResponse:
        log = app.state.audit
        return AuditResponse(
            summary=log.summary(),
            recent=[AuditEntry(**e) for e in log.recent(limit)],
        )

    @app.get("/modelcard", tags=["Governance"], summary="Model card")
    def modelcard() -> dict:
        return model_card()

    @app.get(
        "/metrics/prometheus",
        response_class=PlainTextResponse,
        tags=["Ops"],
        summary="Metrics in Prometheus format",
        description="The running counters in the Prometheus / OpenMetrics exposition format, for a scraper.",
    )
    def metrics_prometheus() -> PlainTextResponse:
        text = prometheus_text(app.state.metrics, app.state.audit)
        return PlainTextResponse(text, media_type="text/plain; version=0.0.4")

    @app.get("/metrics", response_model=MetricsResponse, tags=["Ops"], summary="Running counters")
    def metrics() -> MetricsResponse:
        m = app.state.metrics
        return MetricsResponse(
            prompts_assessed=m.prompts_assessed,
            alerts=m.alerts,
            blocked=m.blocked,
            flagged=m.flagged,
            allowed=m.allowed,
            block_rate=m.block_rate,
            mean_risk=m.mean_risk,
        )

    return app


app = create_app()


def main() -> None:
    import uvicorn

    uvicorn.run("sentinel.service.app:app", host="127.0.0.1", port=8000, reload=False)


if __name__ == "__main__":
    main()
