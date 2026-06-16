# Governance

How SentinelAI's controls map to common AI-governance expectations. This is an
illustrative mapping for a portfolio project, not legal advice.

## Audit trail

Every guardrail decision is recorded by `AuditLog` and exposed at `GET /audit`.
Each entry has a timestamp, the stage (`input` or `output`), the risk score, the
decision, and the alert flag. It deliberately stores **no prompt or response
content**, so the trail is safe to retain and inspect under data-protection rules.

## Model card

`GET /modelcard` (and `docs/model_card.md`) document intended use, detectors,
evaluation metrics, and limitations, so a reviewer can see what the system does
and where it is weak before relying on it.

## EU AI Act alignment (illustrative)

The AI Act asks providers of higher-risk AI systems for, among other things,
risk management, logging/traceability, transparency, human oversight, and
robustness testing. SentinelAI demonstrates a slice of each:

| AI Act theme | SentinelAI control |
|--------------|--------------------|
| Risk management | Continuous risk scoring with allow / flag / block decisions |
| Logging & traceability | Content-free audit log (`/audit`) of every decision |
| Transparency | Model card (`/modelcard`), interpretable signature detectors |
| Human oversight | `flag` decision routes borderline cases to a human instead of auto-blocking |
| Accuracy & robustness | Real-data benchmark (`sentinel-benchmark`) and the red-team robustness loop |
| Cybersecurity | Detection of prompt injection, jailbreaks, and output leakage |

## Observability

`GET /metrics/prometheus` exposes the counters in Prometheus / OpenMetrics
format for a scraper. With the `[otel]` extra installed and
`OTEL_EXPORTER_OTLP_ENDPOINT` set, the service also pushes the same metrics over
OpenTelemetry OTLP, so they land in any OTel-compatible backend.

## Roadmap

- Per-tenant audit logs and retention policies.
- Signed model cards versioned alongside detector changes.
- Exporting the audit trail (not just metrics) to a SIEM.
