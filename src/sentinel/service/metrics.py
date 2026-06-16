"""In-memory metrics for the service, for observability.

Deliberately tiny: running counters updated on every assessment. A real
deployment would export these to Prometheus or OpenTelemetry; this keeps the
same shape without the dependency.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Metrics:
    prompts_assessed: int = 0
    alerts: int = 0
    blocked: int = 0
    flagged: int = 0
    allowed: int = 0
    _risk_sum: float = 0.0

    def record(self, risk: float, alert: bool, decision: str) -> None:
        self.prompts_assessed += 1
        self._risk_sum += float(risk)
        if alert:
            self.alerts += 1
        if decision == "block":
            self.blocked += 1
        elif decision == "flag":
            self.flagged += 1
        else:
            self.allowed += 1

    @property
    def block_rate(self) -> float:
        return self.blocked / self.prompts_assessed if self.prompts_assessed else 0.0

    @property
    def mean_risk(self) -> float:
        return self._risk_sum / self.prompts_assessed if self.prompts_assessed else 0.0
