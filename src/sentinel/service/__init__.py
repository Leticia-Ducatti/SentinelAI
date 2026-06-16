"""FastAPI service: SentinelAI as a guardrail in front of an LLM application.

The service holds a benign-calibrated ``RiskMonitor`` and exposes it over HTTP.
A caller posts a prompt to ``/assess`` and gets back a risk score, the
per-detector breakdown, and an allow/flag/block decision, so SentinelAI can sit
inline as middleware. The exposure scanner and red-team campaign are exposed as
their own endpoints, and ``/metrics`` reports running counters for observability.
"""

from sentinel.service.app import create_app

__all__ = ["create_app"]
