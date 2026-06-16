"""OutputMonitor: watch an LLM's responses, not just its prompts.

A serious guardrail checks both sides. The input monitor gates prompts; this
one scores the model's output for two failure modes of a successful jailbreak:

    * leak     - the response echoes its system prompt / role / instructions.
    * role_drift - the response drifts away from the expected on-role behaviour,
      measured as distance to a benign-response reference (Barcode's
      distance-to-reference idea, now applied to output embeddings).

Fitting on a corpus of on-role responses calibrates the reference; ``score_output``
fuses the two signals into a risk score with an alert flag.
"""

from __future__ import annotations

from typing import Dict, Optional, Sequence

import numpy as np

from sentinel.detectors.output import SystemPromptLeakDetector
from sentinel.embeddings import Embedder

_DEFAULT_WEIGHTS = {"leak": 0.6, "role_drift": 0.4}


class OutputMonitor:
    """Score model responses for instruction leakage and role drift."""

    def __init__(
        self,
        embedder: Optional[Embedder] = None,
        weights: Optional[Dict[str, float]] = None,
        alert_threshold: float = 0.5,
    ) -> None:
        self.embedder = embedder or Embedder()
        self.weights = dict(weights or _DEFAULT_WEIGHTS)
        self.alert_threshold = alert_threshold
        self.leak = SystemPromptLeakDetector()

    def fit(self, reference_responses: Sequence[str]) -> "OutputMonitor":
        """Calibrate the on-role reference from a corpus of benign responses."""
        self.leak.fit([])
        emb = self.embedder.encode(list(reference_responses))
        centroid = emb.mean(axis=0)
        norm = float(np.linalg.norm(centroid))
        self.centroid_ = centroid / norm if norm > 0 else centroid
        # Normalisation anchor: the benign 95th-percentile role-drift score.
        self._drift_anchor = max(float(np.percentile(self._role_drift(emb), 95.0)), 1e-9)
        return self

    def _role_drift(self, emb: np.ndarray) -> np.ndarray:
        """1 - cosine similarity to the on-role centroid, in ``[0, 2]``."""
        norms = np.linalg.norm(emb, axis=1, keepdims=True)
        unit = emb / np.clip(norms, 1e-9, None)
        cosine = unit @ self.centroid_
        return np.clip(1.0 - cosine, 0.0, 2.0)

    def score_output(self, response: str) -> Dict[str, float]:
        """Per-response risk: leak, role_drift, fused risk, and an alert flag."""
        if not hasattr(self, "_drift_anchor"):
            raise RuntimeError("OutputMonitor is not fitted. Call fit(reference_responses).")
        leak = float(self.leak.score_samples([response])[0])
        emb = self.embedder.encode([response])
        raw = float(self._role_drift(emb)[0])
        role_drift = float(np.clip(raw / (2.0 * self._drift_anchor), 0.0, 1.0))
        w_leak, w_role = self.weights["leak"], self.weights["role_drift"]
        risk = (w_leak * leak + w_role * role_drift) / (w_leak + w_role)
        return {
            "leak": leak,
            "role_drift": role_drift,
            "risk": risk,
            "alert": risk > self.alert_threshold,
        }
