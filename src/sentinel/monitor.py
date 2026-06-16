"""RiskMonitor: fuse the detectors into a single risk score with alerts.

This is the heart of SentinelAI: it embeds incoming prompts once, runs every
detector, normalises each signal against its benign-calibrated threshold, and
combines them into a weighted risk score in ``[0, 1]``. Anything above
``alert_threshold`` is surfaced as an alert. Batch-level embedding drift is
reported alongside the per-prompt table.
"""

from __future__ import annotations

from typing import Dict, Optional, Sequence

import numpy as np
import pandas as pd

from sentinel.detectors import (
    EmbeddingDriftDetector,
    InjectionDetector,
    PromptAnomalyDetector,
)
from sentinel.embeddings import Embedder

_DEFAULT_WEIGHTS = {"injection": 0.4, "anomaly": 0.35, "drift": 0.25, "classifier": 0.7}


class RiskMonitor:
    """Orchestrate detectors over a stream of prompts.

    Parameters
    ----------
    embedder : Embedder, optional
        Shared text encoder (auto-selects backend if omitted).
    weights : dict, optional
        Relative weight of each component in the fused risk score.
    alert_threshold : float
        Fused-risk cut-off above which a prompt is flagged as an alert.
    """

    def __init__(
        self,
        embedder: Optional[Embedder] = None,
        weights: Optional[Dict[str, float]] = None,
        alert_threshold: float = 0.5,
        classifier=None,
    ) -> None:
        self.embedder = embedder or Embedder()
        self.weights = dict(weights or _DEFAULT_WEIGHTS)
        self.alert_threshold = alert_threshold
        self.anomaly = PromptAnomalyDetector()
        self.drift = EmbeddingDriftDetector()
        self.injection = InjectionDetector()
        # Optional supervised detector; used in score_prompt when present.
        self.classifier = classifier

    # --- fit --------------------------------------------------------------------

    def fit(self, benign_prompts: Sequence[str]) -> "RiskMonitor":
        """Calibrate every detector on a corpus of known-benign prompts."""
        emb = self.embedder.encode(benign_prompts)
        self.anomaly.fit(emb)
        self.drift.fit(emb)
        self.injection.fit(benign_prompts)
        # Normalisation anchors: the benign 95th-percentile score per detector.
        self._anomaly_anchor = self.anomaly.fit_threshold(emb, percentile=95.0)
        self._drift_anchor = max(self.drift.fit_threshold(emb, percentile=95.0), 1e-9)
        return self

    # --- assess -----------------------------------------------------------------

    def assess(self, prompts: Sequence[str]) -> pd.DataFrame:
        """Score a batch of prompts; return a per-prompt risk table."""
        if not hasattr(self, "_anomaly_anchor"):
            raise RuntimeError("RiskMonitor is not fitted. Call fit(benign_prompts).")
        prompts = list(prompts)
        emb = self.embedder.encode(prompts)

        injection = self.injection.score_samples(prompts)
        anomaly = self._normalise(self.anomaly.score_samples(emb), self._anomaly_anchor)
        drift_batch = self._batch_drift(emb)

        risk = (
            self.weights["injection"] * injection
            + self.weights["anomaly"] * anomaly
            + self.weights["drift"] * drift_batch
        ) / sum(self.weights.values())

        return pd.DataFrame(
            {
                "prompt": prompts,
                "injection": injection,
                "anomaly": anomaly,
                "drift": drift_batch,
                "risk": risk,
                "alert": risk > self.alert_threshold,
            }
        )

    def score_prompt(self, prompt: str) -> Dict[str, float]:
        """Per-request risk for a single prompt (the inline-guardrail path).

        Uses only the genuinely per-sample detectors, injection and anomaly.
        Drift is a distributional signal that needs a window of traffic, so it
        is reported over batches via :meth:`assess`, not folded into a single
        request where it would saturate.
        """
        if not hasattr(self, "_anomaly_anchor"):
            raise RuntimeError("RiskMonitor is not fitted. Call fit(benign_prompts).")
        emb = self.embedder.encode([prompt])
        components = {
            "injection": float(self.injection.score_samples([prompt])[0]),
            "anomaly": float(self._normalise(self.anomaly.score_samples(emb), self._anomaly_anchor)[0]),
        }
        if self.classifier is not None:
            components["classifier"] = float(self.classifier.score_embeddings(emb)[0])
        total = sum(self.weights[k] for k in components)
        risk = sum(self.weights[k] * v for k, v in components.items()) / total
        return {**components, "risk": risk, "alert": risk > self.alert_threshold}

    # --- helpers ----------------------------------------------------------------

    def _batch_drift(self, emb: np.ndarray) -> float:
        """Single drift figure for the batch, normalised to ~[0, 1]."""
        scores = self.drift.score_samples(emb)
        return float(np.clip(scores.max() / self._drift_anchor, 0.0, 1.0))

    @staticmethod
    def _normalise(scores: np.ndarray, anchor: float) -> np.ndarray:
        """Map raw scores to ~[0, 1], where ``anchor`` lands at 0.5."""
        if anchor <= 0:
            anchor = 1e-9
        return np.clip(scores / (2.0 * anchor), 0.0, 1.0)
