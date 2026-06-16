"""Prompt-anomaly detector: Isolation Forest over prompt embeddings.

Trained on benign prompts only, it flags individual prompts whose embedding
sits in a sparse region of the benign manifold: out-of-distribution inputs,
oddly long or templated payloads, encoded text, etc. This is the same
unsupervised-baseline tool used in Barcode, here applied to embeddings.
"""

from __future__ import annotations

from typing import Union

import numpy as np
from sklearn.ensemble import IsolationForest

from sentinel.detectors.base import RiskDetector


class PromptAnomalyDetector(RiskDetector):
    """Per-prompt anomaly score from an Isolation Forest on embeddings."""

    name = "anomaly"

    def __init__(
        self,
        n_estimators: int = 200,
        contamination: Union[str, float] = "auto",
        threshold: float = None,
        random_state: int = 0,
    ) -> None:
        self.n_estimators = n_estimators
        self.contamination = contamination
        self.threshold = threshold
        self.random_state = random_state

    def _fit(self, X: np.ndarray) -> None:
        X = np.asarray(X, dtype=np.float64)
        self.model_ = IsolationForest(
            n_estimators=self.n_estimators,
            contamination=self.contamination,
            random_state=self.random_state,
        ).fit(X)

    def score_samples(self, X: np.ndarray) -> np.ndarray:
        if not hasattr(self, "model_"):
            raise RuntimeError("PromptAnomalyDetector is not fitted. Call fit() first.")
        # sklearn's score_samples: higher = more normal. Negate so higher = riskier.
        return -self.model_.score_samples(np.asarray(X, dtype=np.float64))
