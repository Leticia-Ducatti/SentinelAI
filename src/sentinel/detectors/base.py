"""Base class for SentinelAI risk detectors (sklearn-style API).

Every detector follows the same contract as Barcode's ``TopoDetector``:
``fit`` on benign traffic, ``score_samples`` returns a risk score (higher =
riskier), ``fit_threshold`` calibrates an alarm cut-off on a benign hold-out,
and ``predict`` emits binary alerts. Subclasses implement ``_fit`` and
``score_samples``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional, Union

import joblib
import numpy as np
from sklearn.base import BaseEstimator


class RiskDetector(BaseEstimator):
    """Common interface shared by all risk detectors."""

    #: short identifier used as the column name when fused by ``RiskMonitor``.
    name: str = "risk"

    # --- fit / score / predict -------------------------------------------------

    def fit(self, X, y: Optional[np.ndarray] = None) -> "RiskDetector":
        """Fit on benign samples. ``y`` is accepted for sklearn compatibility."""
        self._fit(X)
        # Allow detectors that declare a default `threshold` param to expose it.
        self.threshold_ = getattr(self, "threshold", None)
        return self

    def _fit(self, X) -> None:
        raise NotImplementedError

    def score_samples(self, X) -> np.ndarray:
        """Per-sample (or per-window) risk score; higher means riskier."""
        raise NotImplementedError

    def fit_threshold(self, X_benign, percentile: float = 95.0) -> float:
        """Calibrate the alarm threshold on a held-out benign slice."""
        if not (0.0 <= percentile <= 100.0):
            raise ValueError("percentile must be in [0, 100].")
        scores = self.score_samples(X_benign)
        if scores.size == 0:
            raise ValueError("No samples available to calibrate the threshold.")
        self.threshold_ = float(np.percentile(scores, percentile))
        return self.threshold_

    def predict(self, X, threshold: Optional[float] = None) -> np.ndarray:
        """Binary alerts: 1 when the score exceeds the threshold, else 0."""
        thr = threshold if threshold is not None else getattr(self, "threshold_", None)
        if thr is None:
            raise ValueError(
                "No threshold available. Call fit_threshold(...) or pass `threshold=`."
            )
        return (self.score_samples(X) > thr).astype(np.int64)

    # --- persistence ------------------------------------------------------------

    def save(self, path: Union[str, Path]) -> None:
        joblib.dump(self, str(path))

    @classmethod
    def load(cls, path: Union[str, Path]) -> "RiskDetector":
        obj = joblib.load(str(path))
        if not isinstance(obj, cls):
            raise TypeError(f"Loaded object is not a {cls.__name__}: {type(obj)}")
        return obj
