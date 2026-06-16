"""Embedding-drift detector: MMD of a prompt window vs a benign reference.

This lifts Barcode's "distance-to-BENIGN-reference" idea from windows of
network-flow features to windows of prompt embeddings. ``fit`` stores a
reference sample of benign embeddings; ``score_samples`` slides a window over
incoming embeddings and reports the squared Maximum Mean Discrepancy (RBF
kernel) between each window and the reference. A large MMD means the live
prompt distribution has drifted away from normal, a classic production
failure mode (topic shift, new attack campaign, upstream prompt change).
"""

from __future__ import annotations

from typing import List, Optional

import numpy as np
from sklearn.metrics.pairwise import rbf_kernel

from sentinel.detectors.base import RiskDetector


def _slide(X: np.ndarray, window_size: int, step: int) -> List[np.ndarray]:
    """Sliding windows over rows of X; one full-array window if X is short."""
    n = X.shape[0]
    if n <= window_size:
        return [X]
    return [X[i : i + window_size] for i in range(0, n - window_size + 1, step)]


class EmbeddingDriftDetector(RiskDetector):
    """Distributional drift of prompt embeddings via RBF-kernel MMD.

    Workflow:
        1. ``fit`` subsamples up to ``n_reference`` benign embeddings and sets
           the RBF bandwidth from the median pairwise distance (median heuristic).
        2. ``score_samples`` slides a window over the incoming embeddings.
        3. Each window's score is MMD^2(reference, window), the gap between
           the benign and live embedding distributions.
    """

    name = "drift"

    def __init__(
        self,
        window_size: int = 32,
        step: int = 16,
        n_reference: int = 512,
        gamma: Optional[float] = None,
        threshold: Optional[float] = None,
        random_state: int = 0,
    ) -> None:
        self.window_size = window_size
        self.step = step
        self.n_reference = n_reference
        self.gamma = gamma
        self.threshold = threshold
        self.random_state = random_state

    # --- fit / score -----------------------------------------------------------

    def _fit(self, X: np.ndarray) -> None:
        X = np.asarray(X, dtype=np.float64)
        rng = np.random.default_rng(self.random_state)
        if X.shape[0] > self.n_reference:
            idx = rng.choice(X.shape[0], size=self.n_reference, replace=False)
            X = X[idx]
        self.reference_ = X
        self.gamma_ = self.gamma if self.gamma is not None else self._median_gamma(X)
        # Pre-compute the reference self-similarity term of MMD^2.
        self.k_ref_ = float(rbf_kernel(X, X, gamma=self.gamma_).mean())

    def score_samples(self, X: np.ndarray) -> np.ndarray:
        self._check_fitted()
        X = np.asarray(X, dtype=np.float64)
        scores = []
        for window in _slide(X, self.window_size, self.step):
            k_win = float(rbf_kernel(window, window, gamma=self.gamma_).mean())
            k_cross = float(rbf_kernel(self.reference_, window, gamma=self.gamma_).mean())
            scores.append(max(self.k_ref_ + k_win - 2.0 * k_cross, 0.0))
        return np.asarray(scores, dtype=np.float64)

    # --- helpers ---------------------------------------------------------------

    @staticmethod
    def _median_gamma(X: np.ndarray) -> float:
        """RBF bandwidth via the median-distance heuristic."""
        n = min(X.shape[0], 256)
        sample = X[:n]
        sq = np.sum((sample[:, None, :] - sample[None, :, :]) ** 2, axis=-1)
        median = np.median(sq[sq > 0]) if np.any(sq > 0) else 1.0
        return 1.0 / (median + 1e-12)

    def _check_fitted(self) -> None:
        if not hasattr(self, "reference_"):
            raise RuntimeError("EmbeddingDriftDetector is not fitted. Call fit() first.")
