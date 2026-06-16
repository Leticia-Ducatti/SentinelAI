"""Supervised injection classifier: a trained detector over embeddings.

The benchmark shows a logistic-regression classifier on embeddings is the
strongest detector (ROC-AUC 0.94 on the held-out deepset/prompt-injections test
split), well above the signature and unsupervised approaches. Unlike the other
detectors it is supervised: ``fit(texts, labels)`` needs labelled data. It is
trained once (``python -m sentinel.train``) and persisted; the monitor loads it
when the artifact is present and matches the embedding space.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional, Sequence, Union

import joblib
import numpy as np
from sklearn.linear_model import LogisticRegression

from sentinel.detectors.base import RiskDetector
from sentinel.embeddings import Embedder

DEFAULT_MODEL_PATH = "data/models/injection_clf.joblib"


class TrainedInjectionClassifier(RiskDetector):
    """Logistic regression over prompt embeddings; the supervised detector."""

    name = "classifier"

    def __init__(self, embedder: Optional[Embedder] = None, C: float = 1.0) -> None:
        self.embedder = embedder or Embedder()
        self.C = C

    def fit(self, X: Sequence[str], y) -> "TrainedInjectionClassifier":
        emb = self.embedder.encode(list(X))
        self.clf_ = LogisticRegression(max_iter=1000, class_weight="balanced", C=self.C).fit(
            emb, np.asarray(y)
        )
        self.dim_ = int(emb.shape[1])
        self.backend_ = self.embedder.backend
        self.threshold_ = 0.5
        return self

    def score_embeddings(self, emb: np.ndarray) -> np.ndarray:
        """Score pre-computed embeddings (lets the monitor embed once)."""
        return self.clf_.predict_proba(np.asarray(emb))[:, 1]

    def score_samples(self, X: Sequence[str]) -> np.ndarray:
        return self.score_embeddings(self.embedder.encode(list(X)))

    # --- persistence (store only the lightweight parts, not the embedder) -------

    def save(self, path: Union[str, Path] = DEFAULT_MODEL_PATH) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump({"clf": self.clf_, "dim": self.dim_, "backend": self.backend_}, str(path))

    @classmethod
    def load(
        cls, path: Union[str, Path] = DEFAULT_MODEL_PATH, embedder: Optional[Embedder] = None
    ) -> "TrainedInjectionClassifier":
        payload = joblib.load(str(path))
        obj = cls(embedder=embedder)
        obj.clf_ = payload["clf"]
        obj.dim_ = int(payload["dim"])
        obj.backend_ = payload["backend"]
        obj.threshold_ = 0.5
        return obj

    @classmethod
    def try_load(
        cls, embedder: Embedder, path: Union[str, Path] = DEFAULT_MODEL_PATH
    ) -> Optional["TrainedInjectionClassifier"]:
        """Load only if the artifact exists and matches the embedding space."""
        if not Path(path).exists():
            return None
        obj = cls.load(path, embedder=embedder)
        if obj.dim_ != getattr(embedder, "dim", None):
            return None  # trained in a different embedding space; do not use
        return obj
