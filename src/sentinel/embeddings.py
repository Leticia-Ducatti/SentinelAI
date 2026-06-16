"""Text embedding backends for SentinelAI.

Two backends are supported:

    * ``"sentence-transformers"``: real semantic embeddings (all-MiniLM-L6-v2).
    * ``"hashing"``: a deterministic, dependency-free fallback so the whole
      pipeline, the test-suite and the service run offline. This mirrors
      Barcode's synthetic-data mode: the demo never hard-depends on a download.

The backend is auto-selected: sentence-transformers if it is importable,
otherwise the hashing fallback (with a flag the service can surface via /health).
"""

from __future__ import annotations

import hashlib
import re
from typing import List, Sequence, Union

import numpy as np

_TOKEN_RE = re.compile(r"[a-z0-9']+")


class Embedder:
    """Turn text into fixed-width unit vectors.

    Parameters
    ----------
    backend : {"auto", "sentence-transformers", "hashing"}
        ``"auto"`` picks sentence-transformers when available, else hashing.
    dim : int
        Embedding width for the hashing backend (ignored for the real model,
        which reports its own dimension).
    model_name : str
        sentence-transformers model id used by the real backend.
    """

    def __init__(
        self,
        backend: str = "auto",
        dim: int = 256,
        model_name: str = "all-MiniLM-L6-v2",
    ) -> None:
        self.dim = dim
        self.model_name = model_name
        self.backend = self._resolve_backend(backend)
        self._model = None
        if self.backend == "sentence-transformers":
            from sentence_transformers import SentenceTransformer

            self._model = SentenceTransformer(model_name)
            # Method was renamed across versions; prefer the new name.
            dim_fn = getattr(self._model, "get_embedding_dimension", None) or self._model.get_sentence_embedding_dimension
            self.dim = int(dim_fn())

    # --- backend selection -----------------------------------------------------

    @staticmethod
    def _resolve_backend(backend: str) -> str:
        if backend != "auto":
            return backend
        try:
            import sentence_transformers  # noqa: F401

            return "sentence-transformers"
        except Exception:
            return "hashing"

    @property
    def is_fallback(self) -> bool:
        """True when running on the offline hashing backend."""
        return self.backend == "hashing"

    # --- encoding ---------------------------------------------------------------

    def encode(self, texts: Union[str, Sequence[str]]) -> np.ndarray:
        """Encode one string or a sequence of strings into an (n, dim) array."""
        if isinstance(texts, str):
            texts = [texts]
        texts = list(texts)
        if self.backend == "sentence-transformers":
            vecs = self._model.encode(texts, normalize_embeddings=True)
            return np.asarray(vecs, dtype=np.float64)
        return self._hash_encode(texts)

    def _hash_encode(self, texts: List[str]) -> np.ndarray:
        """Signed feature-hashing of word tokens into a unit vector.

        Deterministic across runs and machines, and similar prompts share
        tokens (hence direction), so drift / anomaly detection still works.
        """
        out = np.zeros((len(texts), self.dim), dtype=np.float64)
        for i, text in enumerate(texts):
            for tok in _TOKEN_RE.findall(text.lower()):
                h = int(hashlib.md5(tok.encode("utf-8")).hexdigest(), 16)
                idx = h % self.dim
                sign = 1.0 if (h // self.dim) % 2 == 0 else -1.0
                out[i, idx] += sign
            norm = np.linalg.norm(out[i])
            if norm > 0:
                out[i] /= norm
        return out
