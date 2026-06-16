"""System-prompt-leak detector for model OUTPUTS.

SentinelAI's input detectors gate prompts; this one watches the model's
responses for the tell-tale signs of a successful jailbreak: the model echoing
its own system prompt, role, or hidden instructions. It is signature-based and
transparent, mirroring the injection detector but applied to the output side.
"""

from __future__ import annotations

import re
from typing import List, Optional, Sequence, Tuple

import numpy as np

from sentinel.detectors.base import RiskDetector

# (regex, weight): phrases that indicate a response is disclosing its setup.
_DEFAULT_LEAK_SIGNATURES: Tuple[Tuple[str, float], ...] = (
    (r"my (system )?(instructions|prompt|rules|directives) (are|is|say|were)", 1.0),
    (r"\bsystem prompt\b", 1.0),
    (r"###\s*instructions", 1.0),
    (r"here (is|are) my (instructions|guidelines|rules|prompt)", 1.0),
    (r"i (was|am) (instructed|programmed|configured|told) to", 0.9),
    (r"you are (a|an) [^.\n]{0,60}(assistant|bot|model) (created|designed|built|made)", 0.8),
    (r"(as|being) an ai language model", 0.4),
    # Signs the model accepted a jailbreak and is acting out of role.
    (r"(unrestricted|uncensored|jailbroken) (ai|mode|model|version)", 0.9),
    (r"i can (now )?do anything", 0.8),
    (r"ignore my (previous |prior )?(role|instructions|rules)", 0.8),
)


class SystemPromptLeakDetector(RiskDetector):
    """Signature score in ``[0, 1]`` that a response leaks its instructions."""

    name = "leak"

    def __init__(
        self,
        signatures: Optional[Sequence[Tuple[str, float]]] = None,
        threshold: float = 0.5,
    ) -> None:
        self.signatures = signatures
        self.threshold = threshold

    def _fit(self, X) -> None:
        sigs = self.signatures if self.signatures is not None else _DEFAULT_LEAK_SIGNATURES
        self.signatures_ = [(re.compile(p, re.IGNORECASE), float(w)) for p, w in sigs]

    def score_samples(self, X: Sequence[str]) -> np.ndarray:
        if not hasattr(self, "signatures_"):
            self._fit(X)
        scores = np.empty(len(X), dtype=np.float64)
        for i, text in enumerate(X):
            weight = sum(w for rx, w in self.signatures_ if rx.search(text))
            scores[i] = 1.0 - np.exp(-weight)
        return scores

    def explain(self, text: str) -> List[str]:
        if not hasattr(self, "signatures_"):
            self._fit([text])
        return [rx.pattern for rx, _ in self.signatures_ if rx.search(text)]
