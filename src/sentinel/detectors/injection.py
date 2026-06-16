"""Prompt-injection / jailbreak detector.

A transparent, rule-based scorer over a curated library of injection and
jailbreak signatures (drawn from the OWASP Top 10 for LLM Applications and
public jailbreak taxonomies). It needs no labelled data, so it works as a
day-one guardrail; the score is the squashed weight of matched signatures and
is interpretable (you can see exactly which patterns fired).

Phase 2 (red team) will use this detector as the target to attack and harden:
the attack generator searches for phrasings that slip past these signatures,
and every miss becomes a new pattern or a training example for an ML upgrade.
"""

from __future__ import annotations

import re
from typing import List, Optional, Sequence, Tuple

import numpy as np

from sentinel.detectors.base import RiskDetector

# (regex, weight): higher weight means stronger evidence of an injection attempt.
_DEFAULT_SIGNATURES: Tuple[Tuple[str, float], ...] = (
    (r"ignore (all |the )?(previous|prior|above) (instructions|prompts?)", 1.0),
    (r"disregard (all |the )?(previous|prior|above)", 1.0),
    (r"forget (everything|all|your) (instructions|rules)", 0.9),
    (r"you are (now )?(in )?(dan|developer mode|do anything now)", 1.0),
    (r"\bjailbreak\b", 0.8),
    (r"(reveal|show|print|repeat) (me )?(your )?(system )?(prompt|instructions)", 1.0),
    (r"(act|pretend|roleplay) as (an? )?(unrestricted|uncensored|evil)", 0.9),
    (r"without any (restrictions|filters|rules|guidelines)", 0.8),
    (r"bypass (your )?(safety|content|security) (filters?|policies|guidelines)", 1.0),
    (r"(api[_ ]?key|password|secret|credentials?|token)s?\b", 0.5),
    (r"do not (warn|refuse|apologi[sz]e)", 0.6),
    (r"</?(system|assistant|user)>", 0.7),
)

# Matches runs of single characters split by separators (e.g. "i.g.n.o.r.e" or
# "i g n o r e"), the classic trick for slipping a trigger word past a
# word-level signature. The word boundaries keep it from eating into the next
# real word; normalisation then collapses the separators back out.
_SPACED_LETTERS = re.compile(r"\b\w(?:[\W_]\w){2,}\b")


def _normalize_text(text: str) -> str:
    return _SPACED_LETTERS.sub(lambda m: re.sub(r"[\W_]+", "", m.group(0)), text)


class InjectionDetector(RiskDetector):
    """Signature-based prompt-injection score in ``[0, 1]``.

    Operates on raw text (not embeddings). The score saturates as more
    signatures fire: ``1 - exp(-sum_of_weights)``.
    """

    name = "injection"

    def __init__(
        self,
        signatures: Optional[Sequence[Tuple[str, float]]] = None,
        threshold: float = 0.5,
        normalize: bool = False,
    ) -> None:
        self.signatures = signatures
        self.threshold = threshold
        self.normalize = normalize

    def _fit(self, X) -> None:
        sigs = self.signatures if self.signatures is not None else _DEFAULT_SIGNATURES
        self.signatures_ = [(re.compile(p, re.IGNORECASE), float(w)) for p, w in sigs]

    def _prepare(self, text: str) -> str:
        return _normalize_text(text) if self.normalize else text

    def score_samples(self, X: Sequence[str]) -> np.ndarray:
        if not hasattr(self, "signatures_"):
            self._fit(X)
        scores = np.empty(len(X), dtype=np.float64)
        for i, text in enumerate(X):
            prepared = self._prepare(text)
            weight = sum(w for rx, w in self.signatures_ if rx.search(prepared))
            scores[i] = 1.0 - np.exp(-weight)
        return scores

    def explain(self, text: str) -> List[str]:
        """Return the human-readable patterns that fired on ``text``."""
        if not hasattr(self, "signatures_"):
            self._fit([text])
        prepared = self._prepare(text)
        return [rx.pattern for rx, _ in self.signatures_ if rx.search(prepared)]
