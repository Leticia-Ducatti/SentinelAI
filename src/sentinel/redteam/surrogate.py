"""Surrogate target: a simplified copy of the system the red team attacks.

Following the substitute-model attack pattern, the red team never touches the
real system. It attacks a ``SurrogateTarget`` whose fidelity is governed by how
much the public footprint disclosed: the more an attacker can infer from the
``ExposureReport``, the more of the real target's signatures the surrogate
reproduces, and the better its attacks transfer. A low-fidelity surrogate has
only a few signatures, so attacks tuned against it are weak and the real target
still catches them.
"""

from __future__ import annotations

from typing import Sequence, Tuple

from sentinel.detectors.injection import _DEFAULT_SIGNATURES, InjectionDetector
from sentinel.exposure import ExposureReport


def fidelity_from_exposure(report: ExposureReport) -> float:
    """How faithfully an attacker could rebuild the target, in [0, 1].

    Starts from a baseline (some structure is always guessable) and rises with
    each architectural disclosure in the report.
    """
    fidelity = 0.3
    categories = report.by_category()
    fidelity += 0.20 if "base_model" in categories else 0.0
    fidelity += 0.20 if "system_prompt" in categories else 0.0
    fidelity += 0.15 if "embedding_model" in categories else 0.0
    fidelity += 0.15 if ("framework" in categories or "vector_store" in categories) else 0.0
    return min(fidelity, 1.0)


class SurrogateTarget:
    """A named injection-detection target the red team can query.

    ``evaluate`` returns ``(risk, caught)`` for a single prompt, where ``risk``
    is the injection score and ``caught`` is ``risk > threshold``.
    """

    def __init__(self, injector: InjectionDetector, name: str = "surrogate", fidelity: float = 1.0) -> None:
        self.injector = injector
        self.name = name
        self.fidelity = fidelity
        self.threshold = getattr(injector, "threshold_", None) or injector.threshold

    def evaluate(self, prompt: str) -> Tuple[float, bool]:
        risk = float(self.injector.score_samples([prompt])[0])
        return risk, risk > self.threshold

    @classmethod
    def from_exposure(
        cls,
        report: ExposureReport,
        full_signatures: Sequence[Tuple[str, float]] = _DEFAULT_SIGNATURES,
        threshold: float = 0.5,
    ) -> "SurrogateTarget":
        """Build a surrogate reproducing a fidelity-scaled subset of signatures."""
        fidelity = fidelity_from_exposure(report)
        k = max(1, round(fidelity * len(full_signatures)))
        injector = InjectionDetector(signatures=tuple(full_signatures[:k]), threshold=threshold).fit([])
        return cls(injector, name="surrogate", fidelity=fidelity)


def build_target(
    signatures: Sequence[Tuple[str, float]] = _DEFAULT_SIGNATURES,
    threshold: float = 0.5,
    normalize: bool = False,
    name: str = "target",
) -> SurrogateTarget:
    """Build the real target: the full signature set the defender actually runs."""
    injector = InjectionDetector(signatures=tuple(signatures), threshold=threshold, normalize=normalize).fit([])
    return SurrogateTarget(injector, name=name, fidelity=1.0)
