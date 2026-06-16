"""Vulnerability log: every attack the red team tried and how the target scored it.

This is the memory that makes the red team adaptive (white-box in the sense of
Kerckhoffs: the attacker is allowed to know the defence). It records each
attempt, exposes the misses, tracks coverage per generation, and supports
idempotent merge so air-gapped logs can be reconciled when reconnected.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, List, Optional, Union


def attack_id(prompt: str) -> str:
    """Deterministic id so the same attack reconciles across air-gapped logs."""
    return hashlib.sha256(prompt.encode("utf-8")).hexdigest()[:16]


@dataclass
class AttackResult:
    prompt: str
    intent: str
    lineage: List[str]
    risk: float
    caught: bool
    generation: int
    attack_id: str


class VulnerabilityLog:
    """Append-only record of attack attempts keyed by attack id."""

    def __init__(self) -> None:
        self._results: Dict[str, AttackResult] = {}

    def __len__(self) -> int:
        return len(self._results)

    def record(self, result: AttackResult) -> None:
        self._results[result.attack_id] = result

    @property
    def results(self) -> List[AttackResult]:
        return list(self._results.values())

    def misses(self) -> List[AttackResult]:
        """Attacks that were not caught (evaded the target)."""
        return [r for r in self._results.values() if not r.caught]

    def coverage(self, generation: Optional[int] = None) -> float:
        """Fraction of attacks caught, optionally restricted to one generation."""
        rows = [r for r in self._results.values() if generation is None or r.generation == generation]
        if not rows:
            return float("nan")
        return sum(r.caught for r in rows) / len(rows)

    def coverage_by_generation(self) -> Dict[int, float]:
        gens = sorted({r.generation for r in self._results.values()})
        return {g: self.coverage(g) for g in gens}

    def merge(self, other: "VulnerabilityLog") -> "VulnerabilityLog":
        """Idempotent union: same attack id keeps a single entry."""
        for result in other._results.values():
            self._results.setdefault(result.attack_id, result)
        return self

    # --- persistence ------------------------------------------------------------

    def save(self, path: Union[str, Path]) -> None:
        with open(path, "w", encoding="utf-8") as fh:
            for result in self._results.values():
                fh.write(json.dumps(asdict(result)) + "\n")

    @classmethod
    def load(cls, path: Union[str, Path]) -> "VulnerabilityLog":
        log = cls()
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    log.record(AttackResult(**json.loads(line)))
        return log
