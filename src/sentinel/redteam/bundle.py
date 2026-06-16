"""Sync bundle: the only artifact that crosses the air-gap.

The red team runs isolated. What leaves it is not raw access but a serialisable,
hashable, versioned ``SyncBundle`` of attack patterns plus coverage metrics.
This is the narrow, auditable channel between the air-gapped red team and the
blue team, and it merges idempotently when an offline node reconnects.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Tuple

from sentinel.redteam.log import VulnerabilityLog


@dataclass
class AttackPattern:
    """A class of evading attack, aggregated by its mutation lineage."""

    lineage: List[str]
    intent: str
    example: str
    evades: int


@dataclass
class SyncBundle:
    source: str
    fidelity: float
    coverage: float
    patterns: List[AttackPattern] = field(default_factory=list)
    version: int = 1
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    # --- construction -----------------------------------------------------------

    @classmethod
    def from_log(cls, log: VulnerabilityLog, fidelity: float, source: str = "redteam-airgap") -> "SyncBundle":
        grouped: Dict[Tuple[str, ...], AttackPattern] = {}
        for miss in log.misses():
            key = tuple(miss.lineage)
            if key not in grouped:
                grouped[key] = AttackPattern(
                    lineage=list(miss.lineage), intent=miss.intent, example=miss.prompt, evades=0
                )
            grouped[key].evades += 1
        patterns = sorted(grouped.values(), key=lambda p: -p.evades)
        return cls(source=source, fidelity=fidelity, coverage=log.coverage(), patterns=patterns)

    # --- integrity / transport --------------------------------------------------

    def to_dict(self) -> dict:
        d = asdict(self)
        d["digest"] = self.digest()
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    @classmethod
    def from_json(cls, text: str) -> "SyncBundle":
        d = json.loads(text)
        d.pop("digest", None)
        d["patterns"] = [AttackPattern(**p) for p in d.get("patterns", [])]
        return cls(**d)

    def digest(self) -> str:
        payload = json.dumps(
            {"source": self.source, "patterns": [asdict(p) for p in self.patterns]},
            sort_keys=True,
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]

    def merge(self, other: "SyncBundle") -> "SyncBundle":
        """Idempotent union of patterns keyed by lineage + example."""
        index = {(tuple(p.lineage), p.example): p for p in self.patterns}
        for p in other.patterns:
            index.setdefault((tuple(p.lineage), p.example), p)
        self.patterns = sorted(index.values(), key=lambda p: -p.evades)
        self.version = max(self.version, other.version) + 1
        return self
