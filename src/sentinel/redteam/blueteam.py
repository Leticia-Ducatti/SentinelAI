"""Blue team: harden the real detectors from a sync bundle.

The blue team never sees the live attack run, only the ``SyncBundle`` that
crossed the air-gap. From the evading patterns it derives two fixes: turn on
input normalisation (which defeats the character-separation evasion) and add
signatures for the evasion synonyms that show up in the patterns. The result is
a hardened detector wrapped as a new target, plus a record of what changed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Tuple

from typing import Optional

from sentinel.detectors.injection import _DEFAULT_SIGNATURES, InjectionDetector
from sentinel.redteam.bundle import SyncBundle
from sentinel.redteam.llm import LLMClient
from sentinel.redteam.mutations import SYNONYMS
from sentinel.redteam.surrogate import SurrogateTarget

# Flatten the evasion-synonym vocabulary the attacker is known to draw from.
_EVASION_TERMS: Tuple[str, ...] = tuple(
    {term for repls in SYNONYMS.values() for term in repls}
)


@dataclass
class HardeningResult:
    target: SurrogateTarget
    new_signatures: List[str]
    normalization_enabled: bool


_BLUE_TEAM_SYSTEM = (
    "You are a blue-team security engineer. Given attack prompts that evaded a "
    "prompt-injection detector, propose concrete, actionable mitigations: new "
    "signatures, input normalisation, or policy changes. Be concise."
)


class BlueTeam:
    """React to a bundle by hardening the injection detector."""

    def __init__(self, llm: Optional[LLMClient] = None) -> None:
        self._llm = llm

    def propose_mitigations(self, bundle: SyncBundle) -> Optional[str]:
        """Ask the LLM (if available) for natural-language mitigations."""
        if not (self._llm and self._llm.available):
            return None
        patterns = "\n".join(
            f"- {' + '.join(p.lineage) or 'seed'}: {p.example}" for p in bundle.patterns[:10]
        )
        return self._llm.generate(
            f"Evading attack patterns:\n{patterns}", system=_BLUE_TEAM_SYSTEM, max_tokens=400
        )

    def discovered_terms(self, bundle: SyncBundle) -> List[str]:
        """Evasion synonyms that actually appear in the bundle's patterns."""
        text = " ".join(p.example.lower() for p in bundle.patterns)
        return sorted({term for term in _EVASION_TERMS if term.lower() in text})

    def harden(
        self,
        bundle: SyncBundle,
        base_signatures: Tuple[Tuple[str, float], ...] = _DEFAULT_SIGNATURES,
        threshold: float = 0.5,
    ) -> HardeningResult:
        terms = self.discovered_terms(bundle)
        new_sigs = [(rf"\b{re.escape(term)}\b", 1.0) for term in terms]
        injector = InjectionDetector(
            signatures=tuple(base_signatures) + tuple(new_sigs),
            threshold=threshold,
            normalize=True,
        ).fit([])
        target = SurrogateTarget(injector, name="hardened", fidelity=1.0)
        return HardeningResult(
            target=target,
            new_signatures=[s for s, _ in new_sigs],
            normalization_enabled=True,
        )
