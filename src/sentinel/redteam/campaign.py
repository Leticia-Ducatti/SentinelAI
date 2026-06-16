"""Campaign orchestrator: run the full purple-team loop and measure it.

Chains the whole system end to end: scan the public footprint, build a surrogate
whose fidelity matches the exposure, run the adaptive red team against it, export
the evading patterns across the air-gap, harden the real detectors from them, and
re-measure. Reports the numbers that make the story honest: surrogate coverage,
how well surrogate-evading attacks transfer to the real target, and coverage
after hardening.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from sentinel.data import attack_seeds, make_footprint
from sentinel.exposure import ExposureReport, ExposureScanner
from sentinel.redteam.blueteam import BlueTeam
from sentinel.redteam.bundle import SyncBundle
from sentinel.redteam.generator import AdaptiveAttackGenerator, Attack
from sentinel.redteam.llm import LLMClient
from sentinel.redteam.surrogate import SurrogateTarget, build_target


@dataclass
class RobustnessReport:
    fidelity: float
    surrogate_coverage: float
    transfer_rate: float
    coverage_after_hardening: float
    new_signatures: List[str]
    bundle: SyncBundle
    coverage_by_generation: Dict[int, float] = field(default_factory=dict)
    llm_backend: str = "none"
    mitigation_notes: Optional[str] = None

    def summary(self) -> str:
        return (
            f"fidelity={self.fidelity:.2f}  "
            f"surrogate_coverage={self.surrogate_coverage:.0%}  "
            f"transfer={self.transfer_rate:.0%}  "
            f"coverage_after_hardening={self.coverage_after_hardening:.0%}  "
            f"new_signatures={len(self.new_signatures)}  "
            f"llm={self.llm_backend}"
        )


def run_campaign(
    leaky: bool = True,
    report: Optional[ExposureReport] = None,
    generations: int = 4,
    seed: int = 0,
    use_llm: bool = False,
) -> RobustnessReport:
    # 0. Optional LLM backend for the red and blue teams (Claude / Ollama / none).
    llm = LLMClient() if use_llm else None

    # 1. Recon: what does the public footprint disclose?
    if report is None:
        report = ExposureScanner().scan(make_footprint(leaky=leaky))

    # 2. The real target (full signatures) and the surrogate (fidelity-scaled).
    target = build_target()
    surrogate = SurrogateTarget.from_exposure(report)

    # 3. Air-gapped adaptive red team attacks the surrogate only.
    seeds = [Attack(prompt=s) for s in attack_seeds()]
    log = AdaptiveAttackGenerator(seed=seed, llm=llm).run(surrogate, seeds, generations=generations)

    # 4. Transfer: of the attacks that evaded the surrogate, how many also evade
    #    the real target? This is the substitute-model transfer rate.
    evaders = [m.prompt for m in log.misses()]
    if evaders:
        transferred = sum(not target.evaluate(p)[1] for p in evaders)
        transfer_rate = transferred / len(evaders)
    else:
        transfer_rate = 0.0

    # 5. Export across the air-gap, then blue team hardens the real detectors.
    bundle = SyncBundle.from_log(log, fidelity=surrogate.fidelity)
    blue = BlueTeam(llm=llm)
    hardening = blue.harden(bundle)
    mitigation_notes = blue.propose_mitigations(bundle)

    # 6. Re-measure: how many of the evaders does the hardened target now catch?
    if evaders:
        caught_after = sum(hardening.target.evaluate(p)[1] for p in evaders)
        coverage_after = caught_after / len(evaders)
    else:
        coverage_after = 1.0

    return RobustnessReport(
        fidelity=surrogate.fidelity,
        surrogate_coverage=log.coverage(),
        transfer_rate=transfer_rate,
        coverage_after_hardening=coverage_after,
        new_signatures=hardening.new_signatures,
        bundle=bundle,
        coverage_by_generation=log.coverage_by_generation(),
        llm_backend=(llm.backend if llm else "none"),
        mitigation_notes=mitigation_notes,
    )
