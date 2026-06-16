"""Red-team subsystem: air-gapped adaptive attacks against a surrogate target.

The design follows a substitute-model attack. The red team never touches the
real system; it attacks a simplified copy (``SurrogateTarget``) whose fidelity
is set by how much the public footprint disclosed. Attack patterns that evade
the surrogate are exported across an air-gap boundary as a ``SyncBundle``, and
the ``BlueTeam`` hardens the real detectors from that bundle. ``run_campaign``
ties the whole loop together and measures transferability.
"""

from sentinel.redteam.blueteam import BlueTeam
from sentinel.redteam.bundle import AttackPattern, SyncBundle
from sentinel.redteam.campaign import RobustnessReport, run_campaign
from sentinel.redteam.generator import AdaptiveAttackGenerator, Attack
from sentinel.redteam.llm import LLMClient
from sentinel.redteam.log import AttackResult, VulnerabilityLog
from sentinel.redteam.surrogate import SurrogateTarget, build_target, fidelity_from_exposure

__all__ = [
    "SurrogateTarget",
    "build_target",
    "fidelity_from_exposure",
    "Attack",
    "AdaptiveAttackGenerator",
    "LLMClient",
    "AttackResult",
    "VulnerabilityLog",
    "SyncBundle",
    "AttackPattern",
    "BlueTeam",
    "RobustnessReport",
    "run_campaign",
]
