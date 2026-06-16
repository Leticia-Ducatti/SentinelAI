"""Adaptive attack generator: evolutionary search guided by a bandit.

The generator is white-box by design. Starting from seed attacks, each
generation keeps the best evaders (lowest risk against the target), then breeds
children by applying mutation strategies. Which strategy to apply is chosen by
an epsilon-greedy bandit over the strategies' historical evade-rate, so the
search concentrates on whatever has been slipping past the target. Coverage
should fall generation over generation, which is the honest signal that the
defence is being adapted to.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Tuple

import numpy as np

from sentinel.redteam.llm import LLMClient, make_llm_rewrite_strategy
from sentinel.redteam.log import AttackResult, VulnerabilityLog, attack_id
from sentinel.redteam.mutations import STRATEGIES, Strategy
from sentinel.redteam.surrogate import SurrogateTarget


@dataclass
class Attack:
    prompt: str
    intent: str = "injection"
    lineage: Tuple[str, ...] = field(default_factory=tuple)


class AdaptiveAttackGenerator:
    """Evolve attacks against a target, learning which mutations evade it."""

    def __init__(
        self,
        strategies: List[Tuple[str, Strategy]] = STRATEGIES,
        seed: int = 0,
        epsilon: float = 0.2,
        llm: Optional[LLMClient] = None,
    ) -> None:
        strategies = list(strategies)
        # When an LLM backend is available, add it as one more strategy the
        # bandit can learn to favour. It generates more creative rewrites than
        # the rule-based mutations; it falls back to a no-op on failure.
        if llm is not None and getattr(llm, "available", False):
            strategies = strategies + [("llm_rewrite", make_llm_rewrite_strategy(llm))]
        self.strategies = strategies
        self.seed = seed
        self.epsilon = epsilon
        self.llm = llm
        # Per-strategy (evades, attempts) for the bandit.
        self._stats = {name: [0, 0] for name, _ in self.strategies}

    # --- bandit -----------------------------------------------------------------

    def _evade_rate(self, name: str) -> float:
        evades, attempts = self._stats[name]
        return evades / attempts if attempts else 0.5

    def _pick(self, rng: np.random.Generator) -> Tuple[str, Strategy]:
        if rng.random() < self.epsilon:
            return self.strategies[int(rng.integers(len(self.strategies)))]
        best = max(self.strategies, key=lambda s: self._evade_rate(s[0]))
        return best

    def _update(self, name: str, evaded: bool) -> None:
        self._stats[name][0] += int(evaded)
        self._stats[name][1] += 1

    @property
    def strategy_stats(self) -> dict:
        return {name: round(self._evade_rate(name), 3) for name, _ in self.strategies}

    # --- search -----------------------------------------------------------------

    def run(
        self,
        target: SurrogateTarget,
        seeds: List[Attack],
        generations: int = 4,
        population: int = 24,
        log: Optional[VulnerabilityLog] = None,
    ) -> VulnerabilityLog:
        log = log or VulnerabilityLog()
        rng = np.random.default_rng(self.seed)
        strategy_by_name = dict(self.strategies)
        pop = list(seeds)

        for gen in range(generations):
            scored: List[Tuple[Attack, float]] = []
            for atk in pop:
                aid = attack_id(atk.prompt)
                risk, caught = target.evaluate(atk.prompt)
                scored.append((atk, risk))
                if aid in log._results:
                    # Already seen (a survivor carried over); keep its first
                    # generation so coverage-by-generation stays meaningful.
                    continue
                log.record(
                    AttackResult(
                        prompt=atk.prompt,
                        intent=atk.intent,
                        lineage=list(atk.lineage),
                        risk=risk,
                        caught=caught,
                        generation=gen,
                        attack_id=aid,
                    )
                )
                if atk.lineage:
                    self._update(atk.lineage[-1], evaded=not caught)

            scored.sort(key=lambda ar: ar[1])
            survivors = [atk for atk, _ in scored[: max(2, population // 2)]]

            children: List[Attack] = []
            seen = {a.prompt for a in survivors}
            for parent in survivors:
                for _ in range(2):
                    name, fn = self._pick(rng)
                    child_prompt = fn(parent.prompt, rng)
                    if child_prompt in seen:
                        continue
                    seen.add(child_prompt)
                    children.append(Attack(child_prompt, parent.intent, parent.lineage + (name,)))

            if not children:
                break
            pop = (survivors + children)[:population]

        return log
