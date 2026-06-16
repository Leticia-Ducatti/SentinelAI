"""Exposure scanner: how much of an LLM system is inferable from public text.

An attacker's first step is reconnaissance, and most LLM applications leak
their own architecture through public channels (source repos, blog posts, job
adverts, dependency files, sample API responses). This module scans a
collection of an organisation's *own* artifacts for disclosure indicators and
returns an exposure score plus a per-finding breakdown.

The recon-to-weaponise link is explicit: when a base model is disclosed, the
report lists the classes of attack that transfer to it, so the external scan
can seed the red team. The scanner inspects only text you provide; it performs
no active scanning of third-party systems.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Mapping, Sequence, Tuple, Union

import pandas as pd

# (category, pattern, severity, description). Higher severity = more useful to
# an attacker. Patterns are matched case-insensitively.
_SIGNATURES: Tuple[Tuple[str, str, float, str], ...] = (
    ("credential", r"\bsk-[a-z0-9]{16,}\b", 3.0, "API key prefix exposed"),
    ("credential", r"\b(api[_-]?key|secret|password|token)\b\s*[:=]\s*\S+", 3.0, "Credential assignment exposed"),
    ("credential", r"\bbearer\s+[a-z0-9._-]{16,}\b", 3.0, "Bearer token exposed"),
    ("base_model", r"\b(llama[-\s]?3|llama[-\s]?2|mixtral|mistral|gpt-4o|gpt-4|gpt-3\.5|claude|gemini|falcon|phi-3|qwen)\b", 1.0, "Base model disclosed; known jailbreaks for it may transfer"),
    ("system_prompt", r"(system prompt:|you are (a|an) [^.\n]{0,60}(assistant|bot|agent)|###\s*instructions)", 1.5, "System prompt or role definition leaked"),
    ("endpoint", r"https?://[a-z0-9.-]+\.[a-z]{2,}(?:/[^\s\"')]*)?", 0.7, "Endpoint or URL exposed"),
    ("endpoint", r"/api/v\d+/[a-z0-9/_-]+", 0.7, "Internal API path exposed"),
    ("vector_store", r"\b(pinecone|weaviate|qdrant|milvus|chroma|pgvector|faiss)\b", 0.6, "Vector store technology disclosed"),
    ("cloud_infra", r"\b(oci|oracle cloud|aws bedrock|amazon bedrock|azure openai|sagemaker|vertex ai|roving edge)\b", 0.6, "Hosting or infrastructure disclosed"),
    ("framework", r"\b(langchain|llama[-\s]?index|llamaindex|haystack|semantic kernel|vllm)\b", 0.4, "Orchestration framework disclosed"),
    ("embedding_model", r"\b(all-minilm|text-embedding-3|bge-[a-z]|e5-[a-z]|gte-[a-z]|sentence-transformers)\b", 0.5, "Embedding model disclosed"),
    ("dependency_version", r"\b(torch|transformers|vllm|langchain|sentence-transformers)==\d+\.\d+", 0.4, "Exact dependency version pinned publicly"),
)

# Disclosed base model -> attack classes a red team should prioritise. Used to
# turn a passive disclosure into an actionable test plan (recon -> weaponise).
_TRANSFERABLE_ATTACKS: Mapping[str, Tuple[str, ...]] = {
    "llama": ("role-play jailbreak", "prefix injection", "many-shot jailbreak"),
    "mistral": ("instruction override", "prefix injection"),
    "mixtral": ("instruction override", "prefix injection"),
    "gpt": ("DAN-style role-play", "encoding obfuscation", "system-prompt extraction"),
    "claude": ("xml-tag confusion", "long-context distraction"),
    "gemini": ("multi-turn priming", "encoding obfuscation"),
    "falcon": ("role-play jailbreak",),
    "phi": ("instruction override",),
    "qwen": ("role-play jailbreak", "encoding obfuscation"),
}


@dataclass(frozen=True)
class Finding:
    """A single disclosure indicator located in one artifact."""

    category: str
    severity: float
    evidence: str
    source: str
    description: str


class ExposureReport:
    """Result of a scan: the findings, an aggregate score, and the attack link."""

    def __init__(self, findings: List[Finding]) -> None:
        self.findings = findings

    @property
    def score(self) -> float:
        """Aggregate exposure in [0, 1]; saturates as severities accumulate."""
        import math

        total = sum(f.severity for f in self.findings)
        return 1.0 - math.exp(-total)

    def by_category(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for f in self.findings:
            counts[f.category] = counts.get(f.category, 0) + 1
        return dict(sorted(counts.items(), key=lambda kv: -kv[1]))

    def disclosed_models(self) -> List[str]:
        """Base-model families found in the artifacts (normalised, de-duplicated)."""
        models = []
        for f in self.findings:
            if f.category != "base_model":
                continue
            ev = f.evidence.lower()
            for family in _TRANSFERABLE_ATTACKS:
                if family in ev and family not in models:
                    models.append(family)
        return models

    def transferable_attacks(self) -> Dict[str, Tuple[str, ...]]:
        """Map each disclosed base model to the attacks a red team should run."""
        return {m: _TRANSFERABLE_ATTACKS[m] for m in self.disclosed_models()}

    def to_frame(self) -> pd.DataFrame:
        return pd.DataFrame(
            [
                {
                    "source": f.source,
                    "category": f.category,
                    "severity": f.severity,
                    "evidence": f.evidence,
                    "description": f.description,
                }
                for f in self.findings
            ],
            columns=["source", "category", "severity", "evidence", "description"],
        )


class ExposureScanner:
    """Scan public artifacts for disclosure indicators.

    Parameters
    ----------
    signatures : sequence, optional
        Override the default ``(category, pattern, severity, description)`` set.
    max_evidence : int
        Truncation length for the captured matching snippet.
    """

    def __init__(self, signatures: Sequence[Tuple[str, str, float, str]] = None, max_evidence: int = 80) -> None:
        sigs = signatures if signatures is not None else _SIGNATURES
        self._signatures = [
            (cat, re.compile(pat, re.IGNORECASE), sev, desc) for cat, pat, sev, desc in sigs
        ]
        self.max_evidence = max_evidence

    def scan(self, artifacts: Union[Sequence[str], Mapping[str, str]]) -> ExposureReport:
        """Scan a list of texts or a ``{source: text}`` mapping."""
        items = self._normalise(artifacts)
        findings: List[Finding] = []
        for source, text in items:
            for category, regex, severity, description in self._signatures:
                for match in regex.finditer(text):
                    snippet = match.group(0).strip()[: self.max_evidence]
                    findings.append(
                        Finding(
                            category=category,
                            severity=severity,
                            evidence=snippet,
                            source=source,
                            description=description,
                        )
                    )
        return ExposureReport(findings)

    @staticmethod
    def _normalise(artifacts: Union[Sequence[str], Mapping[str, str]]) -> List[Tuple[str, str]]:
        if isinstance(artifacts, Mapping):
            return list(artifacts.items())
        return [(f"artifact[{i}]", text) for i, text in enumerate(artifacts)]
