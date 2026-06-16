"""Governance: an audit trail and a model card for SentinelAI.

Two AI-governance artifacts that production deployments and frameworks such as
the EU AI Act expect:

    * ``AuditLog`` - an append-only record of every guardrail decision. It
      stores the risk, decision, and timestamp, never the prompt or response
      content, so the trail is safe to retain and inspect.
    * ``model_card`` - a structured description of the system: intended use,
      detectors, evaluation metrics, and known limitations.
"""

from __future__ import annotations

import json
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Deque, Dict, List, Optional, Union


class AuditLog:
    """Append-only log of guardrail decisions (content-free, privacy-preserving)."""

    def __init__(self, path: Optional[Union[str, Path]] = None, keep_last: int = 1000) -> None:
        self._entries: Deque[dict] = deque(maxlen=keep_last)
        self.path = Path(path) if path else None

    def record(self, stage: str, risk: float, decision: str, alert: bool) -> dict:
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "stage": stage,                 # "input" or "output"
            "risk": round(float(risk), 4),
            "decision": decision,           # allow / flag / block
            "alert": bool(alert),
        }
        self._entries.append(entry)
        if self.path is not None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry) + "\n")
        return entry

    def __len__(self) -> int:
        return len(self._entries)

    def recent(self, n: int = 50) -> List[dict]:
        return list(self._entries)[-n:]

    def summary(self) -> Dict[str, float]:
        rows = list(self._entries)
        total = len(rows)
        blocked = sum(r["decision"] == "block" for r in rows)
        flagged = sum(r["decision"] == "flag" for r in rows)
        return {
            "total": total,
            "blocked": blocked,
            "flagged": flagged,
            "block_rate": (blocked / total if total else 0.0),
        }


# Source of truth for the model card, served at /modelcard and mirrored in
# docs/model_card.md. Metrics come from `python -m sentinel.benchmark`.
MODEL_CARD: Dict[str, object] = {
    "name": "SentinelAI",
    "version": "0.1.0",
    "purpose": "Risk monitoring guardrail for LLM applications: scores prompts and responses and decides allow/flag/block.",
    "intended_use": [
        "Inline guardrail in front of an LLM application (chatbot, RAG, agent).",
        "Scanning an organisation's own public footprint for architectural exposure.",
        "Red-team robustness testing of the guardrail's own detectors.",
    ],
    "out_of_scope": [
        "Not a model-serving framework; it observes, it does not host the LLM.",
        "Not a substitute for human review on high-stakes decisions.",
        "The red team and exposure scanner act only on assets under the operator's control.",
    ],
    "detectors": [
        {"name": "classifier", "method": "Logistic regression over embeddings (supervised, optional)", "watches": "input", "limitation": "Needs labelled training data and a built model artifact; strongest detector (ROC-AUC 0.94) when present."},
        {"name": "injection", "method": "OWASP-LLM signature library", "watches": "input", "limitation": "English regexes; fire at chance level on the multilingual/paraphrased deepset/prompt-injections test split."},
        {"name": "anomaly", "method": "Isolation Forest over embeddings", "watches": "input", "limitation": "Weak on the offline hashing encoder; needs semantic embeddings to reach full strength."},
        {"name": "drift", "method": "RBF-kernel MMD vs benign reference", "watches": "input (batch)", "limitation": "A distributional signal; not meaningful on a single prompt."},
        {"name": "leak", "method": "Signature library for response disclosures", "watches": "output", "limitation": "Signature-based; novel leak phrasings can evade it."},
        {"name": "role_drift", "method": "Cosine distance to a benign-response reference", "watches": "output", "limitation": "Same embedding-quality dependence as the input anomaly detector."},
    ],
    "evaluation": {
        "dataset": "deepset/prompt-injections (held-out test split, 116 prompts, 60 injections)",
        "metric": "ROC-AUC / precision / recall at best-F1 threshold, semantic embeddings",
        "results": {
            "injection_signatures": {"precision": 0.00, "recall": 0.00, "roc_auc": 0.50},
            "fused_unsupervised": {"precision": 0.64, "recall": 0.88, "f1": 0.74, "roc_auc": 0.69},
            "trained_classifier": {"precision": 0.87, "recall": 0.90, "f1": 0.89, "roc_auc": 0.94},
        },
    },
    "data": "Detectors calibrate on benign traffic. The repo ships synthetic benign/attack data so everything runs offline; evaluation uses a real public dataset.",
    "ethical_considerations": [
        "The audit log stores decisions and risk scores, never prompt or response content.",
        "The red-team module is dual-use; it ships no exfiltration tooling and invents no novel attacks, and targets only the local detectors.",
    ],
    "limitations": [
        "Signature detectors are precise but do not generalise; ML detectors depend on embedding quality.",
        "Synthetic calibration data is a stand-in for real production traffic.",
    ],
}


def model_card() -> Dict[str, object]:
    """Return the structured model card."""
    return MODEL_CARD
