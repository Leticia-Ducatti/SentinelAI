# Model Card: SentinelAI

A model card following the Mitchell et al. (2019) structure. The live version is
served at `GET /modelcard`; this file is the human-readable mirror.

## Overview

SentinelAI is a risk-monitoring guardrail for LLM applications. It scores prompts
and model responses and returns an allow / flag / block decision, scans an
organisation's public footprint for architectural exposure, and red-teams its own
detectors.

- **Version:** 0.1.0
- **Owners:** Leticia Ducatti
- **License:** MIT

## Intended use

- Inline guardrail in front of an LLM application (chatbot, RAG, agent).
- Scanning an organisation's own public artifacts for exposure.
- Red-team robustness testing of the guardrail's detectors.

## Out of scope

- Not a model-serving framework; it observes, it does not host the LLM.
- Not a substitute for human review on high-stakes decisions.
- The red team and exposure scanner act only on assets under the operator's control.

## Detectors

| Detector | Watches | Method | Key limitation |
|----------|---------|--------|----------------|
| injection | input | OWASP-LLM signature library | English regexes; weak on multilingual / paraphrased attacks |
| anomaly | input | Isolation Forest over embeddings | Needs semantic embeddings to reach full strength |
| drift | input (batch) | RBF-kernel MMD vs benign reference | Distributional; not meaningful on a single prompt |
| leak | output | Signature library for response disclosures | Novel leak phrasings can evade it |
| role_drift | output | Cosine distance to a benign-response reference | Depends on embedding quality |

## Evaluation

Measured on the held-out test split of `deepset/prompt-injections` (116 prompts,
60 injections), with semantic embeddings, at the best-F1 threshold
(`python -m sentinel.benchmark`):

| Approach | Precision | Recall | F1 | ROC-AUC |
|----------|----------:|-------:|---:|--------:|
| Injection signatures | 0.00 | 0.00 | 0.00 | 0.50 |
| Fused unsupervised (injection + anomaly) | 0.64 | 0.88 | 0.74 | 0.69 |
| Trained classifier (logistic regression on embeddings) | 0.87 | 0.90 | 0.89 | 0.94 |

## Ethical considerations

- The audit log records decisions and risk scores, never prompt or response content.
- The red-team module is dual-use: it ships no exfiltration tooling, invents no
  novel attacks, and targets only the local detectors.

## Limitations

- Signature detectors are precise but do not generalise; ML detectors depend on
  embedding quality.
- Synthetic calibration data is a stand-in for real production traffic.
