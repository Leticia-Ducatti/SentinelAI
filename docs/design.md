# SentinelAI Design

## Problem

Companies are deploying LLM applications (chatbots, RAG assistants, agents)
faster than they can monitor them. The real production failure modes are
LLM-specific and invisible to classical APM:

- Prompt injection and jailbreaks: users manipulate the model via natural language.
- Anomalous inputs: out-of-distribution or adversarial prompts.
- Distribution drift: the traffic the model sees moves away from what it was tested on.
- Data leakage, toxicity, hallucination: unsafe or wrong outputs.

SentinelAI is a monitoring layer that watches an LLM application and produces a
continuous risk score with alerts.

## Threat model: the reconnaissance chain

Detection alone is half the picture. An attacker's first step is
reconnaissance, and most LLM applications leak their own architecture through
public channels: source repositories, blog posts, job adverts, dependency
files, and even API error messages. Because almost every system is built on a
handful of civilian base models (Llama, Mistral, GPT, Claude), knowing which
one you use lets an attacker reuse jailbreaks and exploits that are already
public. Public disclosure lowers the cost of an attack to nearly zero. (This
framing is drawn from a public-footprint analysis of sovereign-AI deployments;
SentinelAI generalises it to any organisation running an LLM application.)

SentinelAI therefore models the whole chain rather than just the live traffic:

```
public footprint  ->  inferable exposure  ->  transferable attacks  ->  red team  ->  detectors  ->  hardening
   (recon)              (ExposureScanner)       (supply chain)          (Phase 2)     (Phase 1)      (loop)
```

The same machinery is reused at three points: distributional distance to a
reference (Barcode's core idea) drives drift detection on inputs, role-drift on
outputs, and behavioural drift between model versions.

## Architecture

```
   client --> POST /assess (FastAPI service)
                        |
                   Embedder  (sentence-transformers, hashing fallback)
                        |
        +---------------+-------------------------+
        |               |                         |
  InjectionDetector  PromptAnomalyDetector  EmbeddingDriftDetector
   (signatures)       (Isolation Forest)      (MMD vs benign ref)
        |               |                         |
        +---------------+-------------------------+
                        |
                   RiskMonitor   ->  risk score + allow/flag/block + /metrics
```

Every detector follows the same sklearn-style contract reused from Barcode:
`fit(benign)`, `score_samples`, `fit_threshold(percentile)`, `predict`.

The service exposes the monitor over HTTP so SentinelAI can sit inline as a
guardrail. The per-request gate (`/assess`) uses injection and anomaly, the
genuinely per-sample detectors; drift is a distributional signal measured over
a window of traffic via `RiskMonitor.assess`, not folded into a single request
where it would saturate. Decisions are `allow` / `flag` / `block` against two
thresholds, and `/metrics` reports running counters for observability.

### Output monitoring

Input gating is only half the guardrail. `OutputMonitor` (`/assess/output`)
scores the model's response for two signs of a successful jailbreak: a
signature detector for system-prompt leakage (the model echoing its
instructions or declaring it is now "unrestricted"), and a role-drift detector
that measures cosine distance from a benign-response reference. The role-drift
piece is Barcode's distance-to-reference machinery again, now over output
embeddings rather than input ones, so the same core idea covers input drift,
output drift, and (in the red team) version drift.

### Why these detectors

| Detector | Method | Catches |
|----------|--------|---------|
| Injection | Signature library (OWASP LLM Top 10) | known injection / jailbreak phrasings |
| Anomaly | Isolation Forest on embeddings | OOD / adversarial inputs, unseen attack shapes |
| Drift | RBF-kernel MMD vs benign reference | campaign shifts, topic drift, upstream changes |

The drift detector reuses Barcode's distance-to-benign-reference idea, moved
from network-flow windows to prompt-embedding windows.

### Known limitation

The injection detector is signature-based, so it is precise but does not
generalise: on the real `deepset/prompt-injections` test split it fires at
chance level, because hand-written English regexes miss multilingual and
paraphrased attacks. The unsupervised anomaly approach generalises moderately
(AUC 0.69); the benchmark showed a supervised classifier on embeddings is the
real lever (AUC 0.94), so it ships as `TrainedInjectionClassifier`. It is built
once with `sentinel-train` (persisted to `data/models/`) and the monitor loads
it automatically when the artifact matches the embedding space, fusing it into
the per-request risk as the dominant signal.

### Benchmark

`python -m sentinel.benchmark` evaluates three approaches against
`deepset/prompt-injections` (downloaded via the Hugging Face datasets-server
REST API, no extra dependency), all fitting/training on the train split and
evaluated on the held-out test split (116 prompts, 60 injections), with semantic
embeddings, at the best-F1 threshold:

| Approach | Precision | Recall | F1 | ROC-AUC |
|----------|----------:|-------:|---:|--------:|
| Injection signatures | 0.00 | 0.00 | 0.00 | 0.50 |
| Fused unsupervised (injection + anomaly) | 0.64 | 0.88 | 0.74 | 0.69 |
| Trained classifier (logistic regression on embeddings) | 0.87 | 0.90 | 0.89 | 0.94 |

### Exposure scanning (recon)

`ExposureScanner` is the entry point of the chain. It scans a collection of an
organisation's *own* public artifacts (README files, blog text, job adverts,
dependency manifests, sample API responses) for disclosure indicators and
returns an `ExposureReport` with a score and per-finding breakdown.

| Indicator | Why it matters |
|-----------|----------------|
| Base model name (Llama, Mistral, GPT, Claude) | known jailbreaks for that model transfer |
| Credentials / API keys | direct compromise |
| Vector store / framework / cloud infra | maps the attack surface |
| Internal endpoints and API paths | reachable targets |
| System-prompt or role text | enables targeted injection |
| Pinned dependency versions | links to known CVEs |

The recon-to-weaponise link is explicit: a disclosed base model maps to the
classes of attack a red team should prioritise (`transferable_attacks`), so the
external scan directly seeds the offline red team in Phase 2. The scanner is
rule and pattern based today (NER for entity extraction is a future upgrade),
and it is meant to be run against assets you control.

### Red team: air-gapped substitute-model attack

The red team follows a substitute-model attack (Papernot et al.): it never
touches the real system, only a simplified copy. Three roles are kept isolated:

```
[ ExposureReport ] --build--> [ SurrogateTarget ]   simplified copy; fidelity = exposure
                                     ^
                                     | attacks (air-gapped, offline)
                             [ Red team generator ]  evolutionary search + bandit,
                                     |                memory in VulnerabilityLog
                                     | SyncBundle (the only thing crossing the gap)
                                     v
                             [ BlueTeam ]            hardens the real detectors
```

Key design choices and why:

- **Surrogate fidelity equals public exposure.** The surrogate reproduces a
  fidelity-scaled subset of the target's signatures, where fidelity is derived
  from the `ExposureReport`. A leaky footprint yields a near-perfect copy; a
  clean one yields a poor copy. This makes the reconnaissance thesis measurable.
- **The air-gap is a trust boundary, not just an edge feature.** The red team
  runs isolated; the only artifact that crosses to the blue team is a hashed,
  versioned `SyncBundle` of attack patterns and coverage. Bundles and logs merge
  idempotently, which is also what an intermittently-connected (offline) node
  needs.
- **The attacker is allowed to know the defence (Kerckhoffs).** The generator is
  white-box against the surrogate and keeps a `VulnerabilityLog`, so the search
  concentrates on known blind spots. This is the honest way to evaluate a defence.
- **Transfer rate is the headline metric.** Of the attacks that evade the
  surrogate, how many also evade the real target? It rises with surrogate
  fidelity, which is the empirical statement of the threat model.

The blue team derives two fixes from the bundle: input normalisation (defeats
the character-separation evasion) and new signatures for the evasion synonyms
that appear in the patterns. Coverage is then re-measured on the evading set.

**Optional LLM agents.** The red and blue teams default to algorithmic
behaviour (evolutionary search and rules), which is what keeps them
deterministic, testable, and fully offline. With an LLM backend they become the
two real "AIs" of the substitute-model design: the red team generates creative
rewrites, the blue team proposes mitigations in natural language. The backend is
auto-detected in three tiers, each falling back to the next: the Anthropic API
(if a key is set), a local Ollama server (free, and genuinely air-gapped, which
matches the threat model), then the algorithmic mode. Nothing about the loop
changes; only the quality of the generated attacks and mitigations.

## Roadmap

- Phase 1 (this repo): detection core and service. Detectors, fused risk score,
  FastAPI guardrail, tests. Done.
- Phase 1b: exposure scanning. `ExposureScanner` scores an organisation's
  public footprint and links disclosed base models to transferable attacks.
  Done.
- Phase 2: red team. Air-gapped adaptive attacks against an exposure-scaled
  surrogate, blue-team hardening, and a transfer-rate measurement. Done.
- Phase 3: governance. Model cards, an audit log of alerts, and risk reporting
  aligned to AI-governance frameworks such as the EU AI Act.

## Non-goals

- Not a model-serving framework. SentinelAI observes; it does not host the LLM.
- The red-team module attacks only the local detectors, on models under the
  user's control. It ships no exfiltration tooling and invents no novel attacks.
- The exposure scanner inspects artifacts you provide (your own assets). It
  performs no active scanning, crawling, or probing of third-party systems.
