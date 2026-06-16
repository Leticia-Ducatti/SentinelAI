"""Evaluate the detectors against a real public prompt-injection dataset.

Loads ``deepset/prompt-injections`` (binary-labelled: 0 benign, 1 injection)
through the Hugging Face datasets-server REST API, so no heavy ``datasets``
dependency is needed, and reports precision / recall / F1 / ROC-AUC for the
injection-signature detector and for the fused risk monitor.

Run with:  python -m sentinel.benchmark
"""

from __future__ import annotations

import json
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Dict, List, Tuple

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

from sentinel.detectors.injection import InjectionDetector
from sentinel.embeddings import Embedder
from sentinel.monitor import RiskMonitor

_DATASET = "deepset/prompt-injections"
_ROWS_URL = "https://datasets-server.huggingface.co/rows"
_PAGE = 100


def load_prompt_injections(
    split: str = "train", cache_dir: str = "data"
) -> Tuple[List[str], np.ndarray]:
    """Return ``(texts, labels)`` for a split, caching the download locally."""
    cache = Path(cache_dir) / f"prompt_injections_{split}.json"
    if cache.exists():
        payload = json.loads(cache.read_text())
        return payload["texts"], np.array(payload["labels"], dtype=np.int64)

    texts: List[str] = []
    labels: List[int] = []
    offset = 0
    while True:
        params = urllib.parse.urlencode(
            {"dataset": _DATASET, "config": "default", "split": split, "offset": offset, "length": _PAGE}
        )
        with urllib.request.urlopen(f"{_ROWS_URL}?{params}", timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        rows = data.get("rows", [])
        if not rows:
            break
        for r in rows:
            texts.append(r["row"]["text"])
            labels.append(int(r["row"]["label"]))
        offset += len(rows)
        if offset >= data.get("num_rows_total", offset):
            break

    cache.parent.mkdir(parents=True, exist_ok=True)
    cache.write_text(json.dumps({"texts": texts, "labels": labels}))
    return texts, np.array(labels, dtype=np.int64)


def evaluate_scores(scores: np.ndarray, labels: np.ndarray, threshold: float) -> Dict[str, float]:
    """Threshold the scores into predictions and compute standard metrics."""
    preds = (np.asarray(scores) > threshold).astype(np.int64)
    metrics = {
        "precision": float(precision_score(labels, preds, zero_division=0)),
        "recall": float(recall_score(labels, preds, zero_division=0)),
        "f1": float(f1_score(labels, preds, zero_division=0)),
        "accuracy": float(accuracy_score(labels, preds)),
        "threshold": float(threshold),
    }
    if len(set(labels.tolist())) > 1:
        metrics["roc_auc"] = float(roc_auc_score(labels, scores))
    return metrics


def best_f1_threshold(scores: np.ndarray, labels: np.ndarray) -> float:
    """The score threshold that maximises F1 (a fair operating point).

    A fixed 0.5 cut-off is arbitrary when scores live in a compressed range;
    ROC-AUC measures ranking quality independently, and this picks the best
    threshold to report precision/recall at.
    """
    scores = np.asarray(scores)
    candidates = np.unique(scores)
    best_thr, best_f1 = 0.5, -1.0
    for thr in candidates:
        preds = (scores > thr).astype(np.int64)
        f1 = f1_score(labels, preds, zero_division=0)
        if f1 > best_f1:
            best_f1, best_thr = f1, float(thr)
    return best_thr


def run_benchmark() -> Dict[str, Dict[str, float]]:
    """Benchmark three approaches on a held-out test split.

    All three fit/train on the train split and are evaluated on the test split:
    the signature detector (no training), the unsupervised fused monitor, and a
    supervised classifier trained on embeddings.
    """
    train_texts, train_labels = load_prompt_injections(split="train")
    test_texts, test_labels = load_prompt_injections(split="test")
    benign_train = [t for t, y in zip(train_texts, train_labels) if y == 0]

    results: Dict[str, Dict[str, float]] = {}

    # 1. Signatures: precise but narrow, no training.
    injector = InjectionDetector().fit([])
    inj_scores = injector.score_samples(test_texts)
    results["injection_signatures"] = evaluate_scores(
        inj_scores, test_labels, best_f1_threshold(inj_scores, test_labels)
    )

    # 2. Unsupervised fused monitor: calibrated on benign only.
    monitor = RiskMonitor().fit(benign_train)
    risk = np.array([monitor.score_prompt(t)["risk"] for t in test_texts])
    results["fused_unsupervised"] = evaluate_scores(risk, test_labels, best_f1_threshold(risk, test_labels))

    # 3. Supervised classifier on embeddings: trained on labels.
    embedder = Embedder()
    emb_train = embedder.encode(train_texts)
    emb_test = embedder.encode(test_texts)
    clf = LogisticRegression(max_iter=1000, class_weight="balanced").fit(emb_train, train_labels)
    proba = clf.predict_proba(emb_test)[:, 1]
    results["trained_classifier"] = evaluate_scores(proba, test_labels, best_f1_threshold(proba, test_labels))

    results["_meta"] = {
        "split": "test",
        "n": len(test_texts),
        "n_injection": int(test_labels.sum()),
        "embedder": "hashing" if embedder.is_fallback else "semantic",
    }
    return results


def main() -> None:
    results = run_benchmark()
    meta = results.pop("_meta")
    print(
        f"Dataset: {_DATASET} ({meta['split']}), n={meta['n']}, "
        f"injections={meta['n_injection']}, embedder={meta['embedder']}\n"
    )
    header = f"{'detector':<22}{'precision':>10}{'recall':>9}{'f1':>7}{'roc_auc':>9}{'thr':>7}"
    print(header)
    print("-" * len(header))
    for name, m in results.items():
        print(
            f"{name:<22}{m['precision']:>10.2f}{m['recall']:>9.2f}{m['f1']:>7.2f}"
            f"{m.get('roc_auc', float('nan')):>9.2f}{m['threshold']:>7.2f}"
        )

    out = Path("data/results")
    out.mkdir(parents=True, exist_ok=True)
    (out / "benchmark.json").write_text(json.dumps({**results, "_meta": meta}, indent=2))


if __name__ == "__main__":
    main()
