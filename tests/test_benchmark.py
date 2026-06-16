import numpy as np

from sentinel.benchmark import best_f1_threshold, evaluate_scores


def test_evaluate_scores_perfect_separation():
    scores = np.array([0.9, 0.8, 0.1, 0.2])
    labels = np.array([1, 1, 0, 0])
    m = evaluate_scores(scores, labels, threshold=0.5)
    assert m["precision"] == 1.0
    assert m["recall"] == 1.0
    assert m["f1"] == 1.0
    assert m["roc_auc"] == 1.0


def test_evaluate_scores_with_errors():
    scores = np.array([0.9, 0.4, 0.6, 0.1])  # preds at 0.5 -> [1, 0, 1, 0]
    labels = np.array([1, 1, 0, 0])          # one FN, one FP
    m = evaluate_scores(scores, labels, threshold=0.5)
    assert m["precision"] == 0.5
    assert m["recall"] == 0.5


def test_best_f1_threshold_finds_separating_cut():
    scores = np.array([0.1, 0.2, 0.7, 0.8])
    labels = np.array([0, 0, 1, 1])
    thr = best_f1_threshold(scores, labels)
    preds = (scores > thr).astype(int)
    assert list(preds) == [0, 0, 1, 1]
