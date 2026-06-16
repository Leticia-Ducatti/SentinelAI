from sentinel.data import make_attacks, make_benign, make_stream
from sentinel.embeddings import Embedder
from sentinel.monitor import RiskMonitor


def _monitor():
    mon = RiskMonitor(embedder=Embedder(backend="hashing", dim=256))
    return mon.fit(make_benign(200))


def test_attacks_get_higher_risk_than_benign():
    mon = _monitor()
    benign_risk = mon.assess(make_benign(50, seed=11))["risk"].mean()
    attack_risk = mon.assess(make_attacks(50, seed=12))["risk"].mean()
    assert attack_risk > benign_risk


def test_assess_returns_expected_columns_and_alerts():
    mon = _monitor()
    prompts, labels = make_stream(n_benign=80, n_attacks=20, seed=13)
    out = mon.assess(prompts)
    assert list(out.columns) == [
        "prompt", "injection", "anomaly", "drift", "risk", "alert",
    ]
    # Most alerts should land on actual attacks (precision sanity check).
    flagged = out["alert"].to_numpy()
    if flagged.any():
        precision = (labels[flagged] == 1).mean()
        assert precision >= 0.5


def test_assess_before_fit_raises():
    import pytest

    mon = RiskMonitor(embedder=Embedder(backend="hashing"))
    with pytest.raises(RuntimeError):
        mon.assess(["hello"])
