from sentinel.data import make_footprint
from sentinel.exposure import ExposureScanner


def test_leaky_footprint_scores_higher_than_clean():
    scanner = ExposureScanner()
    leaky = scanner.scan(make_footprint(leaky=True)).score
    clean = scanner.scan(make_footprint(leaky=False)).score
    assert leaky > clean
    assert leaky > 0.5


def test_leaky_footprint_finds_model_and_credential():
    report = ExposureScanner().scan(make_footprint(leaky=True))
    categories = report.by_category()
    assert "base_model" in categories
    assert "credential" in categories


def test_disclosed_model_maps_to_transferable_attacks():
    report = ExposureScanner().scan(make_footprint(leaky=True))
    attacks = report.transferable_attacks()
    assert "llama" in attacks
    assert len(attacks["llama"]) >= 1


def test_clean_footprint_has_no_high_severity_findings():
    report = ExposureScanner().scan(make_footprint(leaky=False))
    assert all(f.severity < 1.5 for f in report.findings)
    assert not report.disclosed_models()


def test_report_to_frame_columns():
    report = ExposureScanner().scan(make_footprint(leaky=True))
    frame = report.to_frame()
    assert list(frame.columns) == [
        "source", "category", "severity", "evidence", "description",
    ]
    assert len(frame) == len(report.findings)


def test_scan_accepts_plain_list():
    findings = ExposureScanner().scan(["we run on Llama-3 and Pinecone"]).findings
    assert any(f.category == "base_model" for f in findings)
    assert findings[0].source == "artifact[0]"
