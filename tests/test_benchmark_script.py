import json

import pandas as pd
import pytest

from cybersentinel.contracts import AnomalyDetectionResult
from scripts import evaluate_benchmark


class FakeThreatAgent:
    model = type("Model", (), {"backend": "random_forest", "metadata": {"training_rows": 100}})()

    def predict_many(self, features):
        return [
            {"predicted_class": "BENIGN", "confidence": 0.99, "status": "success"},
            {"predicted_class": "DOS", "confidence": 0.98, "status": "success"},
            {"predicted_class": "PORT_SCAN", "confidence": 0.97, "status": "success"},
        ]


class FakeAnomalyAgent:
    metadata = {"training_rows": 80}
    threshold = 0.42

    def score_frame(self, features):
        return [
            AnomalyDetectionResult(-0.2, False),
            AnomalyDetectionResult(0.3, False),
            AnomalyDetectionResult(None, None, status="error"),
        ]


def test_benchmark_counts_every_fusion_status_without_key_error(monkeypatch, tmp_path):
    frame = pd.DataFrame({
        "label": ["BENIGN", "DOS", "PORT_SCAN"],
        "Flow Duration": [100.0, 200.0, 300.0],
    })
    monkeypatch.setattr(evaluate_benchmark, "load_frame", lambda _: frame.copy())
    monkeypatch.setattr(evaluate_benchmark.ThreatDetectionAgent, "load", lambda _: FakeThreatAgent())
    monkeypatch.setattr(evaluate_benchmark.AnomalyDetectionAgent, "load", lambda _: FakeAnomalyAgent())

    output = tmp_path / "official_evaluation.json"
    report = evaluate_benchmark.evaluate(
        "eval.parquet", "threat.joblib", "anomaly.joblib", str(output), fusion_sample=3,
    )

    assert report["agent_3_evidence_fusion_sample"]["evidence_status"] == {
        "AGREE": 1, "CONFLICT": 1, "UNCERTAIN": 1,
    }
    assert report["agent_3_evidence_fusion_sample"]["actions"] == {
        "ALLOW": 1, "BLOCK": 0, "REVIEW": 2,
    }
    assert json.loads(output.read_text(encoding="utf-8")) == report


def test_benchmark_rejects_empty_evaluation_frame(monkeypatch):
    monkeypatch.setattr(evaluate_benchmark, "load_frame", lambda _: pd.DataFrame({"label": []}))
    with pytest.raises(ValueError, match="no rows"):
        evaluate_benchmark.evaluate("empty.csv", "threat.joblib", "anomaly.joblib", "out.json")


def test_benchmark_rejects_missing_and_empty_labels(monkeypatch):
    missing = pd.DataFrame({"label": [None], "Flow Duration": [1.0]})
    monkeypatch.setattr(evaluate_benchmark, "load_frame", lambda _: missing.copy())
    with pytest.raises(ValueError, match="missing"):
        evaluate_benchmark.evaluate("missing.csv", "threat.joblib", "anomaly.joblib", "out.json")

    empty = pd.DataFrame({"label": [" "], "Flow Duration": [1.0]})
    monkeypatch.setattr(evaluate_benchmark, "load_frame", lambda _: empty.copy())
    with pytest.raises(ValueError, match="empty"):
        evaluate_benchmark.evaluate("empty-label.csv", "threat.joblib", "anomaly.joblib", "out.json")
