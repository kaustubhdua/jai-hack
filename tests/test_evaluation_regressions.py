"""Regression tests for evaluation report and runner contracts."""
import ast
import json
import inspect
from pathlib import Path

import pandas as pd
from types import SimpleNamespace

from cybersentinel.evaluation.classification import evaluate_classifier
from cybersentinel.evaluation.loao import evaluate_leave_one_attack_out
from cybersentinel.evaluation.report import save_evaluation_report
from cybersentinel.evaluation.temporal import evaluate_temporal_correlation
from cybersentinel.agents.threat_detection.model import ThreatDetectionModel


def test_classification_report_is_json_serializable_without_cycles():
    report = evaluate_classifier(
        ["BENIGN", "DOS", "DDOS", "PORT_SCAN", "BRUTE_FORCE"],
        ["BENIGN", "DOS", "DDOS", "PORT_SCAN", "BRUTE_FORCE"],
    )
    encoded = json.dumps(report)
    assert json.loads(encoded)["metrics"]["accuracy"] == 1.0


def test_save_evaluation_report_writes_valid_json(tmp_path):
    report = evaluate_classifier(["BENIGN", "DOS"], ["BENIGN", "DOS"])
    path = save_evaluation_report("classification", report, tmp_path)
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["data"]["metrics"]["accuracy"] == 1.0


def test_loao_runner_call_matches_public_function_signature():
    script = Path(__file__).resolve().parents[1] / "scripts" / "evaluate_full_system.py"
    tree = ast.parse(script.read_text(encoding="utf-8"))
    calls = [
        node for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "evaluate_leave_one_attack_out"
    ]
    assert len(calls) == 1
    accepted = set(inspect.signature(evaluate_leave_one_attack_out).parameters)
    passed = {kw.arg for kw in calls[0].keywords if kw.arg}
    assert passed <= accepted
    assert "omitted_classes" not in passed


def test_temporal_evaluation_represents_unobserved_delay_as_none():
    frame = pd.DataFrame({
        "record_id": ["r1", "r2"],
        "source_ip": ["", ""],
        "Destination Port": [80, 443],
        "label": ["BENIGN", "DOS"],
    })
    report = evaluate_temporal_correlation(frame, SimpleNamespace(predict=lambda row: SimpleNamespace(predicted_class="BENIGN", confidence=0.99, status="success")), test_shuffled_robustness=False)
    summary = report["evaluation_summary"]
    assert summary["campaigns_by_type"]["DDOS"] == 0
    assert summary["mean_detection_delay_flows"] is None


def test_temporal_evaluation_never_feeds_ground_truth_labels_to_agent():
    seen = []
    class Predictor:
        def predict(self, row):
            # The evaluator must not pass labels into this call.
            assert "label" not in row
            seen.append("called")
            return type("Prediction", (), {"predicted_class": "BENIGN", "confidence": 0.99, "status": "success"})()

    frame = pd.DataFrame({
        "record_id": ["a", "b", "c", "d", "e"],
        "source_ip": ["192.0.2.1"] * 5,
        "Destination Port": [21, 22, 23, 24, 25],
        "label": ["PORT_SCAN"] * 5,
    })
    report = evaluate_temporal_correlation(frame, Predictor(), test_shuffled_robustness=False)
    assert len(seen) == len(frame)
    assert report["evaluation_summary"]["correlated_flows_total"] == 0
    assert report["evaluation_summary"]["campaign_metrics_available"] is False


def test_loao_model_can_train_on_four_known_classes_without_inventing_fifth():
    frame = pd.DataFrame({
        "feature_a": [0.0, 0.1, 1.0, 1.1, 2.0, 2.1, 3.0, 3.1],
        "feature_b": [1.0, 1.1, 2.0, 2.1, 3.0, 3.1, 4.0, 4.1],
    })
    labels = ["BENIGN", "BENIGN", "BRUTE_FORCE", "BRUTE_FORCE", "DOS", "DOS", "DDOS", "DDOS"]
    model = ThreatDetectionModel(n_estimators=5, allow_missing_classes=True).fit(frame, labels)
    prediction = model.predict_one({"feature_a": 0.05, "feature_b": 1.05})
    assert prediction["predicted_class"] in {"BENIGN", "BRUTE_FORCE", "DOS", "DDOS"}
    assert "PORT_SCAN" in model.metadata["missing_training_classes"]
    assert model.metadata["allow_missing_classes"] is True


def test_temporal_evaluation_uses_batch_predictions_without_passing_labels():
    class BatchPredictor:
        def predict(self, row):
            raise AssertionError("row-wise inference should not be used when predict_frame exists")

        def predict_frame(self, frame):
            assert "label" not in frame.columns
            return [
                SimpleNamespace(predicted_class="BENIGN", confidence=0.99, status="success")
                for _ in range(len(frame))
            ]

    frame = pd.DataFrame({
        "record_id": ["a", "b", "c"],
        "source_ip": ["192.0.2.1"] * 3,
        "Destination Port": [21, 22, 23],
        "label": ["PORT_SCAN"] * 3,
    })
    report = evaluate_temporal_correlation(
        frame, BatchPredictor(), test_shuffled_robustness=False
    )
    assert report["evaluation_summary"]["prediction_errors"] == 0
    assert report["evaluation_summary"]["total_flows_evaluated"] == 3


def test_temporal_batch_prediction_count_must_match_rows():
    class BrokenBatchPredictor:
        def predict_frame(self, frame):
            return []

    frame = pd.DataFrame({
        "record_id": ["a"],
        "source_ip": ["192.0.2.1"],
        "Destination Port": [21],
        "label": ["PORT_SCAN"],
    })
    import pytest
    with pytest.raises(ValueError, match="align one-to-one"):
        evaluate_temporal_correlation(
            frame, BrokenBatchPredictor(), test_shuffled_robustness=False
        )


def test_publication_plots_accept_saved_evaluation_report_schemas(tmp_path):
    import pytest
    pytest.importorskip("matplotlib")
    from cybersentinel.evaluation.plots import generate_all_plots

    bins = [
        {"sample_count": 10, "mean_confidence": 0.7, "observed_accuracy": 0.6},
        {"sample_count": 8, "mean_confidence": 0.9, "observed_accuracy": 0.8},
        {"sample_count": 0, "mean_confidence": 0.0, "observed_accuracy": 0.0},
    ]
    anomaly = {
        "roc_auc": 0.82,
        "average_precision": 0.91,
        "roc_curve": [{"fpr": 0.0, "tpr": 0.0}, {"fpr": 1.0, "tpr": 1.0}],
        "pr_curve": [{"recall": 1.0, "precision": 0.8}, {"recall": 0.0, "precision": 1.0}],
    }
    calibration = {
        "evaluation": {
            "uncalibrated": {"ece": 0.1, "reliability_bins": bins},
            "calibrated": {"ece": 0.12, "reliability_bins": bins},
        }
    }
    matrix = [[2, 0], [0, 2]]
    generated = generate_all_plots(
        tmp_path,
        classification_data={"confusion_matrix": matrix},
        fusion_data={"confusion_matrix_after_fusion": matrix},
        anomaly_data=anomaly,
        generalization_data={
            "seen_evaluation": {},
            "unseen_evaluation": {},
        },
        calibration_data=calibration,
        loao_data={"trials": {}},
        temporal_data={},
        defense_data={"comparison_table": {"baseline": {"name": "Baseline"}}},
    )
    names = {path.name for path in generated}
    assert "anomaly_roc_pr_curves.png" in names
    assert "calibration_reliability_diagram.png" in names
    assert (tmp_path / "anomaly_roc_pr_curves.svg").is_file()
    assert (tmp_path / "calibration_reliability_diagram.svg").is_file()
