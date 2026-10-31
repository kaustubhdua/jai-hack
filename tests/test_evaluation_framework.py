"""Contract tests for the current-mainline evaluation utilities."""
from pathlib import Path
from types import SimpleNamespace

import numpy as np
import pandas as pd

from cybersentinel.evaluation.anomaly import evaluate_anomaly_detector
from cybersentinel.evaluation.calibration import calculate_expected_calibration_error, calculate_multiclass_brier_score, evaluate_probability_calibration
from cybersentinel.evaluation.classification import evaluate_classifier
from cybersentinel.evaluation.generalization import build_training_feature_registry, canonicalize_feature_vector
from cybersentinel.evaluation.report import compute_file_sha256
from cybersentinel.evaluation.temporal import evaluate_temporal_correlation


def test_classifier_metrics_are_bounded_and_keep_all_five_classes():
    labels = ["BENIGN", "BRUTE_FORCE", "DOS", "DDOS", "PORT_SCAN"]
    report = evaluate_classifier(labels, labels)
    assert report["metrics"]["accuracy"] == 1.0
    assert len(report["confusion_matrix"]) == 5
    assert all(len(row) == 5 for row in report["confusion_matrix"])


def test_anomaly_evaluation_inverts_isolation_forest_scores():
    labels = ["BENIGN", "BENIGN", "DOS", "DDOS", "PORT_SCAN"]
    # Lower raw Isolation Forest decision scores mean more anomalous.
    scores = [0.2, 0.3, -0.2, -0.3, -0.4]
    report = evaluate_anomaly_detector(labels, scores, operational_threshold=0.0)
    assert report["roc_auc"] == 1.0
    assert report["operational_metrics"]["attack_recall"] == 1.0
    assert report["operational_metrics"]["benign_fpr"] == 0.0


def test_calibration_metrics_are_finite_and_bounded():
    y = np.array([0, 1, 2])
    probabilities = np.array([[0.8, 0.1, 0.1], [0.1, 0.8, 0.1], [0.1, 0.1, 0.8]])
    ece, bins = calculate_expected_calibration_error(y, probabilities)
    brier = calculate_multiclass_brier_score(y, probabilities, 3)
    assert 0.0 <= ece <= 1.0
    assert 0.0 <= brier <= 2.0
    assert len(bins) == 10


def test_feature_registry_uses_stable_feature_hashes():
    frame = pd.DataFrame({"f1": [1.0, 2.0], "f2": [3.0, 4.0]})
    registry = build_training_feature_registry(frame, ["f1", "f2"])
    assert canonicalize_feature_vector(np.array([1.0, 3.0])) in registry
    assert len(registry) == 2


def test_temporal_evaluation_returns_explicit_summary():
    frame = pd.DataFrame({
        "record_id": ["r1", "r2", "r3"],
        "source_ip": ["192.0.2.1", "192.0.2.1", "192.0.2.2"],
        "destination_ip": ["198.51.100.1", "198.51.100.1", "198.51.100.2"],
        "Destination Port": [22, 23, 443],
        "label": ["BENIGN", "PORT_SCAN", "BENIGN"],
    })
    report = evaluate_temporal_correlation(frame, SimpleNamespace(predict=lambda row: SimpleNamespace(predicted_class="BENIGN", confidence=0.99, status="success")), test_shuffled_robustness=False)
    assert report["evaluation_summary"]["total_flows_evaluated"] == 3


def test_report_hash_is_empty_for_missing_files(tmp_path: Path):
    assert compute_file_sha256(tmp_path / "missing.json") == ""

def test_probability_calibration_uses_group_isolated_training_holdout():
    rng = np.random.default_rng(11)
    classes = ["BENIGN", "BRUTE_FORCE", "DOS", "DDOS", "PORT_SCAN"]
    train = pd.DataFrame(rng.normal(size=(150, 6)), columns=[f"feature_{i}" for i in range(6)])
    train["label"] = np.repeat(classes, 30)
    evaluation = pd.DataFrame(rng.normal(size=(25, 6)), columns=[f"feature_{i}" for i in range(6)])
    evaluation["label"] = np.repeat(classes, 5)

    report = evaluate_probability_calibration(train, evaluation, cal_fraction=0.2, n_estimators=10)
    assert report["training_samples"] + report["calibration_samples"] == len(train)
    assert report["evaluation_samples"] == len(evaluation)
    assert "group-isolated" in report["calibration_provenance"]
    assert np.isfinite(report["calibrated"]["ece"])
