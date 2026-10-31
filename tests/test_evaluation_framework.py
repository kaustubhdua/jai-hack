"""Automated test suite for CyberSentinel Comprehensive Evaluation Framework."""
from __future__ import annotations

from pathlib import Path
import pytest
import numpy as np
import pandas as pd

from cybersentinel.contracts import BenchmarkClass
from cybersentinel.agents.threat_detection import ThreatDetectionAgent, ThreatDetectionModel
from cybersentinel.agents.anomaly_detection import AnomalyDetectionAgent
from cybersentinel.agents.fusion import EvidenceFusionAgent
from cybersentinel.evaluation import (
    evaluate_classifier,
    evaluate_classifier_vs_fusion,
    evaluate_anomaly_detection,
    evaluate_seen_unseen_generalization,
    evaluate_leave_one_attack_out,
    evaluate_probability_calibration,
    evaluate_temporal_correlation,
    evaluate_adaptive_defense,
)
from cybersentinel.replay.submission import SubmissionValidator


@pytest.fixture
def mock_dataset():
    """Create a minimal synthetic flow dataset containing all 5 classes and numeric features."""
    np.random.seed(42)
    n_samples = 200
    classes = ["BENIGN", "BRUTE_FORCE", "DOS", "DDOS", "PORT_SCAN"]
    labels = np.random.choice(classes, size=n_samples, p=[0.6, 0.1, 0.1, 0.1, 0.1])

    features = {f"feature_{i}": np.random.randn(n_samples) for i in range(10)}
    features["Destination Port"] = np.random.choice([80, 443, 22, 8080], size=n_samples)
    features["source_ip"] = [f"192.168.1.{i % 15}" for i in range(n_samples)]
    features["label"] = labels
    features["record_id"] = [f"FLOW-{i:05d}" for i in range(n_samples)]

    return pd.DataFrame(features)


@pytest.fixture
def trained_models(mock_dataset):
    """Train miniature A1 and A2 models on the mock dataset."""
    feature_cols = [f"feature_{i}" for i in range(10)] + ["Destination Port"]

    # Train ThreatDetectionModel (A1)
    threat_model = ThreatDetectionModel(n_estimators=10, random_state=42)
    threat_model.fit(mock_dataset[feature_cols], mock_dataset["label"])
    threat_agent = ThreatDetectionAgent(threat_model)

    # Train AnomalyDetectionAgent (A2) on BENIGN only
    benign_df = mock_dataset[mock_dataset["label"] == "BENIGN"]
    anomaly_agent = AnomalyDetectionAgent().fit(benign_df)

    return threat_agent, anomaly_agent, feature_cols


def test_classification_evaluation(mock_dataset, trained_models):
    threat_agent, _, _ = trained_models
    results = evaluate_classifier(mock_dataset, threat_agent)

    assert "metrics" in results
    m = results["metrics"]
    assert 0.0 <= m["accuracy"] <= 1.0
    assert 0.0 <= m["macro_f1"] <= 1.0
    assert 0.0 <= m["balanced_accuracy"] <= 1.0
    assert 0.0 <= m["benign_false_positive_rate"] <= 1.0
    assert 0.0 <= m["attack_detection_rate"] <= 1.0

    # Ensure 5x5 confusion matrix
    cm = results["confusion_matrix"]
    assert len(cm) == 5
    assert all(len(row) == 5 for row in cm)
    assert len(results["classes"]) == 5


def test_fusion_evaluation(mock_dataset, trained_models):
    threat_agent, anomaly_agent, _ = trained_models
    fusion_agent = EvidenceFusionAgent()

    results = evaluate_classifier_vs_fusion(mock_dataset, threat_agent, anomaly_agent, fusion_agent)

    assert "summary" in results
    s = results["summary"]
    assert "a1_accuracy" in s
    assert "a3_accuracy" in s
    assert "net_improvement_percentage" in s
    assert "total_overrides" in s

    # Ensure security decisions (ALLOW/REVIEW/BLOCK) are tracked separately from classification
    sec = results["security_decisions"]
    assert "action_counts" in sec
    assert set(sec["action_counts"].keys()) == {"ALLOW", "REVIEW", "BLOCK"}
    assert sum(sec["action_counts"].values()) == len(mock_dataset)


def test_anomaly_evaluation(mock_dataset, trained_models):
    _, anomaly_agent, _ = trained_models
    results = evaluate_anomaly_detection(mock_dataset, anomaly_agent, threshold=0.5)

    assert results["score_inverted"] is True
    assert 0.0 <= results["roc_auc"] <= 1.0
    assert 0.0 <= results["average_precision"] <= 1.0

    op = results["operational_metrics"]
    assert 0.0 <= op["benign_fpr"] <= 1.0
    assert 0.0 <= op["attack_recall"] <= 1.0
    assert "per_attack_class_recall" in results


def test_generalization_evaluation(mock_dataset, trained_models):
    threat_agent, _, _ = trained_models
    train_subset = mock_dataset.iloc[:100]
    eval_subset = mock_dataset.iloc[100:]

    results = evaluate_seen_unseen_generalization(train_subset, eval_subset, threat_agent)

    gen = results["generalization_summary"]
    assert gen["total_eval_samples"] == len(eval_subset)
    assert gen["seen_samples_count"] + gen["unseen_samples_count"] == len(eval_subset)
    assert "seen_evaluation" in results
    assert "unseen_evaluation" in results


def test_probability_calibration(mock_dataset):
    train_subset = mock_dataset.iloc[:120]
    eval_subset = mock_dataset.iloc[120:]

    results = evaluate_probability_calibration(
        train_df=train_subset,
        eval_df=eval_subset,
        cal_fraction=0.25,
    )

    ev = results["evaluation"]
    assert "uncalibrated" in ev
    assert "calibrated" in ev
    assert "ece" in ev["uncalibrated"]
    assert "brier_score" in ev["uncalibrated"]
    assert len(ev["calibrated"]["reliability_bins"]) > 0


def test_temporal_correlation_evaluation(mock_dataset):
    results = evaluate_temporal_correlation(mock_dataset)

    assert "evaluation_summary" in results
    s = results["evaluation_summary"]
    assert "total_campaigns_detected" in s
    assert 0.0 <= s["campaign_precision"] <= 1.0
    assert "mean_detection_delay_flows" in s


def test_adaptive_defense_evaluation(mock_dataset, trained_models):
    threat_agent, anomaly_agent, _ = trained_models
    results = evaluate_adaptive_defense(mock_dataset, threat_agent, anomaly_agent, policy_duration=30)

    assert "comparison_table" in results
    tbl = results["comparison_table"]
    assert "config_1_no_defense" in tbl
    assert "config_2_existing_defense" in tbl
    assert "config_3_defense_without_temporal" in tbl
    assert "config_4_temporal_plus_defense" in tbl

    cfg4 = tbl["config_4_temporal_plus_defense"]
    assert 0.0 <= cfg4["containment_rate"] <= 1.0
    assert 0.0 <= cfg4["false_blocking_rate"] <= 1.0


def test_submission_validator_exact_id_matching(tmp_path):
    class_file = tmp_path / "classification.csv"
    class_file.write_text(
        "record_id,predicted_class,anomaly score,evidence status\n"
        "REC-1,BENIGN,0.1,AGREE\n"
        "REC-2,DOS,0.9,AGREE\n",
        encoding="utf-8"
    )

    # Correct IDs match
    res_valid = SubmissionValidator.validate_classification(class_file, ["REC-1", "REC-2"])
    assert res_valid["valid"] is True

    # Mismatched ID fails validation
    res_invalid = SubmissionValidator.validate_classification(class_file, ["REC-1", "REC-3"])
    assert res_invalid["valid"] is False
    assert any("Missing expected record IDs" in err for err in res_invalid["errors"])
