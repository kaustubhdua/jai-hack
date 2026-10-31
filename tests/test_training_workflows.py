import numpy as np
import pandas as pd
import pytest
from pathlib import Path

from cybersentinel.agents.threat_detection.train import train_from_csv
from scripts.train_anomaly import train_anomaly
from scripts.train_models import train_models

CLASSES = ["BENIGN", "BRUTE_FORCE", "DOS", "DDOS", "PORT_SCAN"]


def small_frame(rows_per_class=12):
    rng = np.random.default_rng(44)
    rows = []
    for class_index, label in enumerate(CLASSES):
        for _ in range(rows_per_class):
            rows.append({
                "Flow Duration": float(class_index * 100 + rng.normal(0, 2)),
                "Total Fwd Packets": float(class_index * 10 + rng.normal(0, 1)),
                "Flow Bytes/s": float(class_index * 1000 + rng.normal(0, 10)),
                "label": label,
            })
    return pd.DataFrame(rows)


def test_agent1_training_workflow_persists_calibrated_artifact(tmp_path):
    train, calibration = small_frame(), small_frame(rows_per_class=5)
    train_path, calibration_path = tmp_path / "train.csv", tmp_path / "calibration.csv"
    train.to_csv(train_path, index=False)
    calibration.to_csv(calibration_path, index=False)
    model_path, report_path = tmp_path / "agent1.joblib", tmp_path / "agent1.json"
    report = train_from_csv(
        str(train_path), "label", str(model_path),
        calibration_validation_csv=str(calibration_path),
        report_out=str(report_path), n_estimators=20,
    )
    assert report["confidence_calibration"]["validation_rows"] == len(calibration)
    assert report["artifact_metadata"]["confidence_calibrated"] is True
    assert model_path.is_file() and report_path.is_file()


def test_agent1_training_rejects_training_file_as_calibration(tmp_path):
    train = small_frame()
    path = tmp_path / "train.csv"
    train.to_csv(path, index=False)
    with pytest.raises(ValueError, match="separate held-out"):
        train_from_csv(str(path), "label", calibration_validation_csv=str(path), n_estimators=10)


def test_agent2_training_workflow_calibrates_and_persists_threshold(tmp_path):
    train, calibration = small_frame(30), small_frame(8)
    train_path, calibration_path = tmp_path / "train.csv", tmp_path / "calibration.csv"
    train.to_csv(train_path, index=False)
    calibration.to_csv(calibration_path, index=False)
    model_path, report_path = tmp_path / "agent2.joblib", tmp_path / "agent2.json"
    report = train_anomaly(
        str(train_path), str(model_path), str(report_path),
        validation_path=str(calibration_path), max_benign_fpr=0.10,
    )
    assert report["threshold_calibration"] is not None
    assert report["metadata"]["threshold_selection_uses_labels"] is True
    assert model_path.is_file() and report_path.is_file()


def test_agent2_training_rejects_training_file_as_validation(tmp_path):
    train = small_frame()
    path = tmp_path / "train.csv"
    train.to_csv(path, index=False)
    with pytest.raises(ValueError, match="separate held-out"):
        train_anomaly(
            str(path), str(tmp_path / "model.joblib"), str(tmp_path / "report.json"),
            validation_path=str(path),
        )



def test_combined_training_workflow_reloads_both_real_model_artifacts(tmp_path):
    training = small_frame(rows_per_class=20)
    training_path = tmp_path / "training.csv"
    training.to_csv(training_path, index=False)
    manifest = train_models(
        training_path=training_path,
        validation_path=None,
        model_dir=tmp_path / "models",
        report_dir=tmp_path / "reports",
        n_estimators=20,
    )
    assert manifest["training_rows"] == len(training)
    assert manifest["model_training_rows"] == 85
    assert manifest["validation_rows"] == 15
    assert manifest["evaluation_data_used_for_training_or_calibration"] is False
    assert manifest["hidden_data_used_for_training_or_calibration"] is False
    assert manifest["a1"]["training_rows"] == 85
    assert manifest["a2"]["training_rows"] == 17
    assert manifest["a1"]["confidence_calibrated"] is True
    assert manifest["a2"]["threshold_calibrated"] is False
    assert manifest["a2"]["threshold_selection_source"] == "benign_training_distribution"
    assert Path(manifest["a1"]["artifact"]).is_file()
    assert Path(manifest["a2"]["artifact"]).is_file()


def test_combined_training_workflow_rejects_training_file_as_external_validation(tmp_path):
    training_path = tmp_path / "training.csv"
    small_frame().to_csv(training_path, index=False)
    with pytest.raises(ValueError, match="separate held-out partition"):
        train_models(
            training_path=training_path,
            validation_path=training_path,
            model_dir=tmp_path / "models",
            report_dir=tmp_path / "reports",
            n_estimators=10,
        )
