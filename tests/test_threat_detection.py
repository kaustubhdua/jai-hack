import json
import numpy as np
import pandas as pd
import pytest
from cybersentinel.agents.threat_detection import ThreatDetectionAgent, ThreatDetectionModel
from cybersentinel.agents.threat_detection.model import numeric_features
from cybersentinel.agents.threat_detection.evaluate import evaluate_predictions
from cybersentinel.agents.threat_detection.train import load_label_mapping
from cybersentinel.contracts import ThreatDetectionResult

CLASSES = ["BENIGN", "BRUTE_FORCE", "DOS", "DDOS", "PORT_SCAN"]

def sample_data():
    rows, labels = [], []
    rng = np.random.default_rng(7)
    for index, label in enumerate(CLASSES):
        for _ in range(12):
            rows.append({"Flow Duration": float(index * 100 + rng.normal(0, 2)),
                         "Total Fwd Packets": float(index * 10 + rng.normal(0, 1)),
                         "Flow Bytes/s": float(index * 1000 + rng.normal(0, 10)),
                         "Flow ID": f"flow-{len(rows)}", "Timestamp": "2026-10-30 10:00:00"})
            labels.append(label)
    return pd.DataFrame(rows), labels

def test_train_predict_save_reload_and_contract(tmp_path):
    x, y = sample_data()
    agent = ThreatDetectionAgent().fit(x, y)
    result = agent.predict(x.iloc[0].to_dict())
    assert isinstance(result, ThreatDetectionResult)
    assert result.predicted_class in CLASSES and 0 <= result.confidence <= 1
    assert result.status == "success"
    assert agent.model.feature_columns == ["Flow Duration", "Total Fwd Packets", "Flow Bytes/s"]
    path = tmp_path / "agent1.joblib"
    agent.save(path)
    restored = ThreatDetectionAgent.load(path)
    assert restored.predict(x.iloc[0].to_dict()).predicted_class == result.predicted_class

def test_batch_output_has_required_fields():
    x, y = sample_data()
    result = ThreatDetectionModel(n_estimators=25).fit(x, y).predict_frame(x.iloc[:2])
    assert set(result[0]) == {"agent", "predicted_class", "confidence", "status"}
    assert result[0]["agent"] == "threat_detection"

def test_training_requires_all_five_classes():
    x, y = sample_data()
    with pytest.raises(ValueError, match="all five"):
        ThreatDetectionModel(n_estimators=10).fit(x.iloc[:-12], y[:-12])

def test_mapping_does_not_guess_original_attack_names():
    with pytest.raises(ValueError, match="organiser mapping"):
        load_label_mapping(None, ["BENIGN", "FTP-Patator"])

def test_explicit_mapping_is_checked(tmp_path):
    path = tmp_path / "map.json"
    path.write_text(json.dumps({"BENIGN": "BENIGN", "Original-Label": "BRUTE_FORCE"}))
    assert load_label_mapping(path, ["BENIGN", "Original-Label"])["Original-Label"] == "BRUTE_FORCE"

def test_metrics_report_all_classes():
    result = evaluate_predictions(CLASSES, CLASSES)
    assert result["accuracy"] == 1.0 and result["macro_f1"] == 1.0
    assert list(result["per_class"]) == CLASSES
    assert len(result["confusion_matrix"]) == 5


def test_record_id_is_excluded_from_classifier_features():
    frame = pd.DataFrame({
        "record_id": [1, 2, 3],
        "Flow Duration": [100, 200, 300],
        "Flow ID": ["a", "b", "c"],
    })
    features = numeric_features(frame)
    assert "record_id" not in features.columns
    assert "Flow Duration" in features.columns


def test_validation_temperature_calibration_is_persisted(tmp_path):
    x, y = sample_data()
    agent = ThreatDetectionAgent().fit(x, y)
    assert agent.model.metadata["confidence_calibrated"] is False
    metrics = agent.model.calibrate_confidence(x, y)
    assert metrics["temperature"] > 0
    assert agent.model.metadata["confidence_calibrated"] is True
    prediction = agent.predict(x.iloc[0].to_dict())
    assert 0.0 <= prediction.confidence <= 1.0
    artifact = tmp_path / "calibrated.joblib"
    agent.save(artifact)
    restored = ThreatDetectionAgent.load(artifact)
    assert restored.model.calibration_temperature == agent.model.calibration_temperature
    assert restored.model.metadata["confidence_calibrated"] is True

def test_organizer_replay_metadata_is_not_a_supervised_feature():
    frame = pd.DataFrame({
        "seq": [1, 2, 3],
        "day": ["2017-07-04"] * 3,
        "time_offset": ["00:49.8", "02:14.1", "02:39.9"],
        "source_ip": ["192.168.10.12", "192.168.10.5", "192.168.10.17"],
        "destination_ip": ["192.168.10.3"] * 3,
        "source_port": [51001, 51002, 51003],
        "destination_port": [80, 443, 22],
        "protocol": [6, 6, 6],
        "Destination Port": [80, 443, 22],
        "Flow Duration": [100, 200, 300],
    })
    features = numeric_features(frame)
    assert list(features.columns) == ["Destination Port", "Flow Duration"]
    assert "destination_port" not in features.columns
    assert "seq" not in features.columns
    assert "protocol" not in features.columns
