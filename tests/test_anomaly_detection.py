import numpy as np
import pandas as pd

from cybersentinel.agents.anomaly_detection import AnomalyDetectionAgent


def benign_sample(rows=120):
    rng = np.random.default_rng(17)
    return pd.DataFrame({
        "Destination Port": np.full(rows, 443.0),
        "Flow Duration": rng.normal(1200, 80, rows),
        "Total Fwd Packets": rng.normal(8, 1.2, rows),
        "Flow Packets/s": rng.normal(45, 5, rows),
        "Flow Bytes/s": rng.normal(18000, 1800, rows),
    })


def test_fit_score_and_artifact_round_trip(tmp_path):
    agent = AnomalyDetectionAgent().fit(benign_sample())
    normal = {
        "Destination Port": 443,
        "Flow Duration": 1200,
        "Total Fwd Packets": 8,
        "Flow Packets/s": 45,
        "Flow Bytes/s": 18000,
    }
    result = agent.score(normal)
    assert result.status == "success"
    assert result.anomaly_score is not None
    assert isinstance(result.is_anomaly, bool)

    artifact = tmp_path / "anomaly.joblib"
    agent.save(artifact)
    restored = AnomalyDetectionAgent.load(artifact)
    again = restored.score(normal)
    assert again.status == "success"
    assert again.anomaly_score == result.anomaly_score


def test_outlier_returns_feature_evidence():
    agent = AnomalyDetectionAgent().fit(benign_sample())
    outlier = {
        "Destination Port": 65500,
        "Flow Duration": 9_000_000,
        "Total Fwd Packets": 50000,
        "Flow Packets/s": 900000,
        "Flow Bytes/s": 90000000,
    }
    result = agent.score(outlier)
    assert result.status == "success"
    assert result.is_anomaly is True
    assert result.anomaly_score is not None and 0.0 <= result.anomaly_score <= 1.0
    assert result.evidence


def test_untrained_agent_is_not_ready():
    result = AnomalyDetectionAgent().score({"Flow Duration": 1})
    assert result.status == "not_ready"
    assert result.is_anomaly is None


def test_empty_training_data_is_rejected():
    import pytest
    with pytest.raises(ValueError):
        AnomalyDetectionAgent().fit(pd.DataFrame())


def test_score_frame_vectorized():
    agent = AnomalyDetectionAgent().fit(benign_sample())
    df = benign_sample(rows=20)
    results = agent.score_frame(df)
    assert len(results) == 20
    assert all(r.status == "success" for r in results)
    assert all(isinstance(r.is_anomaly, bool) for r in results)


def test_anomaly_score_contract_is_bounded_and_evidence_is_structured():
    agent = AnomalyDetectionAgent().fit(benign_sample())
    assert agent.metadata["score_is_probability"] is False
    assert "range [0,1]" in agent.metadata["score_definition"]
    assert agent.score_scale is not None and agent.score_scale > 0
    normal_score = agent.score({"Destination Port": 443, "Flow Duration": 1200,
                                "Total Fwd Packets": 8, "Flow Packets/s": 45,
                                "Flow Bytes/s": 18000}).anomaly_score
    assert normal_score is not None and 0.0 <= normal_score <= 1.0
    outlier = {"Destination Port": 65500, "Flow Duration": 9_000_000,
               "Total Fwd Packets": 50000, "Flow Packets/s": 900000,
               "Flow Bytes/s": 90000000}
    result = agent.score(outlier)
    assert result.is_anomaly is True
    assert result.evidence
    assert isinstance(result.evidence[0], dict)
    assert {"feature", "observed_value", "baseline_q01", "baseline_q99"}.issubset(result.evidence[0])


def test_validation_threshold_calibration_respects_benign_fpr_limit():
    train = benign_sample(rows=300)
    agent = AnomalyDetectionAgent().fit(train)
    validation_benign = benign_sample(rows=80)
    validation_attack = pd.DataFrame({
        "Destination Port": np.full(20, 65500.0),
        "Flow Duration": np.full(20, 9_000_000.0),
        "Total Fwd Packets": np.full(20, 50000.0),
        "Flow Packets/s": np.full(20, 900000.0),
        "Flow Bytes/s": np.full(20, 90000000.0),
    })
    validation = pd.concat([validation_benign, validation_attack], ignore_index=True)
    labels = ["BENIGN"] * len(validation_benign) + ["DOS"] * len(validation_attack)
    metrics = agent.calibrate_threshold(validation, labels, max_benign_fpr=0.05)
    assert metrics["benign_false_positive_rate"] <= 0.05
    assert 0.0 <= metrics["attack_recall"] <= 1.0
    assert agent.metadata["threshold_selection_uses_labels"] is True
    assert agent.metadata["labels_used_during_scoring"] is False

def test_organizer_replay_metadata_is_not_an_anomaly_feature():
    from cybersentinel.agents.anomaly_detection import _numeric_frame

    frame = benign_sample(rows=5)
    frame["seq"] = [1, 2, 3, 4, 5]
    frame["day"] = ["2017-07-04"] * 5
    frame["time_offset"] = ["00:49.8", "02:14.1", "02:39.9", "05:49.2", "06:51.8"]
    frame["source_ip"] = ["192.168.10.12"] * 5
    frame["destination_ip"] = ["192.168.10.3"] * 5
    frame["source_port"] = [51001, 51002, 51003, 51004, 51005]
    frame["destination_port"] = [80, 443, 22, 21, 3389]
    frame["protocol"] = [6] * 5

    features = _numeric_frame(frame)
    assert set(features.columns) == {
        "Destination Port", "Flow Duration", "Total Fwd Packets",
        "Flow Packets/s", "Flow Bytes/s",
    }
