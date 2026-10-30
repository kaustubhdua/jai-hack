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


def test_anomaly_score_contract_is_raw_and_evidence_is_structured():
    agent = AnomalyDetectionAgent().fit(benign_sample())
    assert agent.metadata["score_is_probability"] is False
    assert "decision_function" in agent.metadata["score_definition"]
    outlier = {"Destination Port": 65500, "Flow Duration": 9_000_000,
               "Total Fwd Packets": 50000, "Flow Packets/s": 900000,
               "Flow Bytes/s": 90000000}
    result = agent.score(outlier)
    assert result.is_anomaly is True
    assert result.evidence
    assert isinstance(result.evidence[0], dict)
    assert {"feature", "observed_value", "baseline_q01", "baseline_q99"}.issubset(result.evidence[0])
