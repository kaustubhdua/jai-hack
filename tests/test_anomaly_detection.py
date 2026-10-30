"""Automated tests for Agent 2 Anomaly Detection."""
import numpy as np
import pandas as pd
import pytest

from cybersentinel.agents.anomaly_detection import AnomalyDetectionAgent
from cybersentinel.contracts import AnomalyDetectionResult


def sample_benign_flows():
    rng = np.random.default_rng(42)
    rows = []
    for _ in range(50):
        rows.append({
            "Destination Port": 80.0,
            "Flow Duration": float(rng.normal(1000, 100)),
            "Flow Packets/s": float(rng.normal(50, 10)),
            "Total Fwd Packets": float(rng.normal(5, 1)),
        })
    return pd.DataFrame(rows)


def test_anomaly_agent_fit_score_save_load(tmp_path):
    train_df = sample_benign_flows()
    agent = AnomalyDetectionAgent().fit(train_df)

    # Benign-like sample
    normal_sample = {"Destination Port": 80.0, "Flow Duration": 1000.0, "Flow Packets/s": 50.0, "Total Fwd Packets": 5.0}
    res_normal = agent.score(normal_sample)
    assert isinstance(res_normal, AnomalyDetectionResult)
    assert res_normal.status == "success"
    assert res_normal.anomaly_score is not None
    assert not res_normal.is_anomaly

    # Extreme outlier sample (severe anomaly)
    outlier_sample = {"Destination Port": 80.0, "Flow Duration": 9999999.0, "Flow Packets/s": 999999.0, "Total Fwd Packets": 50000.0}
    res_outlier = agent.score(outlier_sample)
    assert res_outlier.is_anomaly is True
    assert len(res_outlier.evidence) > 0

    # Save and reload
    save_path = tmp_path / "anomaly_model.joblib"
    agent.save(save_path)
    restored = AnomalyDetectionAgent.load(save_path)
    res_restored = restored.score(normal_sample)
    assert res_restored.status == "success"
    assert res_restored.anomaly_score == res_normal.anomaly_score


def test_anomaly_agent_invalid_input_handling():
    agent = AnomalyDetectionAgent()
    # Unloaded model
    res = agent.score({"Flow Duration": 100})
    assert res.status == "not_ready"

    # Empty dictionary
    agent.estimator = "mock"
    res_empty = agent.score({})
    assert res_empty.status == "error"
