"""Runtime smoke tests for the checked-in public benchmark model artifacts."""

from pathlib import Path

from cybersentinel.pipeline import CyberSentinelPipeline


ROOT = Path(__file__).resolve().parents[1]
THREAT_MODEL = ROOT / "models" / "threat_detection" / "model.joblib"
ANOMALY_MODEL = ROOT / "models" / "anomaly_detection" / "model.joblib"


def test_checked_in_models_load_and_run_real_inference():
    assert THREAT_MODEL.is_file(), "Agent 1 model artifact is missing from the repository."
    assert ANOMALY_MODEL.is_file(), "Agent 2 model artifact is missing from the repository."

    pipeline = CyberSentinelPipeline.load_default(THREAT_MODEL, ANOMALY_MODEL)

    assert pipeline.threat_agent.model is not None
    assert pipeline.anomaly_agent.estimator is not None
    assert pipeline.threat_agent.model.feature_columns
    assert pipeline.anomaly_agent.feature_columns

    # Exercise both serialized estimators with the exact feature contract.
    # Zero-valued measurements are a deterministic schema/load smoke input,
    # not a claimed representative network-flow sample.
    sample = {
        feature: 0.0
        for feature in pipeline.threat_agent.model.feature_columns
    }
    result = pipeline.analyze(sample)

    assert result["threat_detection"]["status"] == "success"
    assert result["threat_detection"]["predicted_class"] in {
        "BENIGN", "BRUTE_FORCE", "DOS", "DDOS", "PORT_SCAN"
    }
    assert result["anomaly_detection"]["status"] == "success"
    assert isinstance(result["anomaly_detection"]["is_anomaly"], bool)
    assert 0.0 <= result["anomaly_detection"]["anomaly_score"] <= 1.0
    assert result["action"] in {"ALLOW", "BLOCK", "REVIEW"}
