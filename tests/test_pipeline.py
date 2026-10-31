import pytest

from cybersentinel.contracts import AnomalyDetectionResult, ThreatDetectionResult
from cybersentinel.pipeline import CyberSentinelPipeline


class ThreatAgent:
    def predict(self, flow):
        return ThreatDetectionResult("BENIGN", 0.98)


class AnomalyAgent:
    def score(self, flow):
        return AnomalyDetectionResult(-0.2, False, [])


class BrokenThreatAgent:
    def predict(self, flow):
        raise RuntimeError("model unavailable")


def test_pipeline_runs_both_agents_and_returns_timed_fusion():
    pipeline = CyberSentinelPipeline(ThreatAgent(), AnomalyAgent())
    result = pipeline.analyze({"Flow Duration": 120})
    assert result["final_class"] == "BENIGN"
    assert result["action"] == "ALLOW"
    assert result["evidence_status"] == "AGREE"
    assert result["latency_ms"] >= 0


def test_pipeline_fails_safely_when_one_agent_throws():
    pipeline = CyberSentinelPipeline(BrokenThreatAgent(), AnomalyAgent())
    result = pipeline.analyze({"Flow Duration": 120})
    assert result["action"] == "REVIEW"
    assert result["evidence_status"] == "UNCERTAIN"


def test_pipeline_rejects_missing_model_artifacts(tmp_path):
    with pytest.raises(FileNotFoundError, match="Required model artifact"):
        CyberSentinelPipeline.load_default(
            tmp_path / "missing-agent1.joblib",
            tmp_path / "missing-agent2.joblib",
        )


def test_invalid_flow_returns_serialized_review_result():
    pipeline = CyberSentinelPipeline(ThreatAgent(), AnomalyAgent())
    result = pipeline.analyze({})
    assert result["action"] == "REVIEW"
    assert result["evidence_status"] == "UNCERTAIN"
    assert "latency_ms" in result
