import pandas as pd

from cybersentinel.agents.adaptive_defense import AdaptiveDefenseAgent
from cybersentinel.contracts import AnomalyDetectionResult, ThreatDetectionResult
from cybersentinel.replay import ReplayEngine


class AttackThreatAgent:
    def predict(self, flow):
        return ThreatDetectionResult(predicted_class="DOS", confidence=0.99, status="success")


class AttackAnomalyAgent:
    def score(self, flow):
        return AnomalyDetectionResult(anomaly_score=0.9, is_anomaly=True, evidence=[], status="success")


def test_final_replay_record_does_not_create_unusable_policy():
    engine = ReplayEngine(AttackThreatAgent(), AttackAnomalyAgent())
    frame = pd.DataFrame([{
        "record_id": "organizer-last",
        "source_ip": "192.0.2.5",
        "Destination Port": 443,
    }])
    result = engine.run_replay(frame)
    assert result["classification_rows"][0]["predicted_class"] == "DOS"
    assert result["replay_rows"][0]["action"] == "ALLOW"
    assert result["policy_rows"] == []


def test_policy_expiry_is_capped_to_last_later_record():
    engine = ReplayEngine(
        AttackThreatAgent(),
        AttackAnomalyAgent(),
        defense_agent=AdaptiveDefenseAgent(default_duration=150),
    )
    frame = pd.DataFrame([
        {"record_id": "alpha", "source_ip": "192.0.2.5", "Destination Port": 443},
        {"record_id": "beta", "source_ip": "192.0.2.5", "Destination Port": 443},
    ])
    result = engine.run_replay(frame)
    assert len(result["policy_rows"]) == 1
    policy = result["policy_rows"][0]
    assert policy["activated_after_record_id"] == "alpha"
    assert policy["expires_after_record_id"] == "beta"
    assert result["replay_rows"][1]["action"] == "BLOCK"
