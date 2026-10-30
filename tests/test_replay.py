import pandas as pd
import pytest
from pathlib import Path

from cybersentinel.replay import ReplayEngine
from cybersentinel.contracts import ThreatDetectionResult, AnomalyDetectionResult


class DummyThreatAgent:
    def predict(self, flow):
        dport = int(flow.get("Destination Port", 0))
        if dport == 80:
            return ThreatDetectionResult(predicted_class="DOS", confidence=0.98)
        return ThreatDetectionResult(predicted_class="BENIGN", confidence=0.99)


class DummyAnomalyAgent:
    def score(self, flow):
        dport = int(flow.get("Destination Port", 0))
        return AnomalyDetectionResult(
            anomaly_score=0.85 if dport == 80 else 0.01,
            is_anomaly=dport == 80,
            evidence=[{"feature": "Destination Port", "value": dport}],
        )


def test_replay_causal_workflow(tmp_path):
    engine = ReplayEngine(
        threat_agent=DummyThreatAgent(),
        anomaly_agent=DummyAnomalyAgent(),
    )

    # 4 flows: 2 attack flows from 1.1.1.1, then 2 benign from 2.2.2.2
    data = [
        {"record_id": 101, "source_ip": "1.1.1.1", "Destination Port": 80, "label": "DOS"},
        {"record_id": 102, "source_ip": "1.1.1.1", "Destination Port": 80, "label": "DOS"},
        {"record_id": 103, "source_ip": "2.2.2.2", "Destination Port": 443, "label": "BENIGN"},
        {"record_id": 104, "source_ip": "2.2.2.2", "Destination Port": 443, "label": "BENIGN"},
    ]
    df = pd.DataFrame(data)

    results = engine.run_replay(df)

    assert len(results["classification_rows"]) == 4
    assert len(results["replay_rows"]) == 4

    # Rate names must use their correct denominators.
    assert results["metrics"]["attack_records"] == 2
    assert results["metrics"]["attacks_contained"] == 1
    assert results["metrics"]["containment_rate"] == 50.0
    assert results["metrics"]["block_precision"] == 100.0
    assert results["metrics"]["benign_preservation_rate"] == 100.0

    # Flow 101: First attack flow -> ALLOW into analyzer, activates policy
    assert results["replay_rows"][0]["record_id"] == 101
    assert results["replay_rows"][0]["action"] == "ALLOW"
    assert results["replay_rows"][0]["applied_policy_id"] == ""

    # Flow 102: Second attack flow from same source -> BLOCKED by active policy!
    assert results["replay_rows"][1]["record_id"] == 102
    assert results["replay_rows"][1]["action"] == "BLOCK"
    assert results["replay_rows"][1]["applied_policy_id"].startswith("POL-")

    # Flow 103 & 104: Benign flows from different source -> ALLOWED!
    assert results["replay_rows"][2]["action"] == "ALLOW"
    assert results["replay_rows"][3]["action"] == "ALLOW"

    # Verify CSV files export
    sub_files = engine.generate_submission_files(df, output_dir=tmp_path)
    assert sub_files["classification"].is_file()
    assert sub_files["policy"].is_file()
    assert sub_files["replay"].is_file()

    # Check header conformity
    class_header = sub_files["classification"].read_text().splitlines()[0]
    assert class_header == "record_id,predicted_class,anomaly score,evidence status"

    policy_header = sub_files["policy"].read_text().splitlines()[0]
    assert policy_header == "policy_id,activated_after_record_id,scope_type,scope_value,expires_after_record_id,policy_action"

    replay_header = sub_files["replay"].read_text().splitlines()[0]
    assert replay_header == "record_id,action,applied_policy_id"



class BrokenThreatAgent:
    def predict(self, flow):
        return ThreatDetectionResult(predicted_class=None, confidence=None, status="error")


class BrokenAnomalyAgent:
    def score(self, flow):
        return AnomalyDetectionResult(anomaly_score=None, is_anomaly=None, status="error")


def test_replay_does_not_fabricate_benign_when_agents_fail():
    engine = ReplayEngine(BrokenThreatAgent(), BrokenAnomalyAgent())
    result = engine.run_replay(pd.DataFrame([{"record_id": 1, "source_ip": "192.0.2.1"}]))
    assert result["classification_rows"][0]["predicted_class"] == ""
    assert result["classification_rows"][0]["evidence status"] == "INCOMPLETE"
    assert result["replay_rows"][0]["action"] == "ALLOW"
    assert result["policy_rows"] == []


def test_replay_never_uses_fingerprint_identity_as_source_ip_policy():
    engine = ReplayEngine(DummyThreatAgent(), DummyAnomalyAgent())
    df = pd.DataFrame([{
        "record_id": 1, "Destination Port": 80,
        "Init_Win_bytes_forward": 64240,
        "min_seg_size_forward": 20,
        "Fwd Header Length": 40,
    }])
    result = engine.run_replay(df)
    assert result["policy_rows"] == []
