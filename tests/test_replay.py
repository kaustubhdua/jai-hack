import pandas as pd
import pytest
from pathlib import Path

from cybersentinel.replay import ReplayEngine
from cybersentinel.agents.correlation import TemporalCorrelationAgent
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
    assert results["replay_rows"][0]["active_policy_id"] == "NONE"

    # Flow 102: Second attack flow from same source -> BLOCKED by active policy!
    assert results["replay_rows"][1]["record_id"] == 102
    assert results["replay_rows"][1]["action"] == "BLOCK"
    assert results["replay_rows"][1]["active_policy_id"].startswith("POL-")

    # Flow 103 & 104: Benign flows from different source -> ALLOWED!
    assert results["replay_rows"][2]["action"] == "ALLOW"
    assert results["replay_rows"][3]["action"] == "ALLOW"

    # Verify CSV files export
    sub_files = engine.generate_submission_files(df, output_dir=tmp_path)
    assert sub_files["classification"].is_file()
    assert sub_files["policies"].is_file()
    assert sub_files["replay"].is_file()

    # Check header conformity
    class_header = sub_files["classification"].read_text().splitlines()[0]
    assert class_header == "record_id,predicted_class,anomaly_score,evidence_status"

    policy_header = sub_files["policies"].read_text().splitlines()[0]
    assert policy_header == "policy_id,activated_after_record_id,scope_type,scope_value,expires_after_record_id"

    replay_header = sub_files["replay"].read_text().splitlines()[0]
    assert replay_header == "record_id,action,active_policy_id"



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
    assert result["classification_rows"][0]["evidence_status"] == "UNCERTAIN"
    assert result["replay_rows"][0]["action"] == "ALLOW"
    assert result["policy_rows"] == []


def test_replay_never_creates_policy_from_fingerprint_metadata():
    engine = ReplayEngine(DummyThreatAgent(), DummyAnomalyAgent())
    fingerprint = {
        "Init_Win_bytes_forward": 64240,
        "min_seg_size_forward": 20,
        "Fwd Header Length": 40,
    }
    df = pd.DataFrame([
        {"record_id": 1, "Destination Port": 80, **fingerprint},
        {"record_id": 2, "Destination Port": 80, **fingerprint},
    ])
    result = engine.run_replay(df)
    assert TemporalCorrelationAgent.derive_source_identity(fingerprint) == ""
    assert result["policy_rows"] == []
    assert [row["action"] for row in result["replay_rows"]] == ["ALLOW", "ALLOW"]
    assert [row["active_policy_id"] for row in result["replay_rows"]] == ["NONE", "NONE"]


def test_replay_uses_day_and_minute_second_offsets_for_temporal_correlation():
    engine = ReplayEngine(DummyThreatAgent(), DummyAnomalyAgent())
    df = pd.DataFrame([
        {"record_id": "F000001", "seq": 1, "source_ip": "192.0.2.1", "destination_ip": "198.51.100.1",
         "Destination Port": 443, "day": "2017-07-04", "time_offset": "00:49.8"},
        {"record_id": "F000002", "seq": 2, "source_ip": "192.0.2.1", "destination_ip": "198.51.100.1",
         "Destination Port": 8443, "day": "2017-07-04", "time_offset": "02:14.1"},
    ])
    engine.run_replay(df)
    timestamps = [item["timestamp"] for item in engine.correlation_agent.history]
    assert timestamps[0] is not None
    assert timestamps[1] is not None
    assert (timestamps[1] - timestamps[0]).total_seconds() == pytest.approx(84.3)


def test_replay_rejects_non_monotonic_organizer_seq():
    engine = ReplayEngine(DummyThreatAgent(), DummyAnomalyAgent())
    df = pd.DataFrame([
        {"record_id": "F000002", "seq": 2, "source_ip": "192.0.2.1", "Destination Port": 80},
        {"record_id": "F000001", "seq": 1, "source_ip": "192.0.2.1", "Destination Port": 443},
    ])
    with pytest.raises(ValueError, match="Organizer seq"):
        engine.run_replay(df)
