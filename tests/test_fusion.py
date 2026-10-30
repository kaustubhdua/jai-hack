"""Automated tests for Agent 3 Evidence Fusion Agent."""
import pytest
from cybersentinel.agents.fusion import EvidenceFusionAgent
from cybersentinel.contracts import ThreatDetectionResult, AnomalyDetectionResult


def test_fusion_both_agree_attack():
    fusion = EvidenceFusionAgent()
    threat = ThreatDetectionResult(predicted_class="DOS", confidence=0.95, status="success")
    anomaly = AnomalyDetectionResult(anomaly_score=-0.15, is_anomaly=True, evidence=["unusual_packet_rate"], status="success")

    res = fusion.fuse(threat, anomaly)
    assert res.action == "BLOCK"
    assert res.final_class == "DOS"
    assert res.evidence_status == "AGREE"
    assert res.agent_agreement == "ATTACK_CONFIRMED"


def test_fusion_both_agree_benign():
    fusion = EvidenceFusionAgent()
    threat = ThreatDetectionResult(predicted_class="BENIGN", confidence=0.90, status="success")
    anomaly = AnomalyDetectionResult(anomaly_score=0.12, is_anomaly=False, evidence=[], status="success")

    res = fusion.fuse(threat, anomaly)
    assert res.action == "ALLOW"
    assert res.final_class == "BENIGN"
    assert res.evidence_status == "AGREE"
    assert res.agent_agreement == "BENIGN_CONFIRMED"


def test_fusion_disagree_attack_without_anomaly_high_confidence():
    fusion = EvidenceFusionAgent()
    threat = ThreatDetectionResult(predicted_class="BRUTE_FORCE", confidence=0.94, status="success")
    anomaly = AnomalyDetectionResult(anomaly_score=0.05, is_anomaly=False, evidence=[], status="success")

    res = fusion.fuse(threat, anomaly)
    assert res.action == "BLOCK"
    assert res.final_class == "BRUTE_FORCE"
    assert res.evidence_status == "DISAGREE"
    assert res.agent_agreement == "SUPERVISED_ATTACK_UNSUPERVISED_NORMAL"


def test_fusion_disagree_attack_without_anomaly_moderate_confidence():
    fusion = EvidenceFusionAgent()
    threat = ThreatDetectionResult(predicted_class="PORT_SCAN", confidence=0.72, status="success")
    anomaly = AnomalyDetectionResult(anomaly_score=0.05, is_anomaly=False, evidence=[], status="success")

    res = fusion.fuse(threat, anomaly)
    assert res.action == "REVIEW"
    assert res.evidence_status == "DISAGREE"


def test_fusion_disagree_benign_with_anomaly_zero_day():
    fusion = EvidenceFusionAgent()
    threat = ThreatDetectionResult(predicted_class="BENIGN", confidence=0.88, status="success")
    anomaly = AnomalyDetectionResult(anomaly_score=-0.25, is_anomaly=True, evidence=["abnormal_flow_duration"], status="success")

    res = fusion.fuse(threat, anomaly)
    assert res.action == "REVIEW"
    assert res.evidence_status == "DISAGREE"
    assert res.agent_agreement == "POTENTIAL_ZERO_DAY"
    assert "POTENTIAL ZERO-DAY" in " ".join(res.rationale).upper() or "ZERO-DAY" in " ".join(res.rationale).upper()


def test_fusion_low_confidence():
    fusion = EvidenceFusionAgent()
    threat = ThreatDetectionResult(predicted_class="DOS", confidence=0.45, status="success")
    anomaly = AnomalyDetectionResult(anomaly_score=-0.15, is_anomaly=True, evidence=[], status="success")

    res = fusion.fuse(threat, anomaly)
    assert res.action == "REVIEW"
    assert res.agent_agreement == "LOW_CONFIDENCE"


def test_fusion_failure_handling():
    fusion = EvidenceFusionAgent()
    # A1 fails
    threat_err = ThreatDetectionResult(predicted_class=None, confidence=None, status="error", message="Timeout")
    anomaly_ok = AnomalyDetectionResult(anomaly_score=-0.10, is_anomaly=True, evidence=["unusual_packet_rate"], status="success")
    res1 = fusion.fuse(threat_err, anomaly_ok)
    assert res1.evidence_status == "INCOMPLETE"
    assert res1.action == "REVIEW"

    # Both fail
    anomaly_err = AnomalyDetectionResult(anomaly_score=None, is_anomaly=None, evidence=[], status="error")
    res2 = fusion.fuse(threat_err, anomaly_err)
    assert res2.evidence_status == "INCOMPLETE"
    assert res2.action == "REVIEW"
    assert res2.agent_agreement == "BOTH_FAILED"
