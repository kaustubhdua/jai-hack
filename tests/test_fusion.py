from cybersentinel.agents.fusion import EvidenceFusionAgent
from cybersentinel.contracts import AnomalyDetectionResult, ThreatDetectionResult


def test_consensus_benign_allows_only_with_high_confidence():
    result = EvidenceFusionAgent().fuse(
        ThreatDetectionResult("BENIGN", 0.97),
        AnomalyDetectionResult(-0.2, False),
    )
    assert result.action == "ALLOW"
    assert result.evidence_status == "AGREE"


def test_consensus_attack_blocks_only_with_high_confidence():
    result = EvidenceFusionAgent().fuse(
        ThreatDetectionResult("DOS", 0.96),
        AnomalyDetectionResult(0.4, True),
    )
    assert result.action == "BLOCK"
    assert result.evidence_status == "AGREE"


def test_agent_disagreement_requires_review():
    result = EvidenceFusionAgent().fuse(
        ThreatDetectionResult("PORT_SCAN", 0.99),
        AnomalyDetectionResult(-0.3, False),
    )
    assert result.action == "REVIEW"
    assert result.evidence_status == "DISAGREE"


def test_incomplete_agent_evidence_fails_to_review():
    result = EvidenceFusionAgent().fuse(
        ThreatDetectionResult(None, None, status="error"),
        AnomalyDetectionResult(0.5, True),
    )
    assert result.action == "REVIEW"
    assert result.evidence_status == "INCOMPLETE"


def test_low_confidence_never_auto_allows_or_blocks():
    result = EvidenceFusionAgent().fuse(
        ThreatDetectionResult("BENIGN", 0.55),
        AnomalyDetectionResult(-0.1, False),
    )
    assert result.action == "REVIEW"
