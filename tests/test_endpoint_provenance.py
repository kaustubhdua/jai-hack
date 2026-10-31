"""Regression tests for endpoint provenance in temporal correlation.

Dataset fingerprints and flow statistics are not network endpoint identities.
Only parseable, literal endpoint fields may be used for endpoint-scoped grouping.
"""
from cybersentinel.agents.correlation import TemporalCorrelationAgent


def test_source_identity_accepts_literal_ipv4_and_ipv6():
    assert TemporalCorrelationAgent.derive_source_identity({"source_ip": "192.0.2.7"}) == "192.0.2.7"
    assert TemporalCorrelationAgent.derive_source_identity({"src": "2001:db8::7"}) == "2001:db8::7"


def test_source_identity_rejects_invalid_or_fingerprint_only_metadata():
    fingerprint = {
        "source_ip": "not-an-ip",
        "Init_Win_bytes_forward": 64240,
        "min_seg_size_forward": 20,
        "Fwd Header Length": 40,
        "Destination Port": 443,
    }
    assert TemporalCorrelationAgent.derive_source_identity(fingerprint) == ""
    assert TemporalCorrelationAgent.has_observed_source_ip(fingerprint) is False


def test_missing_source_endpoint_fails_closed_for_correlation():
    agent = TemporalCorrelationAgent()
    result = agent.correlate(
        "flow-1",
        {
            "Init_Win_bytes_forward": 64240,
            "min_seg_size_forward": 20,
            "Fwd Header Length": 40,
            "Destination Port": 443,
        },
        threat_class="DDOS",
        confidence=0.99,
    )
    assert result.correlated is False
    assert result.status == "not_ready"
    assert len(agent.history) == 0
    assert not agent.source_port_map


def test_invalid_source_does_not_join_a_valid_source_campaign():
    agent = TemporalCorrelationAgent(window_size=20)
    for index, port in enumerate((21, 22, 23, 24, 25)):
        agent.correlate(
            f"valid-{index}",
            {"source_ip": "192.0.2.10", "Destination Port": port},
            threat_class="PORT_SCAN",
        )
    before = len(agent.history)
    result = agent.correlate(
        "invalid-source",
        {"source_ip": "192.0.2.999", "Destination Port": 3389},
        threat_class="PORT_SCAN",
    )
    assert result.correlated is False
    assert result.status == "not_ready"
    assert len(agent.history) == before
