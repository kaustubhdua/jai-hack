from cybersentinel.agents.correlation import TemporalCorrelationAgent


def test_endpoint_extraction():
    agent = TemporalCorrelationAgent()
    flow = {
        "source_ip": "192.168.1.100",
        "destination_ip": "10.0.0.1",
        "Destination Port": 80,
    }
    src, dst, port = agent.extract_endpoints(flow)
    assert src == "192.168.1.100"
    assert dst == "10.0.0.1"
    assert port == 80


def test_tcp_stack_fingerprint_does_not_become_an_endpoint_identity():
    agent = TemporalCorrelationAgent()
    flow = {
        "Init_Win_bytes_forward": 64240,
        "min_seg_size_forward": 20,
        "Fwd Header Length": 40,
        "Destination Port": 443,
        "Flow Duration": 50000,
    }
    src, dst, port = agent.extract_endpoints(flow)
    assert src == ""
    assert dst == ""
    assert port == 443
    result = agent.correlate("F000001", flow, threat_class="DOS", confidence=0.99)
    assert result.status == "not_ready"
    assert result.correlated is False


def test_identical_tcp_fingerprints_share_the_same_synthetic_identity():
    first = {"Init_Win_bytes_forward": 64240, "min_seg_size_forward": 20, "Fwd Header Length": 40}
    second = {"Init_Win_bytes_forward": 64240, "min_seg_size_forward": 20, "Fwd Header Length": 40}
    assert TemporalCorrelationAgent.derive_source_identity(first) == TemporalCorrelationAgent.derive_source_identity(second)


def test_missing_source_identity_fails_closed():
    agent = TemporalCorrelationAgent()
    flow = {"Destination Port": 443, "Flow Duration": 50000, "Total Fwd Packets": 10}
    src, dst, port = agent.extract_endpoints(flow)
    assert src == ""
    assert dst == ""
    assert port == 443
    result = agent.correlate("rec-unknown", flow, threat_class="DOS")
    assert result.correlated is False
    assert result.status == "not_ready"


def test_port_scan_correlation():
    agent = TemporalCorrelationAgent(window_size=50)
    src_ip = "192.168.1.50"

    # Simulate single source scanning 6 different ports
    result = None
    for i, port in enumerate([21, 22, 80, 443, 8080, 3389]):
        flow = {
            "source_ip": src_ip,
            "destination_ip": "10.0.0.5",
            "Destination Port": port,
        }
        result = agent.correlate(record_id=f"rec-{i}", flow=flow)

    assert result is not None
    assert result.correlated is True
    assert result.attack_type == "PORT_SCAN"
    assert result.group_id is not None
    assert "probed" in result.evidence[0]


def test_brute_force_correlation():
    agent = TemporalCorrelationAgent(window_size=50)
    src_ip = "192.168.1.75"

    result = None
    for i in range(5):
        flow = {
            "source_ip": src_ip,
            "destination_ip": "10.0.0.10",
            "Destination Port": 22,
        }
        result = agent.correlate(record_id=f"rec-{i}", flow=flow, threat_class="BRUTE_FORCE")

    assert result is not None
    assert result.correlated is True
    assert result.attack_type == "BRUTE_FORCE"
    assert "authentication flows" in result.evidence[0]



def test_ddos_convergence_requires_observed_destination_identity():
    agent = TemporalCorrelationAgent(window_size=50)
    result = None
    for index in range(12):
        flow = {
            "Init_Win_bytes_forward": 64000 + index,
            "min_seg_size_forward": 20,
            "Fwd Header Length": 40,
            "Destination Port": 80,
        }
        result = agent.correlate(f"record-{index}", flow, threat_class="DDOS")
    assert result is not None
    assert result.correlated is False


def test_timestamp_window_evicts_old_flows_by_elapsed_time():
    agent = TemporalCorrelationAgent(window_size=100, window_seconds=60)
    for index, port in enumerate([21, 22, 23, 24]):
        agent.correlate(
            f"old-{index}",
            {"source_ip": "192.0.2.10", "Destination Port": port,
             "Timestamp": f"2026-10-31T10:00:{index:02d}Z"},
            threat_class="PORT_SCAN",
        )
    result = agent.correlate(
        "new-flow",
        {"source_ip": "192.0.2.10", "Destination Port": 443,
         "Timestamp": "2026-10-31T10:05:00Z"},
        threat_class="PORT_SCAN",
    )
    assert result.correlated is False
    assert len(agent.history) == 1


def test_repeated_benign_ssh_flows_do_not_become_brute_force_campaigns():
    agent = TemporalCorrelationAgent(window_size=50)
    result = None
    for index in range(6):
        result = agent.correlate(
            f"benign-ssh-{index}",
            {"source_ip": "192.0.2.44", "destination_ip": "192.0.2.10", "Destination Port": 22},
            threat_class="BENIGN",
        )
    assert result is not None
    assert result.correlated is False


def test_many_benign_web_clients_do_not_become_ddos_without_classifier_evidence():
    agent = TemporalCorrelationAgent(window_size=50)
    result = None
    for index in range(10):
        result = agent.correlate(
            f"web-{index}",
            {"source_ip": f"192.0.2.{index + 1}", "destination_ip": "198.51.100.10", "Destination Port": 443},
            threat_class="BENIGN",
        )
    assert result is not None
    assert result.correlated is False


def test_ddos_destination_convergence_requires_attack_classifier_evidence():
    agent = TemporalCorrelationAgent(window_size=50)
    for index in range(7):
        agent.correlate(
            f"benign-web-{index}",
            {"source_ip": f"203.0.113.{index + 1}", "destination_ip": "198.51.100.20", "Destination Port": 443},
            threat_class="BENIGN",
        )
    result = agent.correlate(
        "suspected-ddos",
        {"source_ip": "203.0.113.8", "destination_ip": "198.51.100.20", "Destination Port": 443},
        threat_class="DDOS",
    )
    assert result.correlated is True
    assert result.attack_type == "DDOS"

def test_invalid_destination_ip_is_not_used_as_correlation_endpoint():
    agent = TemporalCorrelationAgent()
    result = agent.correlate(
        "bad-destination",
        {"source_ip": "192.0.2.10", "destination_ip": "not-an-ip", "Destination Port": "443"},
        threat_class="BENIGN",
    )
    assert result.status == "success"
    assert result.correlated is False
    assert agent.dest_source_map == {}


def test_invalid_destination_port_is_safely_ignored():
    src, dst, port = TemporalCorrelationAgent.extract_endpoints({
        "source_ip": "192.0.2.10",
        "destination_ip": "198.51.100.20",
        "Destination Port": "not-a-port",
    })
    assert src == "192.0.2.10"
    assert dst == "198.51.100.20"
    assert port == 0


def test_non_ip_source_or_destination_cannot_create_endpoint_group():
    agent = TemporalCorrelationAgent()
    result = agent.correlate(
        "bad-source",
        {"source_ip": "client-fingerprint-123", "destination_ip": "198.51.100.20", "Destination Port": 443},
        threat_class="DOS",
    )
    assert result.status == "not_ready"
    assert result.correlated is False
