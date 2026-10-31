"""Robustness and boundary condition tests for CyberSentinel 5-Agent IDS Architecture.

Tests all five agents independently and in combination under edge conditions,
malformed inputs, infinite/NaN values, out-of-order events, and stress conditions.
"""
import math
import pytest
import pandas as pd
import numpy as np
from pathlib import Path

from cybersentinel.contracts import (
    AnomalyDetectionResult,
    DefenseDecision,
    DefensePolicy,
    FusionResult,
    ThreatDetectionResult,
)
from cybersentinel.agents.threat_detection import ThreatDetectionAgent
from cybersentinel.agents.anomaly_detection import AnomalyDetectionAgent
from cybersentinel.agents.fusion import EvidenceFusionAgent
from cybersentinel.agents.correlation import TemporalCorrelationAgent
from cybersentinel.agents.adaptive_defense import AdaptiveDefenseAgent


def load_model_or_skip(agent_class, artifact_path):
    """Model binaries are intentionally excluded from Git; test them when installed."""
    if not Path(artifact_path).is_file():
        pytest.skip(f"Local model artifact is not present in this checkout: {artifact_path}")
    return agent_class.load(artifact_path)


# ============================================================================
# AGENT 1: Robustness & BOUNDARY TESTS
# ============================================================================
class TestAgent1Robustness:
    def test_uninitialized_agent_raises_runtime_error(self):
        agent = ThreatDetectionAgent(model=None)
        with pytest.raises(RuntimeError, match="has no trained model"):
            agent.predict({"Flow Duration": 100})

    def test_infinite_and_nan_features_gracefully_imputed(self):
        agent = load_model_or_skip(ThreatDetectionAgent, "models/threat_detection/model.joblib")
        Robustness_flow = {
            "Destination Port": 80,
            "Flow Duration": float("inf"),
            "Total Fwd Packets": float("-inf"),
            "Flow Bytes/s": float("nan"),
            "Init_Win_bytes_forward": 8192,
        }
        res = agent.predict(Robustness_flow)
        assert res.status == "success"
        assert res.predicted_class in {"BENIGN", "BRUTE_FORCE", "DOS", "DDOS", "PORT_SCAN"}
        assert 0.0 <= res.confidence <= 1.0

    def test_feature_order_invariance(self):
        agent = load_model_or_skip(ThreatDetectionAgent, "models/threat_detection/model.joblib")
        cols = list(agent.model.feature_columns)
        rev_cols = list(reversed(cols))
        
        sample_dict_normal = {c: 1.0 for c in cols}
        sample_dict_reversed = {c: 1.0 for c in rev_cols}
        
        res1 = agent.predict(sample_dict_normal)
        res2 = agent.predict(sample_dict_reversed)
        assert res1.predicted_class == res2.predicted_class
        assert math.isclose(res1.confidence, res2.confidence, rel_tol=1e-5)

    def test_unknown_and_extraneous_features_ignored(self):
        agent = load_model_or_skip(ThreatDetectionAgent, "models/threat_detection/model.joblib")
        polluted_flow = {
            "Destination Port": 443,
            "ATTACKER_INJECTED_FLAG": "MALICIOUS",
            "EXPLOIT_PAYLOAD": 99999999,
            "SQLI_DETECT": True,
        }
        res = agent.predict(polluted_flow)
        assert res.status == "success"
        assert res.predicted_class in {"BENIGN", "BRUTE_FORCE", "DOS", "DDOS", "PORT_SCAN"}


# ============================================================================
# AGENT 2: Robustness & BOUNDARY TESTS
# ============================================================================
class TestAgent2Robustness:
    def test_empty_flow_returns_error_status(self):
        agent = load_model_or_skip(AnomalyDetectionAgent, "models/anomaly_detection/model.joblib")
        res = agent.score({})
        assert res.status == "error"
        assert res.anomaly_score is None

    def test_extreme_outlier_flow_flagged(self):
        agent = load_model_or_skip(AnomalyDetectionAgent, "models/anomaly_detection/model.joblib")
        # Extreme volumetric and packet length explosion
        wild_flow = {
            "Destination Port": 9999,
            "Flow Duration": 999999999,
            "Total Fwd Packets": 500000,
            "Total Length of Fwd Packets": 1000000000,
            "Flow Bytes/s": 999999999.0,
            "Packet Length Max": 65535,
        }
        res = agent.score(wild_flow)
        assert res.status == "success"
        assert res.is_anomaly is True
        assert len(res.evidence) > 0

    def test_anomaly_score_bounded_and_finite(self):
        agent = load_model_or_skip(AnomalyDetectionAgent, "models/anomaly_detection/model.joblib")
        res = agent.score({"Destination Port": 80, "Flow Duration": 500})
        assert res.status == "success"
        assert isinstance(res.anomaly_score, float)
        assert math.isfinite(res.anomaly_score)


# ============================================================================
# AGENT 3: EVIDENCE FUSION MATRIX COMPLIANCE TESTS
# ============================================================================
class TestAgent3FusionRobustness:
    def setup_method(self):
        self.fusion = EvidenceFusionAgent()

    def test_corroborated_attack_triggers_block(self):
        t = ThreatDetectionResult(predicted_class="DOS", confidence=0.95, status="success")
        a = AnomalyDetectionResult(anomaly_score=0.90, is_anomaly=True, status="success")
        f = self.fusion.fuse(t, a)
        assert f.action == "BLOCK"
        assert f.evidence_status == "AGREE"
        assert f.final_class == "DOS"

    def test_corroborated_benign_triggers_allow(self):
        t = ThreatDetectionResult(predicted_class="BENIGN", confidence=0.99, status="success")
        a = AnomalyDetectionResult(anomaly_score=0.10, is_anomaly=False, status="success")
        f = self.fusion.fuse(t, a)
        assert f.action == "ALLOW"
        assert f.evidence_status == "AGREE"
        assert f.final_class == "BENIGN"

    def test_disagreement_classifier_attack_anomaly_normal_routes_to_review(self):
        t = ThreatDetectionResult(predicted_class="PORT_SCAN", confidence=0.90, status="success")
        a = AnomalyDetectionResult(anomaly_score=0.05, is_anomaly=False, status="success")
        f = self.fusion.fuse(t, a)
        assert f.action == "REVIEW"
        assert f.evidence_status == "CONFLICT"

    def test_disagreement_classifier_benign_anomaly_outlier_routes_to_review(self):
        t = ThreatDetectionResult(predicted_class="BENIGN", confidence=0.90, status="success")
        a = AnomalyDetectionResult(anomaly_score=0.85, is_anomaly=True, status="success")
        f = self.fusion.fuse(t, a)
        assert f.action == "REVIEW"
        assert f.evidence_status == "CONFLICT"

    def test_incomplete_evidence_fails_closed_to_review(self):
        t = ThreatDetectionResult(predicted_class="DOS", confidence=0.95, status="error")
        a = AnomalyDetectionResult(anomaly_score=None, is_anomaly=None, status="error")
        f = self.fusion.fuse(t, a)
        assert f.action == "REVIEW"
        assert f.evidence_status == "UNCERTAIN"


# ============================================================================
# AGENT 4: TEMPORAL CORRELATION Robustness TESTS
# ============================================================================
class TestAgent4CorrelationRobustness:
    def setup_method(self):
        self.agent = TemporalCorrelationAgent(window_size=150)

    def test_port_scan_detection_across_distinct_ports(self):
        src = "192.168.1.50"
        # Sweep 6 different destination ports from same source
        for port in [21, 22, 23, 80, 443, 8080]:
            res = self.agent.correlate(
                record_id=f"rec-{port}",
                flow={"source_ip": src, "Destination Port": port, "Flow Duration": 10},
                threat_class="PORT_SCAN",
                confidence=0.85,
            )
        assert res.correlated is True
        assert res.attack_type == "PORT_SCAN"
        assert len(res.evidence) >= 1

    def test_window_pruning_drops_stale_history(self):
        agent = TemporalCorrelationAgent(window_size=5)
        for i in range(20):
            agent.correlate(
                record_id=i,
                flow={"source_ip": "10.0.0.1", "Destination Port": 80},
                threat_class="BENIGN",
            )
        assert len(agent.history) == 5

    def test_missing_endpoints_fail_closed_without_inventing_identity(self):
        # Empty flow must not become a fabricated host or destination.
        src, dst, port = self.agent.extract_endpoints({})
        assert src == ""
        assert dst == ""
        assert port == 0
        result = self.agent.correlate("missing-endpoints", {})
        assert result.correlated is False
        assert result.status == "not_ready"


# ============================================================================
# AGENT 5: ADAPTIVE DEFENSE & POLICY INVARIANT TESTS
# ============================================================================
class TestAgent5AdaptiveDefenseRobustness:
    def setup_method(self):
        self.defense = AdaptiveDefenseAgent(default_duration=150)

    def test_triggering_record_is_never_self_blocked(self):
        src = "192.168.1.100"
        # First flow triggers an attack detection
        pre = self.defense.evaluate_pre_filter(record_id=1, source_ip=src, current_step=0)
        assert pre is None  # No prior policy exists!

        post = self.defense.handle_post_analysis(
            record_id=1,
            source_ip=src,
            current_step=0,
            attack_detected=True,
            attack_type="DOS",
            confidence=0.95,
        )
        assert post.action == "ALLOW"
        assert post.applied_policy_id == ""
        assert post.new_policy_created is not None
        assert post.new_policy_created.activated_after_record_id == 1
        assert post.new_policy_created.expires_after_record_id == 150

    def test_subsequent_flow_is_pre_filtered_and_blocked(self):
        src = "192.168.1.100"
        # Trigger policy at step 0
        self.defense.handle_post_analysis(
            record_id=1, source_ip=src, current_step=0, attack_detected=True, attack_type="DOS"
        )

        # Subsequent flow arrives at step 1
        pre = self.defense.evaluate_pre_filter(record_id=2, source_ip=src, current_step=1)
        assert pre is not None
        assert pre.action == "BLOCK"
        assert pre.applied_policy_id == "POL-00001"
        assert pre.is_pre_filtered is True

    def test_policy_expires_after_configured_duration(self):
        src = "192.168.1.100"
        self.defense.handle_post_analysis(
            record_id=1, source_ip=src, current_step=0, attack_detected=True, attack_type="DOS", duration=10
        )

        # Active at step 10
        pre_10 = self.defense.evaluate_pre_filter(record_id=10, source_ip=src, current_step=10)
        assert pre_10 is not None
        assert pre_10.action == "BLOCK"

        # Expired at step 11
        pre_11 = self.defense.evaluate_pre_filter(record_id=11, source_ip=src, current_step=11)
        assert pre_11 is None  # Policy expired and pruned!

    def test_no_duplicate_policies_created_while_active(self):
        src = "192.168.1.100"
        # Step 0 triggers POL-00001
        self.defense.handle_post_analysis(
            record_id=1, source_ip=src, current_step=0, attack_detected=True, attack_type="DOS"
        )
        assert len(self.defense.all_policies) == 1

        # Step 1 also detects attack from same source while policy is still active
        self.defense.handle_post_analysis(
            record_id=2, source_ip=src, current_step=1, attack_detected=True, attack_type="DOS"
        )
        # Should NOT spawn duplicate policy!
        assert len(self.defense.all_policies) == 1
