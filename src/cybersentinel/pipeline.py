"""Fault-tolerant orchestration for the three CyberSentinel agents."""
from __future__ import annotations

import logging
import time
from typing import Any

from cybersentinel.contracts import (
    AnomalyDetectionResult,
    FusionResult,
    ThreatDetectionResult,
)
from cybersentinel.agents.fusion import EvidenceFusionAgent

logger = logging.getLogger("cybersentinel.pipeline")


class CyberSentinelPipeline:
    """Run independent detectors and fuse their evidence for offline replay."""

    def __init__(self, threat_agent: Any, anomaly_agent: Any, fusion_agent: Any | None = None):
        self.threat_agent = threat_agent
        self.anomaly_agent = anomaly_agent
        self.fusion_agent = fusion_agent or EvidenceFusionAgent()

    def analyze(self, flow: dict[str, Any]) -> dict[str, Any]:
        started = time.perf_counter()
        if not isinstance(flow, dict) or not flow:
            return self.fusion_agent.fuse(
                ThreatDetectionResult(None, None, status="error", message="Flow must be a non-empty object."),
                AnomalyDetectionResult(None, None, status="error", message="Flow must be a non-empty object."),
            )

        try:
            threat = self.threat_agent.predict(flow)
        except Exception as exc:
            logger.exception("Threat detection agent failed")
            threat = ThreatDetectionResult(None, None, status="error", message=f"Threat agent unavailable: {type(exc).__name__}")

        try:
            anomaly = self.anomaly_agent.score(flow)
        except Exception as exc:
            logger.exception("Anomaly detection agent failed")
            anomaly = AnomalyDetectionResult(None, None, status="error", message=f"Anomaly agent unavailable: {type(exc).__name__}")

        try:
            result = self.fusion_agent.fuse(threat, anomaly)
        except Exception:
            logger.exception("Evidence fusion failed")
            result = FusionResult(
                final_class=None,
                evidence_status="INCOMPLETE",
                action="REVIEW",
                rationale=["Fusion failed safely; simulated action defaulted to REVIEW."],
                threat_detection=threat,
                anomaly_detection=anomaly,
            )

        # Latency is returned as an additive field without changing the shared contract.
        payload = result.to_dict()
        payload["latency_ms"] = round((time.perf_counter() - started) * 1000.0, 4)
        return payload

    def analyze_batch(self, flows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        if not isinstance(flows, list):
            raise ValueError("flows must be a list")
        return [self.analyze(flow) for flow in flows]
