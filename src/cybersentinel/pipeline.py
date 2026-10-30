"""Top-level orchestration pipeline for CyberSentinel."""
from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Any, List

from cybersentinel.contracts import FusionResult, ThreatDetectionResult, AnomalyDetectionResult
from cybersentinel.agents.threat_detection import ThreatDetectionAgent
from cybersentinel.agents.anomaly_detection import AnomalyDetectionAgent
from cybersentinel.agents.fusion import EvidenceFusionAgent

logger = logging.getLogger("cybersentinel.pipeline")

_DEFAULT_PIPELINE: CyberSentinelPipeline | None = None


class CyberSentinelPipeline:
    """End-to-end multi-agent detection and defense orchestration pipeline."""

    def __init__(
        self,
        threat_agent: ThreatDetectionAgent | Any,
        anomaly_agent: AnomalyDetectionAgent | Any,
        fusion_agent: EvidenceFusionAgent | Any,
        preprocessor: Any = None,
    ) -> None:
        self.threat_agent = threat_agent
        self.anomaly_agent = anomaly_agent
        self.fusion_agent = fusion_agent
        self.preprocessor = preprocessor

    @classmethod
    def load_default(
        cls,
        threat_path: str | Path = "models/threat_detection/model.joblib",
        anomaly_path: str | Path = "models/anomaly_detection/model.joblib",
        prep_state_path: str | Path = "data/processed/preprocessing_state.json",
    ) -> "CyberSentinelPipeline":
        """Instantiate pipeline with available trained models and preprocessor."""
        threat_agent = (
            ThreatDetectionAgent.load(threat_path)
            if Path(threat_path).exists()
            else ThreatDetectionAgent()
        )
        anomaly_agent = (
            AnomalyDetectionAgent.load(anomaly_path)
            if Path(anomaly_path).exists()
            else AnomalyDetectionAgent()
        )
        fusion_agent = EvidenceFusionAgent()

        preprocessor = None
        if Path(prep_state_path).exists():
            try:
                from cybersentinel.data.cleaning import FlowPreprocessor
                preprocessor = FlowPreprocessor.load(Path(prep_state_path))
            except Exception:
                preprocessor = None

        return cls(threat_agent, anomaly_agent, fusion_agent, preprocessor)

    def analyze(self, flow: dict[str, Any]) -> FusionResult:
        """Analyze a single flow dictionary through all agents safely."""
        start_time = time.perf_counter()

        # 1. Validate input
        if not isinstance(flow, dict) or not flow:
            return self.fusion_agent.fuse(
                ThreatDetectionResult(None, None, status="error", message="Input flow is empty or not a dictionary"),
                AnomalyDetectionResult(None, None, status="error", message="Input flow is empty or not a dictionary"),
            )

        # 2. Run Agent 1 (Threat Detection) safely
        threat_output = None
        try:
            threat_output = self.threat_agent.predict(flow)
        except Exception as exc:
            logger.exception("Agent 1 execution failed")
            threat_output = ThreatDetectionResult(
                predicted_class=None,
                confidence=None,
                status="error",
                message=f"Agent 1 error: {exc}",
            )

        # 3. Run Agent 2 (Anomaly Detection) independently and safely
        anomaly_output = None
        try:
            anomaly_output = self.anomaly_agent.score(flow)
        except Exception as exc:
            logger.exception("Agent 2 execution failed")
            anomaly_output = AnomalyDetectionResult(
                anomaly_score=None,
                is_anomaly=None,
                evidence=[],
                status="error",
                message=f"Agent 2 error: {exc}",
            )

        # 4. Fuse outputs through Agent 3 (Evidence Fusion)
        try:
            result = self.fusion_agent.fuse(threat_output, anomaly_output)
        except Exception as exc:
            logger.exception("Agent 3 fusion failed")
            result = FusionResult(
                final_class=None,
                evidence_status="INCOMPLETE",
                action="REVIEW",
                agent_agreement="FUSION_ERROR",
                confidence=0.0,
                rationale=[f"Fusion agent failed: {exc}", "Simulated action defaulted to REVIEW."],
                threat_detection=threat_output,
                anomaly_detection=anomaly_output,
                execution_status="error",
            )

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0
        result.latency_ms = round(elapsed_ms, 4)
        return result

    def analyze_batch(self, flows: List[dict[str, Any]]) -> List[FusionResult]:
        """Process a sequence of flow records safely."""
        if not isinstance(flows, list):
            raise ValueError("Input flows must be a list of dictionaries")
        return [self.analyze(f) for f in flows]


def analyze_flow(network_flow: dict[str, Any]) -> FusionResult:
    """Convenience top-level entry point."""
    global _DEFAULT_PIPELINE
    if _DEFAULT_PIPELINE is None:
        _DEFAULT_PIPELINE = CyberSentinelPipeline.load_default()
    return _DEFAULT_PIPELINE.analyze(network_flow)
