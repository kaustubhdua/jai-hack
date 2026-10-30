"""Agent 1 — Threat Detection Agent module."""
from cybersentinel.agents.threat_detection.model import BENCHMARK_CLASSES, ThreatDetectionModel
from cybersentinel.agents.threat_detection.predict import ThreatDetectionAgent

__all__ = ["BENCHMARK_CLASSES", "ThreatDetectionModel", "ThreatDetectionAgent"]
