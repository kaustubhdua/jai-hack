"""Stable serialisable contracts shared by the agents."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal

BenchmarkClass = Literal["BENIGN", "BRUTE_FORCE", "DOS", "DDOS", "PORT_SCAN"]
AgentStatus = Literal["success", "error", "not_ready"]
PolicyAction = Literal["ALLOW", "BLOCK", "REVIEW"]


@dataclass
class ThreatDetectionResult:
    predicted_class: BenchmarkClass | None
    confidence: float | None
    status: AgentStatus = "success"
    agent: str = "threat_detection"
    model_version: str | None = None
    message: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def __getitem__(self, key: str) -> Any:
        return getattr(self, key)


@dataclass
class AnomalyDetectionResult:
    anomaly_score: float | None
    is_anomaly: bool | None
    evidence: list[Any] = field(default_factory=list)
    status: AgentStatus = "success"
    agent: str = "anomaly_detection"
    message: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def __getitem__(self, key: str) -> Any:
        return getattr(self, key)


@dataclass
class FusionResult:
    final_class: BenchmarkClass | None
    evidence_status: Literal["AGREE", "DISAGREE", "INCOMPLETE"]
    action: PolicyAction
    agent_agreement: str = "AGREE"
    confidence: float | None = None
    rationale: list[str] = field(default_factory=list)
    supporting_evidence: list[Any] = field(default_factory=list)
    threat_detection: ThreatDetectionResult | None = None
    anomaly_detection: AnomalyDetectionResult | None = None
    latency_ms: float | None = None
    execution_status: str = "success"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def __getitem__(self, key: str) -> Any:
        return getattr(self, key)
