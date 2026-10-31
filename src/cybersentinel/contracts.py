"""Stable serialisable contracts shared by the agents."""
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
    model_version: str | None = None
    message: str | None = None

@dataclass
class AnomalyDetectionResult:
    anomaly_score: float | None
    is_anomaly: bool | None
    evidence: list[dict[str, Any]] = field(default_factory=list)
    status: AgentStatus = "success"
    message: str | None = None

@dataclass
class FusionResult:
    final_class: BenchmarkClass | None
    evidence_status: Literal["AGREE", "CONFLICT", "UNCERTAIN"]
    action: PolicyAction
    rationale: list[str] = field(default_factory=list)
    agent_agreement: str | None = None
    confidence: float | None = None
    supporting_evidence: list[Any] = field(default_factory=list)
    threat_detection: ThreatDetectionResult | None = None
    anomaly_detection: AnomalyDetectionResult | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

@dataclass
class CorrelationGroup:
    group_id: str
    attack_type: str | None
    source_ip: str | None
    target_endpoints: list[str] = field(default_factory=list)
    member_record_ids: list[str | int] = field(default_factory=list)
    flow_count: int = 0
    start_record_id: str | int | None = None
    end_record_id: str | int | None = None
    confidence: float = 0.0
    evidence: list[str] = field(default_factory=list)

@dataclass
class CorrelationResult:
    correlated: bool
    group_id: str | None = None
    attack_type: str | None = None
    group_size: int = 0
    evidence: list[str] = field(default_factory=list)
    status: AgentStatus = "success"
    message: str | None = None

@dataclass
class DefensePolicy:
    policy_id: str
    activated_after_record_id: str | int
    scope_type: Literal["SOURCE_IP"] = "SOURCE_IP"
    scope_value: str = ""
    expires_after_record_id: str | int = 0
    policy_action: Literal["BLOCK"] = "BLOCK"
    reason: str = ""
    created_at_step: int = 0
    expires_step: int = 0

@dataclass
class DefenseDecision:
    record_id: str | int
    action: Literal["ALLOW", "BLOCK"]
    applied_policy_id: str | None = None
    is_pre_filtered: bool = False
    new_policy_created: DefensePolicy | None = None
    rationale: str = ""
