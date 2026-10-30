# CyberSentinel: System Architecture

**Project:** JAI 2026 | Track 1: Agentic AI for Cybersecurity  
**Author / Responsibility:** Team Lead & Product Integrator (`feature/fusion-integration`)  

---

## 1. High-Level System Overview

CyberSentinel is an offline network-flow intrusion detection and adaptive defense system. It deploys three coordinated agents to evaluate CICIDS2017 flow data:

```
[ Incoming Network Flow ]
          │
          ├───► Agent 1 (Threat Detection) ───► [ Class + Confidence ] ──┐
          │                                                               │
          └───► Agent 2 (Anomaly Detection) ──► [ Anomaly Score + Evid ] ─┼──► Agent 3 (Evidence Fusion)
                                                                          │        │
                                                                          │        ▼
                                                                          └─► [ Final Simulated Action:
                                                                                ALLOW / BLOCK / REVIEW ]
```

### Team Responsibilities & Ownership
- **Teammate 1 (Data Engineering):** Parquet dataset inspection, train-fitted preprocessor, data hygiene reports (`src/cybersentinel/data/cleaning.py`, `docs/data-intelligence.md`).
- **Teammate 2 (Supervised Threat Detection):** Agent 1 multiclass Random Forest classifier, 5 benchmark classes (`src/cybersentinel/agents/threat_detection/`, `docs/AGENT1.md`).
- **Teammate 3 (Anomaly Detection):** Agent 2 unsupervised baseline scoring and feature attribution (`src/cybersentinel/agents/anomaly_detection.py`).
- **Team Lead & Integrator (Self):**
  - Agent 3: Evidence Fusion (`src/cybersentinel/agents/fusion.py`)
  - End-to-end Pipeline Orchestration (`src/cybersentinel/pipeline.py`)
  - Stable Data Contracts (`src/cybersentinel/contracts.py`)
  - Complete Holdout Evaluation & Metrics (`reports/model_evaluation.md`, `reports/metrics.json`, `reports/confusion_matrix.png`)
  - FastAPI Serverless API (`api/index.py`)
  - React/TypeScript SOC Console (`src/App.tsx`)
  - Supabase Database Contracts & RLS (`supabase/schema.sql`)
  - Vercel Deployment & System Testing (`tests/`)

---

## 2. Shared Data Contracts (`src/cybersentinel/contracts.py`)

All agents communicate exclusively through typed, serializable dataclasses:

### `ThreatDetectionResult`
```python
@dataclass
class ThreatDetectionResult:
    predicted_class: BenchmarkClass | None
    confidence: float | None
    status: AgentStatus = "success"
    agent: str = "threat_detection"
    model_version: str | None = None
    message: str | None = None
```

### `AnomalyDetectionResult`
```python
@dataclass
class AnomalyDetectionResult:
    anomaly_score: float | None
    is_anomaly: bool | None
    evidence: list[Any] = field(default_factory=list)
    status: AgentStatus = "success"
    agent: str = "anomaly_detection"
    message: str | None = None
```

### `FusionResult`
```python
@dataclass
class FusionResult:
    final_class: BenchmarkClass | None
    evidence_status: Literal["AGREE", "DISAGREE", "INCOMPLETE"]
    action: PolicyAction  # ALLOW, BLOCK, REVIEW
    agent_agreement: str
    confidence: float | None = None
    rationale: list[str] = field(default_factory=list)
    supporting_evidence: list[Any] = field(default_factory=list)
    threat_detection: ThreatDetectionResult | None = None
    anomaly_detection: AnomalyDetectionResult | None = None
    latency_ms: float | None = None
    execution_status: str = "success"
```

---

## 3. Orchestration Layer (`src/cybersentinel/pipeline.py`)

The pipeline execution satisfies:
1. **Input Validation:** Verifies dictionary structure and non-empty payload.
2. **Independent Agent Dispatch:** Runs Agent 1 and Agent 2 without cross-talk or coupling.
3. **Consensus & Evidence Fusion:** Passes both outputs to Agent 3.
4. **Latency Measurement:** Tracks exact inference latency in milliseconds per flow.
5. **Fail-Safe Operation:** Catches unexpected agent errors and returns structured `INCOMPLETE` results rather than unhandled server crashes.
