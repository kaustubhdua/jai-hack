# CyberSentinel: API Specification

**Service:** FastAPI Serverless Endpoint (`api/index.py`)  
**Deployment Target:** Vercel Python Functions  

---

## Endpoints Summary

### 1. `GET /api/health`
Returns service status, model artifact readiness, and individual agent availability.

**Response:**
```json
{
  "status": "ok",
  "service": "CyberSentinel API",
  "version": "1.0.0",
  "model_ready": true,
  "mode": "offline-replay",
  "agents": {
    "agent_1_threat_detection": true,
    "agent_2_anomaly_detection": true,
    "agent_3_evidence_fusion": true
  },
  "message": "Operational"
}
```

---

### 2. `GET /api/models/status`
Returns metadata describing loaded models, backend types, feature counts, and thresholds.

**Response:**
```json
{
  "status": "ready",
  "models_ready": true,
  "agents": {
    "threat_detection": {
      "name": "Threat Detection Agent",
      "role": "Supervised 5-class classification",
      "backend": "random_forest",
      "classes": ["BENIGN", "BRUTE_FORCE", "DOS", "DDOS", "PORT_SCAN"],
      "feature_count": 71,
      "training_rows": 456737
    },
    "anomaly_detection": {
      "name": "Anomaly Detection Agent",
      "role": "Unsupervised baseline deviation scoring",
      "algorithm": "IsolationForest",
      "threshold": -0.0232,
      "benign_training_rows": 240000
    },
    "evidence_fusion": {
      "name": "Evidence Fusion Agent",
      "role": "Deterministic policy & explainable actions",
      "simulated_actions": ["ALLOW", "BLOCK", "REVIEW"],
      "confidence_threshold": 0.85
    }
  }
}
```

---

### 3. `POST /api/analyze`
Executes single flow analysis across all three agents.

**Request:**
```json
{
  "flow": {
    "Destination Port": 80,
    "Flow Duration": 1500,
    "Total Fwd Packets": 4,
    "Flow Packets/s": 2666.6
  }
}
```

**Response (200 OK):**
```json
{
  "final_class": "BENIGN",
  "evidence_status": "AGREE",
  "action": "ALLOW",
  "agent_agreement": "BENIGN_CONFIRMED",
  "confidence": 0.8235,
  "rationale": [
    "Dual agent consensus: Flow classified as BENIGN (confidence 0.82).",
    "Agent 2 verified traffic within normal baseline parameters (anomaly score 0.1591).",
    "Policy action: Simulated ALLOW permitted."
  ],
  "supporting_evidence": [],
  "threat_detection": {
    "predicted_class": "BENIGN",
    "confidence": 0.8235,
    "status": "success",
    "agent": "threat_detection",
    "model_version": "1",
    "message": null
  },
  "anomaly_detection": {
    "anomaly_score": 0.1591,
    "is_anomaly": false,
    "evidence": [],
    "status": "success",
    "agent": "anomaly_detection",
    "message": null
  },
  "latency_ms": 1.25,
  "execution_status": "success"
}
```

---

### 4. `POST /api/analyze/batch`
Batch flow inference with summary statistics (max 1000 flows).

**Request:**
```json
{
  "flows": [
    { "Destination Port": 80, "Flow Duration": 12000, "Total Fwd Packets": 4 },
    { "Destination Port": 4444, "Flow Duration": 200, "Total Fwd Packets": 1 }
  ]
}
```

---

### 5. `GET /api/metrics`
Official holdout evaluation metrics and confusion matrix.

---

### 6. `GET /api/dataset/summary`
Dataset partitions and class distribution figures.
