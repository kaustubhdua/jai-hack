"""Automated tests for pipeline and FastAPI API endpoints."""
import pytest
from fastapi.testclient import TestClient

from cybersentinel.pipeline import analyze_flow
from api.index import app


def test_analyze_flow_end_to_end():
    sample_flow = {
        "Destination Port": 80,
        "Flow Duration": 1500,
        "Total Fwd Packets": 5,
        "Flow Packets/s": 3333.3,
    }
    result = analyze_flow(sample_flow)
    assert result.final_class in ["BENIGN", "BRUTE_FORCE", "DOS", "DDOS", "PORT_SCAN"]
    assert result.action in ["ALLOW", "BLOCK", "REVIEW"]
    assert result.threat_detection is not None
    assert result.anomaly_detection is not None
    assert result.evidence_status in ["AGREE", "DISAGREE", "INCOMPLETE"]


def test_api_health():
    client = TestClient(app)
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ok"
    assert data["model_ready"] is True


def test_api_models_status():
    client = TestClient(app)
    res = client.get("/api/models/status")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ready"
    assert "threat_detection" in data["agents"]
    assert "anomaly_detection" in data["agents"]


def test_api_metrics():
    client = TestClient(app)
    res = client.get("/api/metrics")
    assert res.status_code == 200
    data = res.json()
    assert "agent_1_threat_detection" in data
    assert data["agent_1_threat_detection"]["overall_accuracy"] > 0.99


def test_api_dataset_summary():
    client = TestClient(app)
    res = client.get("/api/dataset/summary")
    assert res.status_code == 200
    data = res.json()
    assert data["partitions"]["training_rows"] == 456737
    assert data["partitions"]["eval_rows"] == 114185


def test_api_analyze_single():
    client = TestClient(app)
    flow = {"Destination Port": 80, "Flow Duration": 12000, "Total Fwd Packets": 4}
    res = client.post("/api/analyze", json={"flow": flow})
    assert res.status_code == 200
    data = res.json()
    assert "final_class" in data
    assert data["action"] in ["ALLOW", "BLOCK", "REVIEW"]


def test_api_analyze_batch():
    client = TestClient(app)
    flow1 = {"Destination Port": 80, "Flow Duration": 12000, "Total Fwd Packets": 4}
    flow2 = {"Destination Port": 4444, "Flow Duration": 200, "Total Fwd Packets": 1}
    res = client.post("/api/analyze/batch", json={"flows": [flow1, flow2]})
    assert res.status_code == 200
    data = res.json()
    assert data["total_analyzed"] == 2
    assert "summary" in data
