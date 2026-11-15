from fastapi.testclient import TestClient

from api import workspace
from api.index import app
from cybersentinel.experiments.store import ExperimentStore


def test_local_workspace_upload_train_evaluate_detect_and_export(tmp_path, monkeypatch):
    monkeypatch.delenv("VERCEL", raising=False)
    uploads = tmp_path / "uploads"
    models = tmp_path / "models"
    reports = tmp_path / "reports"
    for directory in (uploads, models, reports):
        directory.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(workspace, "UPLOADS", uploads)
    monkeypatch.setattr(workspace, "MODELS", models)
    monkeypatch.setattr(workspace, "REPORTS", reports)
    monkeypatch.setattr(workspace, "STORE", ExperimentStore(tmp_path / "experiments.sqlite3"))

    training_csv = (
        "attack_cat,label,sbytes,sttl,source_ip\\n"
        "Normal,0,10,64,192.0.2.1\\n"
        "Normal,0,12,62,192.0.2.2\\n"
        "DoS,1,100,32,198.51.100.1\\n"
        "DoS,1,110,30,198.51.100.2\\n"
        "Normal,0,14,60,192.0.2.3\\n"
        "DoS,1,120,28,198.51.100.3\\n"
    )
    target_csv = (
        "attack_cat,label,sbytes,sttl,source_ip\\n"
        "Normal,0,15,61,=1+1\\n"
        "Normal,0,17,59,192.0.2.12\\n"
        "DoS,1,130,27,198.51.100.11\\n"
        "DoS,1,140,25,198.51.100.12\\n"
        "Normal,0,19,57,192.0.2.13\\n"
        "DoS,1,150,23,198.51.100.13\\n"
    )
    client = TestClient(app)
    uploaded = client.post(
        "/api/workspace/datasets",
        data={"dataset_type": "unsw-nb15"},
        files={"file": ("unsw-train.csv", training_csv.encode(), "text/csv")},
    )
    assert uploaded.status_code == 200, uploaded.text
    training_id = uploaded.json()["dataset_id"]
    assert uploaded.json()["label_distribution"] == {"Normal": 3, "DoS": 3}

    trained = client.post(
        "/api/workspace/train",
        json={"dataset_id": training_id, "label_column": "label", "model": "random_forest", "n_estimators": 10},
    )
    assert trained.status_code == 200, trained.text
    experiment = trained.json()
    assert "source_label" not in experiment["features"]
    experiment_id = experiment["experiment_id"]

    in_sample = client.post(
        "/api/workspace/evaluate",
        json={"experiment_id": experiment_id, "dataset_id": training_id, "label_column": "label"},
    )
    assert in_sample.status_code == 422
    assert "different source dataset" in in_sample.json()["detail"]

    target_upload = client.post(
        "/api/workspace/datasets",
        data={"dataset_type": "unsw-nb15"},
        files={"file": ("unsw-target.csv", target_csv.encode(), "text/csv")},
    )
    assert target_upload.status_code == 200, target_upload.text
    target_id = target_upload.json()["dataset_id"]

    evaluated = client.post(
        "/api/workspace/evaluate",
        json={"experiment_id": experiment_id, "dataset_id": target_id, "label_column": "label"},
    )
    assert evaluated.status_code == 200, evaluated.text
    assert evaluated.json()["rows"] == 6
    assert len(evaluated.json()["report_sha256"]) == 64

    detected = client.post(f"/api/workspace/detect/{experiment_id}?dataset_id={target_id}")
    assert detected.status_code == 200, detected.text
    assert detected.json()["rows"] == 6
    assert detected.json()["predictions"][0]["source_ip"] == "'=1+1"
    assert detected.json()["export"].startswith("/api/workspace/exports/")

    exported = client.get(detected.json()["export"])
    assert exported.status_code == 200
    assert "prediction" in exported.text
