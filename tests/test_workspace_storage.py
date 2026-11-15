import json

import pytest
from fastapi import HTTPException

from api import workspace


def test_dataset_resolver_ignores_metadata_json(tmp_path, monkeypatch):
    monkeypatch.setattr(workspace, "UPLOADS", tmp_path)
    dataset_id = "a" * 32
    data = tmp_path / f"{dataset_id}.csv"
    metadata = tmp_path / f"{dataset_id}.json"
    data.write_text("x,label\n1,ok\n", encoding="utf-8")
    metadata.write_text(json.dumps({"dataset_id": dataset_id}), encoding="utf-8")
    assert workspace._dataset_path(dataset_id) == data


def test_dataset_resolver_rejects_path_traversal():
    with pytest.raises(HTTPException) as error:
        workspace._dataset_path("../secret")
    assert error.value.status_code == 400


def test_public_serverless_workspace_writes_are_disabled(monkeypatch):
    monkeypatch.setenv("VERCEL", "1")
    with pytest.raises(HTTPException) as error:
        workspace._require_local_workspace()
    assert error.value.status_code == 403


def test_failed_experiment_cannot_be_used_for_inference(tmp_path, monkeypatch):
    from cybersentinel.experiments.store import ExperimentStore

    store = ExperimentStore(tmp_path / "experiments.sqlite3")
    experiment_id = store.add("failed-model", "FAILED", {"error": "training failed"})
    monkeypatch.setattr(workspace, "STORE", store)
    monkeypatch.setattr(workspace, "MODELS", tmp_path / "models")
    (tmp_path / "models" / "failed-model").mkdir(parents=True)
    (tmp_path / "models" / "failed-model" / "model.joblib").write_bytes(b"not-a-valid-model")

    with pytest.raises(HTTPException) as error:
        workspace._experiment_model(experiment_id)
    assert error.value.status_code == 404
