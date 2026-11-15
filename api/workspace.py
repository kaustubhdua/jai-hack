"""Local analyst workspace API for dataset import, experiments, detection and exports.

All uploaded data and artifacts remain on the local filesystem. Vercel's
serverless filesystem is ephemeral; persistent work must run on a local host.
"""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
import re
from typing import Any
from uuid import uuid4

import pandas as pd
from fastapi import APIRouter, File, HTTPException, UploadFile
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from cybersentinel.data.adapters import DATASET_PROFILES, load_dataset
from cybersentinel.experiments.pipeline import ExperimentConfig, train_experiment, evaluate_cross_dataset
from cybersentinel.experiments.store import ExperimentStore
from cybersentinel.integrations.logs import load_zeek_conn, load_suricata_eve, load_wazuh_alerts, load_sigma_rule

router = APIRouter(prefix="/api/workspace", tags=["Analyst Workspace"])
ROOT = Path(__file__).resolve().parent.parent
WORKSPACE = Path(tempfile.gettempdir()) / "cybersentinel-workspace" if os.environ.get("VERCEL") == "1" else ROOT / "data" / "workspace"
UPLOADS = WORKSPACE / "uploads"
MODELS = WORKSPACE / "models"
REPORTS = WORKSPACE / "reports"
for directory in (UPLOADS, MODELS, REPORTS):
    directory.mkdir(parents=True, exist_ok=True)
STORE = ExperimentStore(WORKSPACE / "experiments.sqlite3")
MAX_UPLOAD_BYTES = 100 * 1024 * 1024
ALLOWED_SUFFIXES = {".csv", ".parquet", ".pq", ".feather", ".arrow"}


def _require_local_workspace() -> None:
    if os.environ.get("VERCEL") == "1":
        raise HTTPException(status_code=403, detail="Uploads and training are disabled on the public serverless demo. Run the API locally for a private persistent workspace.")


def _dataset_path(dataset_id: str) -> Path:
    if not re.fullmatch(r"[0-9a-f]{32}", dataset_id):
        raise HTTPException(status_code=400, detail="Invalid dataset identifier.")
    matches = [UPLOADS / f"{dataset_id}{suffix}" for suffix in ALLOWED_SUFFIXES if (UPLOADS / f"{dataset_id}{suffix}").is_file()]
    if len(matches) != 1 or not matches[0].is_file():
        raise HTTPException(status_code=404, detail="Dataset not found in this local workspace.")
    return matches[0]


def _load_uploaded_dataset(dataset_id: str):
    path = _dataset_path(dataset_id)
    metadata_path = UPLOADS / f"{dataset_id}.json"
    dataset_type = "auto"
    if metadata_path.is_file():
        try:
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            dataset_type = metadata.get("manifest", {}).get("dataset_type", metadata.get("source", "auto"))
        except (OSError, json.JSONDecodeError, AttributeError):
            dataset_type = "auto"
    if dataset_type not in DATASET_PROFILES:
        dataset_type = "auto"
    return load_dataset(path, dataset_type)


def _dataset_manifest(dataset_id: str, bundle):
    manifest = bundle.manifest()
    metadata_path = UPLOADS / f"{dataset_id}.json"
    if metadata_path.is_file():
        try:
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            manifest["provenance"] = metadata.get("manifest", {}).get("provenance", {})
        except (OSError, json.JSONDecodeError, AttributeError):
            manifest["provenance"] = {}
    return manifest


def _profile(path: Path, dataset_type: str = "auto", label_column: str | None = None):
    bundle = load_dataset(path, dataset_type, label_column)
    frame = bundle.frame
    schema = []
    for column in frame.columns:
        series = frame[column]
        schema.append({
            "name": str(column), "dtype": str(series.dtype),
            "missing": int(series.isna().sum()),
            "missing_fraction": round(float(series.isna().mean()), 6),
            "unique": int(series.nunique(dropna=True)),
            "numeric": bool(pd.api.types.is_numeric_dtype(series)),
        })
    labels = None
    if bundle.label_column:
        counts = frame[bundle.label_column].astype("string").fillna("<MISSING>").value_counts()
        labels = {str(key): int(value) for key, value in counts.items()}
    return bundle, {
        "dataset_type": bundle.dataset_type, "rows": bundle.rows,
        "columns": len(bundle.columns), "numeric_columns": int(len(frame.select_dtypes(include="number").columns)),
        "duplicate_rows": int(frame.duplicated().sum()), "label_column": bundle.label_column,
        "label_distribution": labels, "schema": schema,
        "sha256": bundle.source_sha256, "warnings": bundle.warnings,
        "normalized_columns": bundle.normalized_columns,
    }


class TrainRequest(BaseModel):
    dataset_id: str
    label_column: str = "label"
    model: str = Field(default="random_forest", pattern="^(random_forest|xgboost|isolation_forest|pytorch_mlp)$")
    feature_columns: list[str] | None = None
    drop_columns: list[str] | None = None
    label_mapping: dict[str, str] | None = None
    random_state: int = 42
    n_estimators: int = Field(default=300, ge=10, le=2000)
    max_depth: int | None = Field(default=None, ge=1, le=100)
    contamination: float = Field(default=0.02, gt=0, le=0.5)
    torch_epochs: int = Field(default=20, ge=1, le=500)


class EvaluateRequest(BaseModel):
    experiment_id: int = Field(gt=0)
    dataset_id: str
    label_column: str = "label"
    label_mapping: dict[str, str] | None = None


@router.post("/datasets")
async def upload_dataset(
    file: UploadFile = File(...), dataset_type: str = "auto",
    source_url: str = "", licence: str = "", retrieval_date: str = "", citation: str = "",
):
    _require_local_workspace()
    suffix = Path(file.filename or "").suffix.casefold()
    if suffix not in ALLOWED_SUFFIXES:
        raise HTTPException(status_code=415, detail="Upload CSV, Parquet, or Feather/Arrow files only.")
    dataset_id = uuid4().hex
    target = UPLOADS / f"{dataset_id}{suffix}"
    size = 0
    try:
        with target.open("wb") as output:
            while chunk := await file.read(1024 * 1024):
                size += len(chunk)
                if size > MAX_UPLOAD_BYTES:
                    raise HTTPException(status_code=413, detail="Dataset exceeds the 100 MB upload limit.")
                output.write(chunk)
        bundle, profile = _profile(target, dataset_type)
        metadata = {
            "dataset_id": dataset_id, "original_filename": Path(file.filename or "dataset").name,
            "bytes": size, "path": str(target), "manifest": {
                **bundle.manifest(),
                "provenance": {"source_url": source_url, "licence": licence,
                               "retrieval_date": retrieval_date, "citation": citation},
            },
            "profile": profile,
        }
        (UPLOADS / f"{dataset_id}.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
        return {"dataset_id": dataset_id, "filename": metadata["original_filename"], **profile}
    except HTTPException:
        target.unlink(missing_ok=True)
        raise
    except Exception as exc:
        target.unlink(missing_ok=True)
        raise HTTPException(status_code=422, detail=f"Dataset could not be imported: {type(exc).__name__}: {exc}") from exc
    finally:
        await file.close()


@router.get("/datasets")
def list_datasets():
    items = []
    for metadata_path in UPLOADS.glob("*.json"):
        try:
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            items.append({key: metadata.get(key) for key in ("dataset_id", "original_filename", "bytes", "profile")})
        except (OSError, json.JSONDecodeError):
            continue
    return {"datasets": sorted(items, key=lambda item: item["dataset_id"] or "", reverse=True)}


@router.get("/datasets/{dataset_id}/profile")
def dataset_profile(dataset_id: str):
    path = _dataset_path(dataset_id)
    metadata_path = UPLOADS / f"{dataset_id}.json"
    if metadata_path.is_file():
        return json.loads(metadata_path.read_text(encoding="utf-8"))["profile"]
    _, profile = _profile(path)
    return profile


@router.post("/train")
def train(request: TrainRequest):
    _require_local_workspace()
    path = _dataset_path(request.dataset_id)
    bundle = _load_uploaded_dataset(request.dataset_id)
    dataset_manifest = _dataset_manifest(request.dataset_id, bundle)
    config = ExperimentConfig(
        model=request.model, label_column=request.label_column,
        feature_columns=request.feature_columns, drop_columns=request.drop_columns,
        label_mapping=request.label_mapping, random_state=request.random_state,
        n_estimators=request.n_estimators, max_depth=request.max_depth,
        contamination=request.contamination, torch_epochs=request.torch_epochs,
    )
    experiment_key = uuid4().hex
    output = MODELS / experiment_key
    try:
        manifest = train_experiment(bundle.frame, config, output, dataset_manifest)
        experiment_id = STORE.add(experiment_key, "COMPLETED", manifest)
        manifest["experiment_id"] = experiment_id
        manifest["experiment_key"] = experiment_key
        report_path = REPORTS / f"{experiment_key}.json"
        report_path.write_text(json.dumps(manifest, indent=2, default=str), encoding="utf-8")
        return manifest
    except Exception as exc:
        STORE.add(experiment_key, "FAILED", {"error": f"{type(exc).__name__}: {exc}"})
        raise HTTPException(status_code=422, detail=f"Training failed: {type(exc).__name__}: {exc}") from exc


@router.get("/experiments")
def list_experiments(limit: int = 50):
    try:
        return {"experiments": STORE.list(limit)}
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


def _experiment_model(experiment_id: int) -> tuple[Path, dict[str, Any]]:
    for row in STORE.list(200):
        if row["id"] == experiment_id:
            if row["status"] != "COMPLETED":
                break
            key = row["name"]
            model = MODELS / key / "model.joblib"
            if model.is_file():
                return model, row
            break
    raise HTTPException(status_code=404, detail="Experiment model not found in this local workspace.")


@router.post("/evaluate")
def evaluate(request: EvaluateRequest):
    _require_local_workspace()
    model_path, experiment = _experiment_model(request.experiment_id)
    target_bundle = _load_uploaded_dataset(request.dataset_id)
    training_hash = (
        experiment.get("manifest", {}).get("dataset", {}).get("source_sha256")
        if isinstance(experiment.get("manifest"), dict) else None
    )
    if training_hash and training_hash == target_bundle.source_sha256:
        raise HTTPException(
            status_code=422,
            detail="Cross-dataset evaluation requires a different source dataset; this file was used to train the selected experiment.",
        )
    target = target_bundle.frame
    try:
        report = evaluate_cross_dataset(model_path, target, request.label_column, request.label_mapping)
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"Cross-dataset evaluation failed: {type(exc).__name__}: {exc}") from exc
    report.update({
        "experiment_id": request.experiment_id, "target_dataset_id": request.dataset_id,
        "target_dataset_manifest": _dataset_manifest(request.dataset_id, target_bundle),
    })
    report_path = REPORTS / f"cross-eval-{request.experiment_id}-{request.dataset_id}.json"
    report_path.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    import hashlib
    report["report_sha256"] = hashlib.sha256(report_path.read_bytes()).hexdigest()
    STORE.add(f"cross-eval:{request.experiment_id}:{request.dataset_id}", "COMPLETED", report)
    report["export"] = f"/api/workspace/exports/{report_path.name}"
    return report


@router.post("/detect/{experiment_id}")
def detect(experiment_id: int, dataset_id: str):
    _require_local_workspace()
    import joblib
    model_path, _ = _experiment_model(experiment_id)
    bundle = joblib.load(model_path)
    frame = _load_uploaded_dataset(dataset_id).frame
    features = bundle["features"]
    missing = sorted(set(features) - set(frame.columns))
    if missing:
        raise HTTPException(status_code=422, detail={"message": "Dataset is missing model features.", "missing_features": missing})
    X = frame[features].apply(pd.to_numeric, errors="coerce").replace([float("inf"), float("-inf")], float("nan"))
    estimator = bundle["estimator"]
    # Preserve useful source context in every prediction/alert export. Without
    # this, an analyst could see an alert count but not identify the event row.
    context_columns = [
        "id", "flow_id", "record_id", "timestamp", "stime",
        "source_ip", "destination_ip", "source_port", "destination_port",
        "protocol", "event_type", "signature", "signature_id", "severity",
        "rule_id", "rule_level", "agent_id", "agent_name",
    ]
    context_columns = [column for column in context_columns if column in frame.columns]
    result = frame[context_columns].copy()
    result.insert(0, "row_index", range(len(frame)))
    if bundle["config"]["model"] == "isolation_forest":
        raw = estimator.predict(X)
        score = -estimator.decision_function(X)
        result["prediction"] = ["ANOMALY" if value == -1 else "NORMAL" for value in raw]
        result["anomaly_score"] = score
    else:
        predictions = estimator.predict(X)
        result["prediction"] = predictions.astype(str)
        if hasattr(estimator, "predict_proba"):
            probabilities = estimator.predict_proba(X)
            result["confidence"] = probabilities.max(axis=1)
    benign_labels = {"BENIGN", "NORMAL", "LEGITIMATE", "0", "FALSE", "ALLOW"}
    alerts = result[~result["prediction"].astype(str).str.upper().isin(benign_labels)].copy()

    # Neutralize spreadsheet formulas in untrusted source context before CSV
    # export; keep numeric negative values numeric and unchanged.
    def _safe_cell(value):
        if isinstance(value, str) and value.lstrip().startswith(("=", "+", "@", "-")):
            return "'" + value
        return value

    for column in result.select_dtypes(include=["object", "string"]).columns:
        result[column] = result[column].map(_safe_cell)
    alerts = result[~result["prediction"].astype(str).str.upper().isin(benign_labels)].copy()

    output = REPORTS / f"detections-{experiment_id}-{dataset_id}.csv"
    alert_output = REPORTS / f"alerts-{experiment_id}-{dataset_id}.csv"
    result.to_csv(output, index=False)
    alerts.to_csv(alert_output, index=False)
    STORE.add(f"detection:{experiment_id}:{dataset_id}", "COMPLETED", {
        "rows": len(result), "alerts": len(alerts),
        "predictions_export": str(output), "alerts_export": str(alert_output),
    })
    return {
        "experiment_id": experiment_id, "rows": len(result), "alerts": len(alerts),
        "alert_preview": json.loads(alerts.head(100).to_json(orient="records")),
        "predictions": json.loads(result.head(100).to_json(orient="records")),
        "export": f"/api/workspace/exports/{output.name}",
        "alerts_export": f"/api/workspace/exports/{alert_output.name}",
    }


@router.post("/integrations/{source}")
async def ingest_open_source_telemetry(source: str, file: UploadFile = File(...)):
    """Convert supported Zeek, Suricata, Wazuh logs into a local dataset."""
    _require_local_workspace()
    suffix = Path(file.filename or "").suffix.casefold()
    temp_id = uuid4().hex
    temp_path = UPLOADS / f"{temp_id}{suffix}"
    try:
        raw = await file.read(MAX_UPLOAD_BYTES + 1)
        if len(raw) > MAX_UPLOAD_BYTES:
            raise HTTPException(status_code=413, detail="Telemetry file exceeds the 100 MB upload limit.")
        temp_path.write_bytes(raw)
        source = source.casefold()
        if source == "sigma":
            if suffix not in {".yml", ".yaml"}:
                raise HTTPException(status_code=415, detail="Sigma import requires a YAML rule file.")
            return load_sigma_rule(temp_path)
        if source == "zeek":
            frame = load_zeek_conn(temp_path)
        elif source == "suricata":
            frame = load_suricata_eve(temp_path)
        elif source == "wazuh":
            frame = load_wazuh_alerts(temp_path)
        else:
            raise HTTPException(status_code=404, detail="Supported integrations: zeek, suricata, wazuh, sigma.")
        if frame.empty:
            raise HTTPException(status_code=422, detail="No telemetry records were found.")
        dataset_id = uuid4().hex
        output = UPLOADS / f"{dataset_id}.csv"
        frame.to_csv(output, index=False)
        import hashlib
        profile = {
            "dataset_type": source, "rows": len(frame), "columns": len(frame.columns),
            "numeric_columns": len(frame.select_dtypes(include="number").columns),
            "label_column": None, "label_distribution": None,
            "sha256": hashlib.sha256(output.read_bytes()).hexdigest(),
            "warnings": ["Telemetry was ingested as event data; it is not a labelled benchmark dataset."],
        }
        metadata = {"dataset_id": dataset_id, "original_filename": Path(file.filename or source).name,
                    "bytes": output.stat().st_size, "path": str(output), "profile": profile,
                    "source": source}
        (UPLOADS / f"{dataset_id}.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
        return {"dataset_id": dataset_id, **profile}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"Could not ingest {source} telemetry: {type(exc).__name__}: {exc}") from exc
    finally:
        temp_path.unlink(missing_ok=True)
        await file.close()


@router.get("/exports/{filename}")
def export_report(filename: str):
    clean = Path(filename).name
    if clean != filename or not re.fullmatch(r"[A-Za-z0-9_.-]+", clean):
        raise HTTPException(status_code=400, detail="Invalid export filename.")
    path = REPORTS / clean
    if not path.is_file():
        raise HTTPException(status_code=404, detail="Export not found.")
    media = "text/csv" if path.suffix == ".csv" else "application/json"
    return FileResponse(path, media_type=media, filename=clean)
