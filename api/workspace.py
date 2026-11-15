"""Local analyst workspace API for dataset import, experiments, detection and exports.

All uploaded data and artifacts remain on the local filesystem. Vercel's
serverless filesystem is ephemeral; persistent work must run on a local host.
"""
from __future__ import annotations

import json
from pathlib import Path
import re
from typing import Any
from uuid import uuid4

import pandas as pd
from fastapi import APIRouter, File, HTTPException, UploadFile
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from cybersentinel.data.adapters import load_dataset
from cybersentinel.experiments.pipeline import ExperimentConfig, train_experiment, evaluate_cross_dataset
from cybersentinel.experiments.store import ExperimentStore
from cybersentinel.integrations.logs import load_zeek_conn, load_suricata_eve, load_wazuh_alerts, load_sigma_rule

router = APIRouter(prefix="/api/workspace", tags=["Analyst Workspace"])
ROOT = Path(__file__).resolve().parent.parent
WORKSPACE = ROOT / "data" / "workspace"
UPLOADS = WORKSPACE / "uploads"
MODELS = WORKSPACE / "models"
REPORTS = WORKSPACE / "reports"
for directory in (UPLOADS, MODELS, REPORTS):
    directory.mkdir(parents=True, exist_ok=True)
STORE = ExperimentStore(WORKSPACE / "experiments.sqlite3")
MAX_UPLOAD_BYTES = 100 * 1024 * 1024
ALLOWED_SUFFIXES = {".csv", ".parquet", ".pq", ".feather", ".arrow"}


def _dataset_path(dataset_id: str) -> Path:
    if not re.fullmatch(r"[0-9a-f]{32}", dataset_id):
        raise HTTPException(status_code=400, detail="Invalid dataset identifier.")
    matches = [UPLOADS / f"{dataset_id}{suffix}" for suffix in ALLOWED_SUFFIXES if (UPLOADS / f"{dataset_id}{suffix}").is_file()]
    if len(matches) != 1 or not matches[0].is_file():
        raise HTTPException(status_code=404, detail="Dataset not found in this local workspace.")
    return matches[0]


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
    contamination: float = Field(default=0.02, gt=0, le=0.5)
    torch_epochs: int = Field(default=20, ge=1, le=500)


class EvaluateRequest(BaseModel):
    experiment_id: int = Field(gt=0)
    dataset_id: str
    label_column: str = "label"
    label_mapping: dict[str, str] | None = None


@router.post("/datasets")
async def upload_dataset(file: UploadFile = File(...), dataset_type: str = "auto"):
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
            "bytes": size, "path": str(target), "manifest": bundle.manifest(),
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
    path = _dataset_path(request.dataset_id)
    bundle = load_dataset(path)
    config = ExperimentConfig(
        model=request.model, label_column=request.label_column,
        feature_columns=request.feature_columns, drop_columns=request.drop_columns,
        label_mapping=request.label_mapping, random_state=request.random_state,
        n_estimators=request.n_estimators, contamination=request.contamination,
        torch_epochs=request.torch_epochs,
    )
    experiment_key = uuid4().hex
    output = MODELS / experiment_key
    try:
        manifest = train_experiment(bundle.frame, config, output, bundle.manifest())
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
            key = row["name"]
            model = MODELS / key / "model.joblib"
            if model.is_file():
                return model, row
            break
    raise HTTPException(status_code=404, detail="Experiment model not found in this local workspace.")


@router.post("/evaluate")
def evaluate(request: EvaluateRequest):
    model_path, experiment = _experiment_model(request.experiment_id)
    target = load_dataset(_dataset_path(request.dataset_id)).frame
    try:
        report = evaluate_cross_dataset(model_path, target, request.label_column, request.label_mapping)
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"Cross-dataset evaluation failed: {type(exc).__name__}: {exc}") from exc
    report.update({"experiment_id": request.experiment_id, "target_dataset_id": request.dataset_id})
    report_path = REPORTS / f"cross-eval-{request.experiment_id}-{request.dataset_id}.json"
    report_path.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    return report


@router.post("/detect/{experiment_id}")
def detect(experiment_id: int, dataset_id: str):
    import joblib
    model_path, _ = _experiment_model(experiment_id)
    bundle = joblib.load(model_path)
    frame = load_dataset(_dataset_path(dataset_id)).frame
    features = bundle["features"]
    missing = sorted(set(features) - set(frame.columns))
    if missing:
        raise HTTPException(status_code=422, detail={"message": "Dataset is missing model features.", "missing_features": missing})
    X = frame[features].apply(pd.to_numeric, errors="coerce").replace([float("inf"), float("-inf")], float("nan"))
    estimator = bundle["estimator"]
    if bundle["config"]["model"] == "isolation_forest":
        raw = estimator.predict(X)
        score = -estimator.decision_function(X)
        result = pd.DataFrame({"prediction": ["ANOMALY" if value == -1 else "NORMAL" for value in raw], "anomaly_score": score})
    else:
        predictions = estimator.predict(X)
        result = pd.DataFrame({"prediction": predictions.astype(str)})
    benign_labels = {"BENIGN", "NORMAL", "LEGITIMATE", "0", "FALSE", "ALLOW"}
    alerts = result[~result["prediction"].astype(str).str.upper().isin(benign_labels)].copy()
    output = REPORTS / f"detections-{experiment_id}-{dataset_id}.csv"
    alert_output = REPORTS / f"alerts-{experiment_id}-{dataset_id}.csv"
    result.to_csv(output, index=False)
    alerts.to_csv(alert_output, index=False)
    return {
        "experiment_id": experiment_id, "rows": len(result), "alerts": len(alerts),
        "alert_preview": alerts.head(100).to_dict(orient="records"),
        "predictions": result.head(100).to_dict(orient="records"),
        "export": f"/api/workspace/exports/{output.name}",
        "alerts_export": f"/api/workspace/exports/{alert_output.name}",
    }


@router.post("/integrations/{source}")
async def ingest_open_source_telemetry(source: str, file: UploadFile = File(...)):
    """Convert supported Zeek, Suricata, Wazuh logs into a local dataset."""
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
