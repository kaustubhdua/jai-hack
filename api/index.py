"""Fail-closed FastAPI endpoints for offline CyberSentinel 5-agent flow replay."""
from __future__ import annotations

from pathlib import Path
import io
import os
import sys
import tempfile
import time
import zipfile
from typing import Any

from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

BASE_DIR = Path(__file__).resolve().parent.parent
SOURCE_DIR = BASE_DIR / "src"
if str(SOURCE_DIR) not in sys.path:
    sys.path.insert(0, str(SOURCE_DIR))

from cybersentinel.pipeline import CyberSentinelPipeline
from cybersentinel.agents.fusion import EvidenceFusionAgent
from cybersentinel.contracts import ThreatDetectionResult, AnomalyDetectionResult
from cybersentinel.agents.anomaly_detection import AnomalyDetectionAgent
from cybersentinel.agents.correlation import TemporalCorrelationAgent
from cybersentinel.agents.adaptive_defense import AdaptiveDefenseAgent
from cybersentinel.replay import ReplayEngine
from cybersentinel.replay.submission import SubmissionValidator
from cybersentinel.replay.input_validation import validate_replay_input
from cybersentinel.storage.history_db import list_runs, record_run
import threading
import pandas as pd
from api.evaluation import router as evaluation_router

app = FastAPI(
    title="CyberSentinel API",
    version="1.0.0",
    description="Offline 5-agent network-flow intrusion detection and adaptive defense replay system.",
)
app.include_router(evaluation_router)
_state_lock = threading.Lock()

THREAT_MODEL = BASE_DIR / "models" / "threat_detection" / "model.joblib"
ANOMALY_MODEL = BASE_DIR / "models" / "anomaly_detection" / "model.joblib"
_pipeline: CyberSentinelPipeline | None = None
_anomaly_agent: AnomalyDetectionAgent | None = None
_correlation_agent = TemporalCorrelationAgent()
_defense_agent = AdaptiveDefenseAgent()
_LAST_CORRELATION_GROUPS: list[dict[str, Any]] = []
SERVERLESS_RUNTIME = os.environ.get("VERCEL") == "1"


class BatchAnalyzeRequest(BaseModel):
    flows: list[dict[str, Any]] = Field(min_length=1, max_length=1000)


class ReplaySimulationRequest(BaseModel):
    flows: list[dict[str, Any]] = Field(min_length=1, max_length=5000)
    dataset_name: str = "custom_replay"


def get_pipeline() -> CyberSentinelPipeline | None:
    global _pipeline
    if _pipeline is not None:
        return _pipeline
    if not THREAT_MODEL.is_file() or not ANOMALY_MODEL.is_file():
        return None
    try:
        _pipeline = CyberSentinelPipeline.load_default(THREAT_MODEL, ANOMALY_MODEL)
    except Exception:
        _pipeline = None
    return _pipeline


@app.get("/")
@app.get("/api")
@app.get("/health")
@app.get("/api/health")
def health():
    pipeline = get_pipeline()
    threat_present = THREAT_MODEL.is_file()
    anomaly_present = ANOMALY_MODEL.is_file()
    return {
        "status": "ok",
        "service": "CyberSentinel API",
        "version": "1.0.0",
        "mode": "offline-replay",
        "model_ready": pipeline is not None,
        "agents": {
            "agent_1_threat_detection": pipeline is not None and threat_present,
            "agent_2_anomaly_detection": pipeline is not None and anomaly_present,
            "agent_3_evidence_fusion": pipeline is not None,
            "agent_4_temporal_correlation": pipeline is not None,
            "agent_5_adaptive_defense": pipeline is not None,
        },
        "readiness": "ready" if pipeline is not None else "not_ready",
        "message": "Both model artifacts loaded; offline inference is ready." if pipeline else "API process is available, but verified model artifacts are missing or failed validation.",
    }


@app.get("/api/system/diagnostics")
def system_diagnostics():
    """Expose actual local artifact presence without inventing readiness."""
    dataset_candidates = (BASE_DIR / "data" / "processed" / "hidden_replay_input.csv", BASE_DIR / "data" / "processed" / "hidden_replay_input.parquet")
    dataset = next((path for path in dataset_candidates if path.is_file()), dataset_candidates[-1])
    history_db = BASE_DIR / "data" / "cybersentinel_history.db"
    submission = BASE_DIR / "outputs" / "submission"
    model_status = {
        "agent_1_model": THREAT_MODEL.is_file(),
        "agent_2_model": ANOMALY_MODEL.is_file(),
        "agent_3_fusion_code": True,
        "agent_4_correlation_code": True,
        "agent_5_defense_code": True,
    }
    files = {}
    for filename in ("classification.csv", "policies.csv", "replay.csv"):
        path = submission / filename
        files[filename] = {
            "present": path.is_file(),
            "bytes": path.stat().st_size if path.is_file() else None,
        }
    input_validation = None
    if dataset.is_file():
        try:
            input_frame = pd.read_parquet(dataset) if dataset.suffix == ".parquet" else pd.read_csv(dataset)
            input_validation = validate_replay_input(input_frame)
        except Exception as exc:
            input_validation = {"valid": False, "errors": [f"Input validation could not run: {type(exc).__name__}"]}
    return {
        "api": {"available": True, "mode": "offline-replay", "runtime": "serverless-preview" if SERVERLESS_RUNTIME else "local"},
        "models": model_status,
        "model_sizes": {
            "agent_1_bytes": THREAT_MODEL.stat().st_size if THREAT_MODEL.is_file() else None,
            "agent_2_bytes": ANOMALY_MODEL.stat().st_size if ANOMALY_MODEL.is_file() else None,
        },
        "models_ready": get_pipeline() is not None,
        "hidden_replay_input": {
            "present": dataset.is_file(),
            "bytes": dataset.stat().st_size if dataset.is_file() else None,
            "path": str(dataset.relative_to(BASE_DIR)) if dataset.is_file() else "data/processed/hidden_replay_input.csv",
            "validation": input_validation,
        },
        "submission_artifacts": files,
        "history_database": {"present": history_db.is_file(), "persistent": not SERVERLESS_RUNTIME, "mode": "ephemeral" if SERVERLESS_RUNTIME else "local_sqlite"},
        "source_identity": "literal observed source IP only; missing or invalid endpoint values remain unknown and never become synthetic identities",
        "firewall": {"mode": "simulated-only", "host_firewall_modified": False},
    }


@app.get("/api/history")
def get_history(limit: int = 15):
    """Retrieve runs from local SQLite database."""
    if SERVERLESS_RUNTIME:
        return {"runs": [], "source": "not_persistent_serverless", "message": "Run history is local-only and is not persisted by serverless preview deployments."}
    try:
        runs = list_runs(limit=limit)
        normalized = [
            {**run, "run_id": run.get("id"), "id": run.get("id")}
            for run in runs
        ]
        return {"runs": normalized, "source": "local_sqlite"}
    except Exception as exc:
        return {"runs": [], "error": str(exc), "source": "local_sqlite"}


@app.get("/api/models/status")
def models_status():
    pipeline = get_pipeline()
    if pipeline is None:
        return {
            "status": "not_ready",
            "models_ready": False,
            "agents": {
                "threat_detection": {"artifact_present": THREAT_MODEL.is_file()},
                "anomaly_detection": {"artifact_present": ANOMALY_MODEL.is_file()},
                "evidence_fusion": {"code_available": True, "runtime_ready": False},
                "temporal_correlation": {"code_available": True, "runtime_ready": False},
                "adaptive_defense": {"code_available": True, "runtime_ready": False},
            },
        }
    return {
        "status": "ready",
        "models_ready": True,
        "agents": {
            "threat_detection": {
                "backend": pipeline.threat_agent.model.metadata.get("backend"),
                "feature_count": len(pipeline.threat_agent.model.feature_columns),
                "feature_columns": list(pipeline.threat_agent.model.feature_columns),
                "training_rows": pipeline.threat_agent.model.metadata.get("training_rows"),
                "confidence_calibrated": bool(pipeline.threat_agent.model.metadata.get("confidence_calibrated", False)),
                "calibration_temperature": pipeline.threat_agent.model.calibration_temperature,
                "classes": list(pipeline.threat_agent.model.label_encoder.classes_),
            },
            "anomaly_detection": {
                "algorithm": "IsolationForest",
                "feature_count": len(pipeline.anomaly_agent.feature_columns),
                "feature_columns": list(pipeline.anomaly_agent.feature_columns),
                "training_rows": pipeline.anomaly_agent.metadata.get("training_rows"),
                "threshold": pipeline.anomaly_agent.threshold,
                "score_is_probability": False,
            },
            "evidence_fusion": {"simulated_actions": ["ALLOW", "BLOCK", "REVIEW"]},
            "temporal_correlation": {"window_size": _correlation_agent.window_size},
            "adaptive_defense": {"scope_type": "SOURCE_IP", "action": "BLOCK"},
        },
    }


@app.post("/api/agents/anomaly/score")
def score_anomaly(payload: dict[str, Any]):
    """Run Agent 2 independently without requiring Agent 1 or evidence fusion."""
    global _anomaly_agent
    if _anomaly_agent is None:
        if not ANOMALY_MODEL.is_file():
            raise HTTPException(
                status_code=503,
                detail={"code": "AGENT_2_NOT_READY", "message": "Agent 2 model artifact is not installed."},
            )
        try:
            _anomaly_agent = AnomalyDetectionAgent.load(ANOMALY_MODEL)
        except Exception as exc:
            raise HTTPException(
                status_code=503,
                detail={"code": "AGENT_2_NOT_READY", "message": f"Agent 2 model could not be loaded: {type(exc).__name__}"},
            )
    flow = payload.get("flow", payload)
    if not isinstance(flow, dict) or not flow:
        raise HTTPException(status_code=422, detail="Provide a non-empty flow object.")
    result = _anomaly_agent.score(flow)
    if result.status != "success":
        raise HTTPException(status_code=422, detail={"code": "AGENT_2_SCORING_ERROR", "message": result.message or "Anomaly scoring failed."})
    return result.to_dict()


@app.post("/api/analyze")
@app.post("/analyze")
def analyze(payload: dict[str, Any]):
    pipeline = get_pipeline()
    if pipeline is None:
        raise HTTPException(
            status_code=503,
            detail={"code": "MODEL_NOT_READY", "message": "Both verified model artifacts are required for inference."},
        )
    flow = payload.get("flow", payload)
    if not isinstance(flow, dict) or not flow:
        raise HTTPException(status_code=422, detail="Provide a non-empty flow object.")

    # This endpoint is deliberately stateless: A4/A5 require chronological
    # sequence state and are run only by /api/replay/simulate or /api/replay/run-official.
    analysis = pipeline.analyze(flow)
    analysis["execution_mode"] = "single_record_model_inference"
    analysis["stateful_agents"] = "not_run; use chronological replay for A4/A5"
    threat_model = getattr(pipeline.threat_agent, "model", None)
    threat_metadata = getattr(threat_model, "metadata", {}) or {}
    analysis["model_provenance"] = {
        "a1_confidence_calibrated": bool(threat_metadata.get("confidence_calibrated", False)),
        "a2_score_is_probability": False,
    }
    return analysis


@app.post("/api/analyze/batch")
@app.post("/analyze/batch")
def analyze_batch(payload: BatchAnalyzeRequest):
    pipeline = get_pipeline()
    if pipeline is None:
        raise HTTPException(
            status_code=503,
            detail={"code": "MODEL_NOT_READY", "message": "Both verified model artifacts are required for inference."},
        )
    results = pipeline.analyze_batch(payload.flows)
    actions = {"ALLOW": 0, "BLOCK": 0, "REVIEW": 0}
    for result in results:
        actions[result["action"]] += 1
    return {"total_analyzed": len(results), "actions": actions, "results": results}


@app.post("/api/fusion/simulate")
def simulate_fusion(payload: dict[str, Any]):
    """Run the production Agent 3 fusion contract against explicit A1/A2 evidence."""
    predicted = str(payload.get("predicted_class", "")).upper()
    confidence = payload.get("confidence")
    anomaly_score = payload.get("anomaly_score")
    is_anomaly = payload.get("is_anomaly")
    if predicted not in {"BENIGN", "BRUTE_FORCE", "DOS", "DDOS", "PORT_SCAN"}:
        raise HTTPException(status_code=422, detail="predicted_class must be one of the five official classes.")
    if isinstance(confidence, bool) or not isinstance(confidence, (int, float)) or not 0 <= float(confidence) <= 1:
        raise HTTPException(status_code=422, detail="confidence must be a number between 0 and 1.")
    if isinstance(anomaly_score, bool) or not isinstance(anomaly_score, (int, float)) or not pd.notna(anomaly_score):
        raise HTTPException(status_code=422, detail="anomaly_score must be a finite number.")
    if not isinstance(is_anomaly, bool):
        raise HTTPException(status_code=422, detail="is_anomaly must be a boolean from Agent 2.")
    threat = ThreatDetectionResult(predicted_class=predicted, confidence=float(confidence))
    anomaly = AnomalyDetectionResult(anomaly_score=float(anomaly_score), is_anomaly=is_anomaly)
    result = EvidenceFusionAgent().fuse(threat, anomaly)
    return result.to_dict()


@app.post("/api/replay/simulate")
def simulate_replay(payload: ReplaySimulationRequest):
    """Run causal chronological replay over provided flow sequence."""
    pipeline = get_pipeline()
    if pipeline is None:
        raise HTTPException(
            status_code=503,
            detail={"code": "MODEL_NOT_READY", "message": "Both verified model artifacts are required for replay."},
        )
    engine = ReplayEngine(
        threat_agent=pipeline.threat_agent,
        anomaly_agent=pipeline.anomaly_agent,
        fusion_agent=pipeline.fusion_agent,
    )
    df = pd.DataFrame(payload.flows)
    threat_model = getattr(engine.threat_agent, "model", None)
    threat_features = getattr(threat_model, "feature_columns", None)
    anomaly_features = getattr(engine.anomaly_agent, "feature_columns", None)
    feature_contracts = {}
    if threat_features:
        feature_contracts["Agent 1"] = list(threat_features)
    if anomaly_features:
        feature_contracts["Agent 2"] = list(anomaly_features)
    input_report = validate_replay_input(df, feature_contracts or None)
    if not input_report["valid"]:
        raise HTTPException(status_code=422, detail={"code": "REPLAY_INPUT_INVALID", "report": input_report})
    results = engine.run_replay(df)

    # Retain only groups produced by this replay run.
    global _LAST_CORRELATION_GROUPS
    _LAST_CORRELATION_GROUPS = [
        {
            "group_id": group.group_id,
            "attack_type": group.attack_type,
            "source_identity": group.source_ip,
            "target_endpoints": list(group.target_endpoints),
            "member_record_ids": [str(value) for value in group.member_record_ids],
            "flow_count": group.flow_count,
            "start_record_id": str(group.start_record_id) if group.start_record_id is not None else None,
            "end_record_id": str(group.end_record_id) if group.end_record_id is not None else None,
            "confidence": group.confidence,
            "evidence": list(group.evidence),
        }
        for group in engine.correlation_agent.active_groups.values()
    ]

    # Save to local SQLite
    run_id = f"RUN-{time.time_ns()}"
    metrics = results["metrics"]
    record_run(
        run_id=run_id,
        dataset_name=payload.dataset_name,
        total_records=metrics["total_records"],
        blocked_records=metrics["blocked_records"],
        allowed_records=metrics["allowed_records"],
        policies_created=metrics["policies_created"],
        containment_rate=metrics["containment_rate"],
        throughput_fps=metrics["throughput_fps"],
        elapsed_seconds=metrics["elapsed_seconds"],
        status="COMPLETED",
    )

    return {
        "run_id": run_id,
        "metrics": metrics,
        "policies_sample": results["policy_rows"][:20],
        "replay_sample": results["replay_rows"][:30],
        "classification_sample": results["classification_rows"][:30],
    }


@app.post("/api/replay/run-official")
def run_official_replay():
    """Run the installed official evaluation stream and write the three submission CSVs."""
    if SERVERLESS_RUNTIME:
        raise HTTPException(status_code=503, detail={"code": "LOCAL_RUNTIME_REQUIRED", "message": "Replay execution and local SQLite history require the local Python runtime; serverless previews are read-only."})
    pipeline = get_pipeline()
    if pipeline is None:
        raise HTTPException(
            status_code=503,
            detail={"code": "MODEL_NOT_READY", "message": "Install and verify both model artifacts before running replay."},
        )
    candidates = (BASE_DIR / "data" / "processed" / "hidden_replay_input.csv", BASE_DIR / "data" / "processed" / "hidden_replay_input.parquet")
    eval_file = next((path for path in candidates if path.is_file()), None)
    if eval_file is None:
        raise HTTPException(status_code=404, detail={"code": "HIDDEN_REPLAY_INPUT_NOT_FOUND", "message": "Install the unlabelled organizer input as hidden_replay_input.parquet or .csv."})
    try:
        frame = pd.read_parquet(eval_file) if eval_file.suffix == ".parquet" else pd.read_csv(eval_file)
        if frame.empty:
            raise HTTPException(status_code=422, detail="The unlabelled hidden replay input is empty.")
        engine = ReplayEngine(
            threat_agent=pipeline.threat_agent,
            anomaly_agent=pipeline.anomaly_agent,
            fusion_agent=pipeline.fusion_agent,
        )
        input_report = validate_replay_input(frame, {
            "Agent 1": engine.threat_agent.model.feature_columns,
            "Agent 2": engine.anomaly_agent.feature_columns,
        })
        if not input_report["valid"]:
            raise HTTPException(status_code=422, detail={"code": "REPLAY_INPUT_INVALID", "report": input_report})
        results = engine.run_replay(frame)
        output_dir = BASE_DIR / "outputs" / "submission"
        output_dir.mkdir(parents=True, exist_ok=True)
        generated_files = engine.write_submission_files(results, output_dir)
        # Validate against the original organiser input, never against the output
        # being validated (which could be truncated and otherwise validate itself).
        if "record_id" not in frame.columns:
            raise HTTPException(status_code=422, detail="The hidden replay input must contain organizer-provided record_id values.")
        record_ids = frame["record_id"].astype(str).tolist()
        validation = SubmissionValidator.validate_submission_bundle(output_dir, record_ids, source_frame=frame)

        global _LAST_CORRELATION_GROUPS
        _LAST_CORRELATION_GROUPS = [
            {
                "group_id": group.group_id,
                "attack_type": group.attack_type,
                "source_identity": group.source_ip,
                "target_endpoints": list(group.target_endpoints),
                "member_record_ids": [str(value) for value in group.member_record_ids],
                "flow_count": group.flow_count,
                "start_record_id": str(group.start_record_id) if group.start_record_id is not None else None,
                "end_record_id": str(group.end_record_id) if group.end_record_id is not None else None,
                "confidence": group.confidence,
                "evidence": list(group.evidence),
            }
            for group in engine.correlation_agent.active_groups.values()
        ]

        metrics = results["metrics"]
        run_id = f"RUN-{int(time.time())}"
        record_run(
            run_id=run_id,
            dataset_name=eval_file.name,
            total_records=metrics["total_records"],
            blocked_records=metrics["blocked_records"],
            allowed_records=metrics["allowed_records"],
            policies_created=metrics["policies_created"],
            containment_rate=metrics.get("containment_rate"),
            throughput_fps=metrics["throughput_fps"],
            elapsed_seconds=metrics["elapsed_seconds"],
            status="COMPLETED" if validation.get("all_valid") else "VALIDATION_FAILED",
        )
        summary = {
            "run_id": run_id,
            "source": "installed_unlabelled_hidden_replay_input",
            "records_processed": int(metrics["total_records"]),
            "artifacts": {
                "classification_rows": len(results["classification_rows"]),
                "replay_rows": len(results["replay_rows"]),
                "policy_rows": len(results["policy_rows"]),
            },
            "operational_metrics": {
                "blocked_records": int(metrics["blocked_records"]),
                "allowed_records": int(metrics["allowed_records"]),
                "policies_created": int(metrics["policies_created"]),
                "elapsed_seconds": float(metrics["elapsed_seconds"]),
                "throughput_records_per_second": float(metrics["throughput_fps"]),
            },
            "ground_truth_metrics": None,
            "validation": {
                "all_valid": bool(validation.get("all_valid")),
                "status": validation.get("status"),
                "organizer_acceptance": "NOT_VERIFIED",
            },
            "disclosure": "The hidden input is unlabelled. Attack/benign performance metrics and organizer acceptance cannot be inferred from this local replay.",
        }
        (output_dir / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
        return {
            "run_id": run_id,
            "metrics": metrics,
            "validation": validation,
            "files": {name: {"path": f"outputs/submission/{name}", "rows": len(results[key])}
                      for name, key in (("classification.csv", "classification_rows"),
                                        ("policies.csv", "policy_rows"),
                                        ("replay.csv", "replay_rows"))},
            "correlation_groups": len(_LAST_CORRELATION_GROUPS),
            "source": "installed_unlabelled_hidden_replay_input",
        }
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail={"code": "OFFICIAL_REPLAY_FAILED", "type": type(exc).__name__, "message": "Official replay failed; inspect backend logs for details."},
        ) from exc


@app.post("/api/replay/input/upload")
async def upload_replay_input(file: UploadFile = File(...)):
    """Install a real organizer CSV or the known cyber-hidden.zip without extracting paths."""
    if SERVERLESS_RUNTIME:
        raise HTTPException(status_code=503, detail={
            "code": "LOCAL_RUNTIME_REQUIRED",
            "message": "Replay input files are stored locally. Use the local Python API, not a serverless preview.",
        })
    filename = (file.filename or "").casefold()
    try:
        payload = await file.read(20 * 1024 * 1024 + 1)
    finally:
        await file.close()
    if len(payload) > 20 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="Upload exceeds the 20 MiB compressed-file limit.")

    if filename.endswith(".csv"):
        csv_payload = payload
    elif filename.endswith(".zip"):
        try:
            with zipfile.ZipFile(io.BytesIO(payload)) as archive:
                try:
                    entry = archive.getinfo("Cyber/hidden/records.csv")
                except KeyError as exc:
                    raise HTTPException(status_code=422, detail={
                        "code": "HIDDEN_CSV_NOT_FOUND",
                        "message": "ZIP must contain the organizer file Cyber/hidden/records.csv.",
                    }) from exc
                if entry.file_size > 50 * 1024 * 1024 or entry.is_dir():
                    raise HTTPException(status_code=413, detail="Uncompressed replay CSV exceeds the 50 MiB limit.")
                if entry.compress_size and entry.file_size / entry.compress_size > 1000:
                    raise HTTPException(status_code=413, detail="ZIP compression ratio exceeds the safety limit.")
                csv_payload = archive.read(entry)
        except zipfile.BadZipFile as exc:
            raise HTTPException(status_code=422, detail="Uploaded ZIP archive is invalid.") from exc
    else:
        raise HTTPException(status_code=415, detail="Upload an organizer .csv file or cyber-hidden.zip.")

    try:
        frame = pd.read_csv(io.BytesIO(csv_payload), dtype={"record_id": str}, keep_default_na=False)
        report = validate_replay_input(frame)
    except Exception as exc:
        raise HTTPException(status_code=422, detail={
            "code": "REPLAY_INPUT_PARSE_FAILED",
            "message": f"Replay input could not be parsed: {type(exc).__name__}.",
        }) from exc
    if not report["valid"]:
        raise HTTPException(status_code=422, detail={"code": "REPLAY_INPUT_INVALID", "report": report})

    destination = BASE_DIR / "data" / "processed" / "hidden_replay_input.csv"
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = None
    try:
        with tempfile.NamedTemporaryFile(prefix=".hidden-replay-", suffix=".csv", dir=destination.parent, delete=False) as handle:
            handle.write(csv_payload)
            temporary_path = Path(handle.name)
        os.replace(temporary_path, destination)
    finally:
        if temporary_path is not None and temporary_path.exists():
            temporary_path.unlink()

    return {
        "installed": True,
        "path": "data/processed/hidden_replay_input.csv",
        "input_validation": report,
        "message": "Organizer input installed locally. No endpoints or timestamps were generated or imputed.",
    }


@app.get("/api/replay/validate")
def validate_submissions():
    """Validate submission files in outputs/submission/."""
    sub_dir = BASE_DIR / "outputs" / "submission"
    if not (sub_dir / "classification.csv").is_file():
        return {
            "valid": False,
            "status": "NOT_GENERATED",
            "message": "Submission files have not yet been generated in outputs/submission/.",
        }

    # The source dataset is the authority for coverage and ordering. Never infer
    # expected IDs from classification.csv, because a truncated file could then
    # incorrectly validate against its own contents.
    candidates = (BASE_DIR / "data" / "processed" / "hidden_replay_input.csv", BASE_DIR / "data" / "processed" / "hidden_replay_input.parquet")
    eval_file = next((path for path in candidates if path.is_file()), None)
    if eval_file is None:
        return {"valid": False, "status": "INPUT_DATASET_NOT_AVAILABLE", "message": "Cannot verify submission coverage without the original unlabelled hidden replay input."}
    try:
        source = pd.read_parquet(eval_file) if eval_file.suffix == ".parquet" else pd.read_csv(eval_file)
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail={"code": "EVALUATION_DATASET_READ_FAILED", "type": type(exc).__name__},
        ) from exc
    if "record_id" not in source.columns:
        raise HTTPException(
            status_code=422,
            detail="The evaluation dataset must contain organiser-provided record_id values.",
        )
    records = source["record_id"].astype(str).tolist()
    if len(records) != len(set(records)):
        raise HTTPException(status_code=422, detail="The evaluation dataset contains duplicate record_id values.")

    return SubmissionValidator.validate_submission_bundle(sub_dir, records, source_frame=source)


@app.get("/api/overview")
def get_overview():
    """Return operational replay counts without inventing hidden-set ground-truth metrics."""
    sub_dir = BASE_DIR / "outputs" / "submission"
    replay_file = sub_dir / "replay.csv"
    policies_file = sub_dir / "policies.csv"
    classification_file = sub_dir / "classification.csv"
    missing = [str(path.name) for path in (replay_file, policies_file, classification_file) if not path.is_file()]
    if missing:
        raise HTTPException(status_code=503, detail={"code": "REPLAY_ARTIFACTS_NOT_READY", "missing": missing})
    try:
        replay = pd.read_csv(replay_file, dtype=str, keep_default_na=False)
        policies = pd.read_csv(policies_file, dtype=str, keep_default_na=False)
        classifications = pd.read_csv(classification_file, dtype=str, keep_default_na=False)
    except Exception as exc:
        raise HTTPException(status_code=503, detail={"code": "OVERVIEW_READ_FAILED", "type": type(exc).__name__}) from exc
    if not {"record_id", "action", "active_policy_id"}.issubset(replay.columns):
        raise HTTPException(status_code=503, detail="Replay CSV does not match the official organizer schema.")
    actions = replay["action"].str.upper()
    total = len(replay)
    blocked = int((actions == "BLOCK").sum())
    allowed = int((actions == "ALLOW").sum())
    return {
        "source": "unlabelled_hidden_replay_submission_artifacts",
        "labels_used_for": "none",
        "metrics": {
            "total_records": total, "blocked_records": blocked, "allowed_records": allowed,
            "policies_created": len(policies), "attack_records": None, "benign_records": None,
            "attacks_contained": None, "attacks_allowed": None, "false_blocks": None,
            "benign_preserved": None, "attack_containment_rate": None,
            "benign_preservation_rate": None, "block_precision": None,
        },
        "integrity": {
            "classification_rows": len(classifications), "replay_rows": len(replay),
            "policy_rows": len(policies),
            "record_ids_match": classifications["record_id"].astype(str).tolist() == replay["record_id"].astype(str).tolist(),
            "action_conservation": total == blocked + allowed,
        },
        "disclosure": "Hidden records are unlabelled. Attack/benign performance metrics are intentionally unavailable and must not be inferred from model predictions.",
    }


@app.get("/api/benchmarks")
def get_benchmarks():
    """Return only metrics loaded from a generated benchmark report."""
    import json

    candidates = (
        BASE_DIR / "outputs" / "reports" / "eval_benchmark_report.json",
        BASE_DIR / "release" / "day2-final" / "eval_benchmark_report.json",
    )
    report_file = next((path for path in candidates if path.is_file()), None)
    if report_file is None:
        raise HTTPException(
            status_code=503,
            detail={
                "code": "BENCHMARK_NOT_AVAILABLE",
                "message": "No generated benchmark report is available. Run the permitted benchmark workflow first.",
            },
        )
    try:
        with report_file.open("r", encoding="utf-8") as handle:
            report = json.load(handle)
    except (OSError, ValueError) as exc:
        raise HTTPException(
            status_code=503,
            detail={"code": "BENCHMARK_REPORT_INVALID", "message": f"Benchmark report could not be read: {type(exc).__name__}"},
        ) from exc
    return {"source": str(report_file.relative_to(BASE_DIR)), "verified_report": report}

@app.get("/api/submissions/download/{filename}")
def download_submission_file(filename: str):
    """Download an official submission CSV or report."""
    allowed = {"classification.csv", "policies.csv", "replay.csv", "summary.json", "validation_report.json"}
    if filename not in allowed:
        raise HTTPException(status_code=400, detail=f"Invalid file requested: {filename}")

    file_path = BASE_DIR / "outputs" / "submission" / filename
    if not file_path.is_file():
        raise HTTPException(status_code=404, detail=f"File {filename} not yet generated.")

    media_type = "text/csv" if filename.endswith(".csv") else "application/json"
    return FileResponse(path=str(file_path), media_type=media_type, filename=filename)


@app.get("/api/flows/sample")
def get_flows_sample(limit: int = 50, offset: int = 0, class_filter: str | None = None):
    """Return flow features joined to predictions/actions, never ground-truth labels."""
    if limit < 1 or limit > 200 or offset < 0:
        raise HTTPException(status_code=422, detail="limit must be 1..200 and offset must be non-negative.")

    sub_dir = BASE_DIR / "outputs" / "submission"
    candidates = (BASE_DIR / "data" / "processed" / "hidden_replay_input.csv", BASE_DIR / "data" / "processed" / "hidden_replay_input.parquet")
    eval_file = next((path for path in candidates if path.is_file()), None)
    class_file = sub_dir / "classification.csv"
    replay_file = sub_dir / "replay.csv"
    if eval_file is None:
        raise HTTPException(status_code=404, detail="Unlabelled hidden replay input is not installed.")
    if not class_file.is_file() or not replay_file.is_file():
        raise HTTPException(
            status_code=409,
            detail={"code": "REPLAY_OUTPUTS_NOT_READY", "message": "Generate classification.csv and replay.csv before inspecting evaluated flows."},
        )

    try:
        df = pd.read_parquet(eval_file) if eval_file.suffix == ".parquet" else pd.read_csv(eval_file)
        classifications = pd.read_csv(class_file, dtype={"record_id": str})
        replay = pd.read_csv(replay_file, dtype={"record_id": str, "active_policy_id": str})
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Flow inspection data could not be loaded: {type(exc).__name__}") from exc

    has_class_cols = (
        {"record_id", "predicted_class", "anomaly_score", "evidence_status"}.issubset(classifications.columns)
    )
    required_replay = {"record_id", "action", "active_policy_id"}
    if not has_class_cols or not required_replay.issubset(replay.columns):
        raise HTTPException(status_code=503, detail="Generated submission files do not match the official schema.")

    class_map = classifications.set_index("record_id").to_dict(orient="index")
    replay_map = replay.set_index("record_id").to_dict(orient="index")

    def numeric_from_value(value: Any) -> float | None:
        parsed = pd.to_numeric(value, errors="coerce")
        return float(parsed) if pd.notna(parsed) else None

    rows = []
    for index, flow in df.iterrows():
        record_id = str(flow.get("record_id", index))
        prediction = class_map.get(record_id)
        decision = replay_map.get(record_id)
        if prediction is None or decision is None:
            continue
        predicted_class = str(prediction.get("predicted_class", ""))
        if class_filter and class_filter.upper() not in ("ALL", predicted_class.upper()):
            continue
        applied = decision.get("active_policy_id") or ""
        raw_score = prediction.get("anomaly_score")
        raw_evidence = prediction.get("evidence_status", "UNCERTAIN")
        rows.append({
            "record_id": record_id,
            "predicted_class": predicted_class,
            "anomaly_score": numeric_from_value(raw_score),
            "evidence_status": str(raw_evidence),
            "action": str(decision.get("action", "")),
            "active_policy_id": "" if pd.isna(applied) or not str(applied).strip() else str(applied),
            "destination_port": int(numeric_from_value(flow.get("Destination Port"))) if numeric_from_value(flow.get("Destination Port")) is not None else None,
            "flow_duration": numeric_from_value(flow.get("Flow Duration", 0)),
            "total_fwd_packets": numeric_from_value(flow.get("Total Fwd Packets", 0)),
            "packet_length_mean": numeric_from_value(flow.get("Packet Length Mean", 0)),
        })

    return {
        "total": len(rows),
        "offset": offset,
        "limit": limit,
        "flows": rows[offset:offset + limit],
        "filter_semantics": "predicted_class",
        "ground_truth_labels_exposed": False,
    }

@app.get("/api/policies")
def get_policies(limit: int = 50, offset: int = 0):
    """Retrieve policies generated during replay from outputs/submission/policies.csv."""
    pol_file = BASE_DIR / "outputs" / "submission" / "policies.csv"
    if not pol_file.is_file():
        return {"policies": [], "total": 0}
    try:
        pol_df = pd.read_csv(pol_file)
        total = len(pol_df)
        subset = pol_df.iloc[offset : offset + limit].to_dict(orient="records")
        return {"policies": subset, "total": total, "offset": offset, "limit": limit}
    except Exception as e:
        return {"policies": [], "total": 0, "error": str(e)}


@app.post("/api/policies/test")
def test_policy_prefilter(payload: dict[str, Any]):
    """Test a policy against organizer record positions, not numeric record-ID arithmetic."""
    source_ip = str(payload.get("source_ip", "")).strip()
    current_step = payload.get("current_step", 1)
    try:
        current_step = int(current_step)
    except (TypeError, ValueError):
        raise HTTPException(status_code=422, detail="current_step must be a 1-based organizer seq value.")
    if not source_ip or current_step < 1:
        raise HTTPException(status_code=422, detail="Provide a source_ip and a positive 1-based current_step.")

    candidates = (
        BASE_DIR / "data" / "processed" / "hidden_replay_input.csv",
        BASE_DIR / "data" / "processed" / "hidden_replay_input.parquet",
    )
    input_file = next((path for path in candidates if path.is_file()), None)
    if input_file is None:
        raise HTTPException(status_code=503, detail={
            "code": "REPLAY_INPUT_NOT_AVAILABLE",
            "message": "Install the organizer replay input to test policy activation by seq.",
        })
    try:
        source = pd.read_parquet(input_file) if input_file.suffix == ".parquet" else pd.read_csv(input_file)
        if not {"record_id", "seq"}.issubset(source.columns):
            raise ValueError("Replay input must contain record_id and seq.")
        positions = dict(zip(source["record_id"].astype(str), pd.to_numeric(source["seq"], errors="raise").astype(int)))
    except Exception as exc:
        raise HTTPException(status_code=503, detail={"code": "REPLAY_INPUT_INVALID", "type": type(exc).__name__}) from exc

    pol_file = BASE_DIR / "outputs" / "submission" / "policies.csv"
    matched_policy = None
    if pol_file.is_file():
        try:
            pol_df = pd.read_csv(pol_file, dtype=str, keep_default_na=False)
            matching = pol_df[
                (pol_df["scope_type"] == "SOURCE_IP") &
                (pol_df["scope_value"] == source_ip) &
                (pol_df["activated_after_record_id"].map(positions) < current_step) &
                (pol_df["expires_after_record_id"].map(positions) >= current_step)
            ]
            if not matching.empty:
                matched_policy = matching.sort_values("policy_id").iloc[0].to_dict()
        except Exception as exc:
            raise HTTPException(status_code=503, detail={"code": "POLICY_FILE_INVALID", "type": type(exc).__name__}) from exc

    if matched_policy:
        return {
            "matched": True, "action": "BLOCK", "policy_id": matched_policy["policy_id"],
            "scope_value": matched_policy["scope_value"],
            "activated_after": matched_policy["activated_after_record_id"],
            "expires_after": matched_policy["expires_after_record_id"],
            "status": "ACTIVE_POLICY_MATCH",
            "message": f"Pre-filter rule {matched_policy['policy_id']} matches source IP {source_ip} at seq {current_step}.",
        }
    return {
        "matched": False, "action": "ALLOW", "policy_id": "",
        "status": "NO_MATCHING_POLICY",
        "message": f"No active policy matches source IP {source_ip} at seq {current_step}.",
    }



@app.get("/api/correlation/groups")
def get_correlation_groups(limit: int = 20):
    """Return groups observed in the latest completed replay; no fabricated fixtures."""
    if limit < 1 or limit > 200:
        raise HTTPException(status_code=422, detail="limit must be between 1 and 200.")
    return {
        "groups": _LAST_CORRELATION_GROUPS[:limit],
        "total": len(_LAST_CORRELATION_GROUPS),
        "source": "latest_completed_replay" if _LAST_CORRELATION_GROUPS else "no_replay_in_this_process",
        "synthetic": False,
        "note": "Correlation groups are populated only after a real replay in this API process.",
    }
