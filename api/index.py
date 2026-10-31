"""Fail-closed FastAPI endpoints for offline CyberSentinel 5-agent flow replay."""
from __future__ import annotations

from pathlib import Path
import sys
import time
from typing import Any

from fastapi import FastAPI, HTTPException
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
            "agent_1_threat_detection": threat_present,
            "agent_2_anomaly_detection": anomaly_present,
            "agent_3_evidence_fusion": True,
            "agent_4_temporal_correlation": True,
            "agent_5_adaptive_defense": True,
        },
        "message": "All 5 multi-agent components operational." if pipeline else "Model artifacts are missing or failed validation.",
    }


@app.get("/api/system/diagnostics")
def system_diagnostics():
    """Expose actual local artifact presence without inventing readiness."""
    dataset = BASE_DIR / "data" / "processed" / "eval_prepared.parquet"
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
    for filename in ("classification.csv", "policy.csv", "replay.csv"):
        path = submission / filename
        files[filename] = {
            "present": path.is_file(),
            "bytes": path.stat().st_size if path.is_file() else None,
        }
    return {
        "api": {"available": True, "mode": "offline-replay"},
        "models": model_status,
        "model_sizes": {
            "agent_1_bytes": THREAT_MODEL.stat().st_size if THREAT_MODEL.is_file() else None,
            "agent_2_bytes": ANOMALY_MODEL.stat().st_size if ANOMALY_MODEL.is_file() else None,
        },
        "models_ready": get_pipeline() is not None,
        "evaluation_dataset": {
            "present": dataset.is_file(),
            "bytes": dataset.stat().st_size if dataset.is_file() else None,
            "path": "data/processed/eval_prepared.parquet",
        },
        "submission_artifacts": files,
        "history_database": {"present": history_db.is_file()},
        "source_identity": "native source IP when present; otherwise TCP-stack-derived synthetic identity; unavailable identity fails closed",
        "firewall": {"mode": "simulated-only", "host_firewall_modified": False},
    }


@app.get("/api/history")
def get_history(limit: int = 15):
    """Retrieve runs from local SQLite database."""
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
                "evidence_fusion": {"ready": True},
                "temporal_correlation": {"ready": True},
                "adaptive_defense": {"ready": True},
            },
        }
    return {
        "status": "ready",
        "models_ready": True,
        "agents": {
            "threat_detection": {
                "backend": pipeline.threat_agent.model.metadata.get("backend"),
                "feature_count": len(pipeline.threat_agent.model.feature_columns),
                "training_rows": pipeline.threat_agent.model.metadata.get("training_rows"),
                "classes": list(pipeline.threat_agent.model.label_encoder.classes_),
            },
            "anomaly_detection": {
                "algorithm": "IsolationForest",
                "feature_count": len(pipeline.anomaly_agent.feature_columns),
                "training_rows": pipeline.anomaly_agent.metadata.get("training_rows"),
                "threshold": pipeline.anomaly_agent.threshold,
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

    # Run Tri-Agent pipeline
    analysis = pipeline.analyze(flow)

    with _state_lock:
        # Correlate with Agent 4
        correlation = _correlation_agent.correlate(
            record_id=flow.get("record_id", "live-flow"),
            flow=flow,
            threat_class=analysis.get("final_class"),
            confidence=analysis.get("confidence"),
        )

        # Evaluate with Agent 5
        src_ip, _, _ = TemporalCorrelationAgent.extract_endpoints(flow)
        is_attack = analysis.get("action") == "BLOCK" or (correlation.correlated and correlation.attack_type != "BENIGN")
        defense = _defense_agent.handle_post_analysis(
            record_id=flow.get("record_id", "live-flow"),
            source_ip=src_ip,
            current_step=len(_correlation_agent.history),
            attack_detected=is_attack,
            attack_type=correlation.attack_type or analysis.get("final_class"),
            confidence=analysis.get("confidence"),
        )

    analysis["temporal_correlation"] = {
        "correlated": correlation.correlated,
        "group_id": correlation.group_id,
        "attack_type": correlation.attack_type,
        "evidence": correlation.evidence,
    }
    analysis["adaptive_defense"] = {
        "action": defense.action,
        "applied_policy_id": defense.applied_policy_id,
        "new_policy": {
            "policy_id": defense.new_policy_created.policy_id,
            "scope_type": defense.new_policy_created.scope_type,
            "scope_value": defense.new_policy_created.scope_value,
            "expires_after_record_id": defense.new_policy_created.expires_after_record_id,
        } if defense.new_policy_created else None,
        "rationale": defense.rationale,
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
    pipeline = get_pipeline()
    if pipeline is None:
        raise HTTPException(
            status_code=503,
            detail={"code": "MODEL_NOT_READY", "message": "Install and verify both model artifacts before running replay."},
        )
    eval_file = BASE_DIR / "data" / "processed" / "eval_prepared.parquet"
    if not eval_file.is_file():
        raise HTTPException(
            status_code=404,
            detail={"code": "EVALUATION_DATASET_NOT_FOUND", "message": "Install the organiser-provided evaluation parquet at data/processed/eval_prepared.parquet."},
        )
    try:
        frame = pd.read_parquet(eval_file)
        if frame.empty:
            raise HTTPException(status_code=422, detail="The evaluation dataset is empty.")
        engine = ReplayEngine(
            threat_agent=pipeline.threat_agent,
            anomaly_agent=pipeline.anomaly_agent,
            fusion_agent=pipeline.fusion_agent,
        )
        results = engine.run_replay(frame)
        output_dir = BASE_DIR / "outputs" / "submission"
        output_dir.mkdir(parents=True, exist_ok=True)
        files = {
            "classification.csv": engine.export_csv(
                results["classification_rows"],
                ["record_id", "predicted_class", "anomaly score", "evidence status"],
            ),
            "policy.csv": engine.export_csv(
                results["policy_rows"],
                ["policy_id", "activated_after_record_id", "scope_type", "scope_value", "expires_after_record_id", "policy_action"],
            ),
            "replay.csv": engine.export_csv(
                results["replay_rows"],
                ["record_id", "action", "applied_policy_id"],
            ),
        }
        for filename, csv_text in files.items():
            (output_dir / filename).write_text(csv_text, encoding="utf-8", newline="")
        record_ids = [str(row["record_id"]) for row in results["classification_rows"]]
        validation = SubmissionValidator.validate_submission_bundle(output_dir, record_ids)

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
        return {
            "run_id": run_id,
            "metrics": metrics,
            "validation": validation,
            "files": {name: {"path": f"outputs/submission/{name}", "rows": len(results[key])}
                      for name, key in (("classification.csv", "classification_rows"),
                                        ("policy.csv", "policy_rows"),
                                        ("replay.csv", "replay_rows"))},
            "correlation_groups": len(_LAST_CORRELATION_GROUPS),
            "source": "installed_official_evaluation_dataset",
        }
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail={"code": "OFFICIAL_REPLAY_FAILED", "type": type(exc).__name__, "message": "Official replay failed; inspect backend logs for details."},
        ) from exc


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
    # Read record ids from classification.csv
    import csv
    with (sub_dir / "classification.csv").open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        records = [r["record_id"] for r in reader]

    report = SubmissionValidator.validate_submission_bundle(sub_dir, records)
    return report


@app.get("/api/overview")
def get_overview():
    """Compute SOC KPIs from actual replay artifacts; labels are evaluation-only."""
    import csv

    eval_file = BASE_DIR / "data" / "processed" / "eval_prepared.parquet"
    sub_dir = BASE_DIR / "outputs" / "submission"
    class_file = sub_dir / "classification.csv"
    replay_file = sub_dir / "replay.csv"
    policy_file = sub_dir / "policy.csv"
    required = (eval_file, class_file, replay_file, policy_file)
    missing = [str(path.relative_to(BASE_DIR)) for path in required if not path.is_file()]
    if missing:
        raise HTTPException(
            status_code=503,
            detail={"code": "OVERVIEW_ARTIFACTS_NOT_READY", "missing": missing,
                    "message": "Overview metrics are unavailable until the evaluation dataset and replay artifacts are installed."},
        )
    try:
        flows = pd.read_parquet(eval_file)
        classifications = pd.read_csv(class_file, dtype={"record_id": str})
        replay = pd.read_csv(replay_file, dtype={"record_id": str, "applied_policy_id": str})
        policies = pd.read_csv(policy_file)
    except Exception as exc:
        raise HTTPException(status_code=503, detail={"code": "OVERVIEW_READ_FAILED", "type": type(exc).__name__}) from exc

    if "label" not in flows.columns:
        raise HTTPException(status_code=503, detail="Evaluation labels are required only for offline metric calculation.")
    flow_ids = [str(value) for value in flows["record_id"].tolist()] if "record_id" in flows.columns else [str(value) for value in flows.index]
    if len(set(flow_ids)) != len(flow_ids):
        raise HTTPException(status_code=503, detail="Evaluation record IDs are not unique.")
    if classifications["record_id"].astype(str).duplicated().any() or replay["record_id"].astype(str).duplicated().any():
        raise HTTPException(status_code=503, detail="Submission artifacts contain duplicate record IDs.")

    class_ids = set(classifications["record_id"].astype(str))
    replay_ids = set(replay["record_id"].astype(str))
    expected_ids = set(flow_ids)
    if class_ids != expected_ids or replay_ids != expected_ids:
        raise HTTPException(
            status_code=503,
            detail={"code": "OVERVIEW_RECORD_MISMATCH", "expected": len(expected_ids),
                    "classification": len(class_ids), "replay": len(replay_ids)},
        )

    truth = dict(zip(flow_ids, flows["label"].astype(str).str.upper().tolist()))
    actions = dict(zip(replay["record_id"].astype(str), replay["action"].astype(str).str.upper()))
    total = len(flow_ids)
    blocked = sum(action == "BLOCK" for action in actions.values())
    allowed = sum(action == "ALLOW" for action in actions.values())
    attacks = sum(label != "BENIGN" for label in truth.values())
    benign = total - attacks
    attack_blocks = sum(actions[rid] == "BLOCK" and truth[rid] != "BENIGN" for rid in flow_ids)
    false_blocks = sum(actions[rid] == "BLOCK" and truth[rid] == "BENIGN" for rid in flow_ids)
    benign_preserved = sum(actions[rid] == "ALLOW" and truth[rid] == "BENIGN" for rid in flow_ids)
    attack_misses = attacks - attack_blocks

    return {
        "source": "local_evaluation_dataset_and_generated_submission_csvs",
        "labels_used_for": "offline_metric_calculation_only",
        "metrics": {
            "total_records": total, "blocked_records": blocked, "allowed_records": allowed,
            "policies_created": int(len(policies)), "attack_records": attacks, "benign_records": benign,
            "attacks_contained": attack_blocks, "attacks_allowed": attack_misses,
            "false_blocks": false_blocks, "benign_preserved": benign_preserved,
            "attack_containment_rate": round(100 * attack_blocks / max(1, attacks), 2),
            "benign_preservation_rate": round(100 * benign_preserved / max(1, benign), 2),
            "block_precision": round(100 * attack_blocks / max(1, blocked), 2),
        },
        "integrity": {
            "classification_rows": len(classifications), "replay_rows": len(replay),
            "policy_rows": len(policies), "record_ids_match": True,
            "action_conservation": total == blocked + allowed,
        },
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
    allowed = {"classification.csv", "policy.csv", "replay.csv", "summary.json", "validation_report.json"}
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
    eval_file = BASE_DIR / "data" / "processed" / "eval_prepared.parquet"
    class_file = sub_dir / "classification.csv"
    replay_file = sub_dir / "replay.csv"
    if not eval_file.is_file():
        raise HTTPException(status_code=404, detail="Evaluation dataset is not installed.")
    if not class_file.is_file() or not replay_file.is_file():
        raise HTTPException(
            status_code=409,
            detail={"code": "REPLAY_OUTPUTS_NOT_READY", "message": "Generate classification.csv and replay.csv before inspecting evaluated flows."},
        )

    try:
        df = pd.read_parquet(eval_file)
        classifications = pd.read_csv(class_file, dtype={"record_id": str})
        replay = pd.read_csv(replay_file, dtype={"record_id": str, "applied_policy_id": str})
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Flow inspection data could not be loaded: {type(exc).__name__}") from exc

    has_class_cols = (
        {"record_id", "predicted_class", "anomaly score", "evidence status"}.issubset(classifications.columns) or
        {"record_id", "predicted_class", "anomaly_score", "evidence_status"}.issubset(classifications.columns)
    )
    required_replay = {"record_id", "action", "applied_policy_id"}
    if not has_class_cols or not required_replay.issubset(replay.columns):
        raise HTTPException(status_code=503, detail="Generated submission files do not match the official schema.")

    class_map = classifications.set_index("record_id").to_dict(orient="index")
    replay_map = replay.set_index("record_id").to_dict(orient="index")

    def numeric_from_value(value: Any) -> float:
        parsed = pd.to_numeric(value, errors="coerce")
        return float(parsed) if pd.notna(parsed) else 0.0

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
        applied = decision.get("applied_policy_id", "")
        raw_score = prediction.get("anomaly score") if "anomaly score" in prediction else prediction.get("anomaly_score")
        raw_evidence = prediction.get("evidence status") if "evidence status" in prediction else prediction.get("evidence_status", "INCOMPLETE")
        rows.append({
            "record_id": record_id,
            "predicted_class": predicted_class,
            "anomaly_score": numeric_from_value(raw_score),
            "evidence_status": str(raw_evidence),
            "action": str(decision.get("action", "")),
            "applied_policy_id": "" if pd.isna(applied) else str(applied),
            "destination_port": int(numeric_from_value(flow.get("Destination Port", 0))),
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
    """Retrieve policies generated during replay from outputs/submission/policy.csv."""
    pol_file = BASE_DIR / "outputs" / "submission" / "policy.csv"
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
    """Test real policy pre-filter matching against an IP and sequence record index."""
    source_ip = str(payload.get("source_ip", "")).strip()
    current_step = int(payload.get("current_step", 100))

    if not source_ip:
        raise HTTPException(status_code=422, detail="Provide a non-empty source_ip string.")

    pol_file = BASE_DIR / "outputs" / "submission" / "policy.csv"
    matched_policy = None
    if pol_file.is_file():
        try:
            pol_df = pd.read_csv(pol_file)
            matching = pol_df[
                (pol_df["scope_value"] == source_ip) &
                (pol_df["activated_after_record_id"] < current_step) &
                (pol_df["expires_after_record_id"] >= current_step)
            ]
            if not matching.empty:
                matched_policy = matching.iloc[0].to_dict()
        except Exception:
            pass

    if matched_policy:
        return {
            "matched": True,
            "action": "BLOCK",
            "policy_id": matched_policy["policy_id"],
            "scope_value": matched_policy["scope_value"],
            "activated_after": matched_policy["activated_after_record_id"],
            "expires_after": matched_policy["expires_after_record_id"],
            "status": "ACTIVE_POLICY_MATCH",
            "message": f"Pre-filter rule {matched_policy['policy_id']} drops flow from {source_ip} (active from record {matched_policy['activated_after_record_id']} to {matched_policy['expires_after_record_id']}).",
        }

    return {
        "matched": False,
        "action": "ALLOW",
        "policy_id": "",
        "status": "NO_MATCHING_POLICY",
        "message": f"No active policy matches source IP {source_ip} at sequence step {current_step}. Flow is allowed through to 5-agent detection pipeline.",
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
