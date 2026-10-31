"""FastAPI endpoints for CyberSentinel Multi-Agent Evaluation & Model Intelligence."""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse

logger = logging.getLogger("cybersentinel.api.evaluation")

router = APIRouter(prefix="/api/evaluation", tags=["Evaluation"])

BASE_DIR = Path(__file__).resolve().parent.parent
EVAL_DIR = BASE_DIR / "outputs" / "evaluation"
PLOTS_DIR = EVAL_DIR / "plots"


def _load_report(report_name: str) -> dict[str, Any]:
    file_path = EVAL_DIR / f"{report_name}.json"
    if not file_path.is_file():
        raise HTTPException(
            status_code=404,
            detail={
                "code": "REPORT_NOT_FOUND",
                "message": f"Evaluation report '{report_name}' has not been generated yet. Run scripts/evaluate_full_system.py first.",
            },
        )
    try:
        return json.loads(file_path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail={"code": "REPORT_READ_ERROR", "message": f"Failed to read {report_name}.json: {exc}"},
        )


@router.get("/summary")
def get_evaluation_summary():
    """Retrieve top-level executive summary spanning all 5 agents."""
    return _load_report("summary")


@router.get("/classification")
def get_classification_report():
    """Retrieve Agent 1 Random Forest comprehensive classification metrics."""
    return _load_report("classification")


@router.get("/fusion")
def get_fusion_report():
    """Retrieve Agent 1 vs Agent 3 Fusion comparative evaluation."""
    return _load_report("fusion")


@router.get("/anomaly")
def get_anomaly_report():
    """Retrieve Agent 2 Isolation Forest ROC, PR and threshold metrics."""
    return _load_report("anomaly")


@router.get("/generalization")
def get_generalization_report():
    """Retrieve seen vs unseen feature-vector generalization metrics."""
    return _load_report("generalization")


@router.get("/calibration")
def get_calibration_report():
    """Retrieve Agent 1 probability calibration and reliability metrics."""
    return _load_report("calibration")


@router.get("/loao")
def get_loao_report():
    """Retrieve Leave-One-Attack-Out zero-day evaluation across all attack classes."""
    return _load_report("loao")


@router.get("/temporal")
def get_temporal_report():
    """Retrieve Agent 4 temporal correlation campaign detection metrics."""
    return _load_report("temporal")


@router.get("/defense")
def get_defense_report():
    """Retrieve Agent 5 adaptive defense 4-way configuration evaluation."""
    return _load_report("defense")


@router.get("/all")
def get_all_evaluation_reports():
    """Retrieve all evaluation reports in a single unified payload for the frontend."""
    report_names = [
        "summary",
        "classification",
        "fusion",
        "anomaly",
        "generalization",
        "calibration",
        "loao",
        "temporal",
        "defense",
    ]
    reports: dict[str, Any] = {}
    missing: list[str] = []

    for name in report_names:
        file_path = EVAL_DIR / f"{name}.json"
        if file_path.is_file():
            try:
                reports[name] = json.loads(file_path.read_text(encoding="utf-8"))
            except Exception:
                reports[name] = None
        else:
            reports[name] = None
            missing.append(name)

    return {
        "status": "ready" if not missing else "partial" if len(missing) < len(report_names) else "not_generated",
        "missing_reports": missing,
        "reports": reports,
    }


@router.get("/plots/{filename}")
def get_evaluation_plot(filename: str):
    """Serve generated evaluation plot images and SVGs."""
    # Sanitize filename
    clean_name = Path(filename).name
    file_path = PLOTS_DIR / clean_name
    if not file_path.is_file():
        raise HTTPException(
            status_code=404,
            detail={"code": "PLOT_NOT_FOUND", "message": f"Plot file '{clean_name}' does not exist."},
        )
    media_type = "image/svg+xml" if clean_name.endswith(".svg") else "image/png"
    return FileResponse(file_path, media_type=media_type)
