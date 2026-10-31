"""CyberSentinel Multi-Agent ML Evaluation Framework."""

from cybersentinel.evaluation.anomaly import evaluate_anomaly_detection
from cybersentinel.evaluation.calibration import evaluate_probability_calibration
from cybersentinel.evaluation.classification import evaluate_classifier
from cybersentinel.evaluation.defense import evaluate_adaptive_defense
from cybersentinel.evaluation.fusion import evaluate_classifier_vs_fusion
from cybersentinel.evaluation.generalization import evaluate_seen_unseen_generalization
from cybersentinel.evaluation.loao import evaluate_leave_one_attack_out
from cybersentinel.evaluation.plots import generate_all_plots
from cybersentinel.evaluation.report import (
    build_master_summary,
    get_system_metadata,
    save_evaluation_report,
)
from cybersentinel.evaluation.temporal import evaluate_temporal_correlation

__all__ = [
    "evaluate_classifier",
    "evaluate_classifier_vs_fusion",
    "evaluate_anomaly_detection",
    "evaluate_seen_unseen_generalization",
    "evaluate_leave_one_attack_out",
    "evaluate_probability_calibration",
    "evaluate_temporal_correlation",
    "evaluate_adaptive_defense",
    "get_system_metadata",
    "save_evaluation_report",
    "build_master_summary",
    "generate_all_plots",
]
