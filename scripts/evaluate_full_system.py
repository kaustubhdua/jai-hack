"""Master Runner for CyberSentinel Comprehensive Multi-Agent ML Evaluation.

Executes complete evaluations across all 5 agents on official prepared datasets:
1. Agent 1 Classification Evaluation (Random Forest)
2. Agent 1 vs Agent 3 Fusion Comparative Evaluation
3. Agent 2 Anomaly Detection Evaluation (Isolation Forest, score-inverted)
4. Seen vs Unseen Feature Generalization
5. Leave-One-Attack-Out (LOAO) 4-Trial Zero-Day Experiments
6. Agent 1 Probability Calibration (Isotonic / Platt scaling)
7. Agent 4 Temporal Correlation & Campaign Detection
8. Agent 5 Adaptive Defense 4-Way Configuration Comparison
9. Publication Plot Generation (PNG & SVG)
10. Master Summary Assembly & Audit Verification
"""
from __future__ import annotations

import logging
from pathlib import Path
import sys
import time

BASE_DIR = Path(__file__).resolve().parent.parent
SRC_DIR = BASE_DIR / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

import pandas as pd

from cybersentinel.agents.anomaly_detection import AnomalyDetectionAgent
from cybersentinel.agents.fusion import EvidenceFusionAgent
from cybersentinel.agents.threat_detection import ThreatDetectionAgent
from cybersentinel.evaluation import (
    build_master_summary,
    evaluate_adaptive_defense,
    evaluate_anomaly_detection,
    evaluate_classifier,
    evaluate_classifier_vs_fusion,
    evaluate_leave_one_attack_out,
    evaluate_probability_calibration,
    evaluate_seen_unseen_generalization,
    evaluate_temporal_correlation,
    generate_all_plots,
    get_system_metadata,
    save_evaluation_report,
)

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s [%(name)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("evaluate_full_system")


def main():
    start_total = time.perf_counter()
    logger.info("=" * 70)
    logger.info("CYBERSENTINEL COMPREHENSIVE MULTI-AGENT EVALUATION FRAMEWORK")
    logger.info("=" * 70)

    eval_data_path = BASE_DIR / "data" / "processed" / "eval_prepared.parquet"
    train_data_path = BASE_DIR / "data" / "processed" / "training_prepared.parquet"
    threat_model_path = BASE_DIR / "models" / "threat_detection" / "model.joblib"
    anomaly_model_path = BASE_DIR / "models" / "anomaly_detection" / "model.joblib"
    output_dir = BASE_DIR / "outputs" / "evaluation"
    plots_dir = output_dir / "plots"

    if not eval_data_path.is_file():
        raise FileNotFoundError(f"Evaluation dataset missing: {eval_data_path}")
    if not threat_model_path.is_file() or not anomaly_model_path.is_file():
        raise FileNotFoundError("Model artifacts missing. Ensure both A1 and A2 models are trained.")

    # 1. Load Data
    logger.info(f"Loading official evaluation dataset from {eval_data_path}...")
    eval_df = pd.read_parquet(eval_data_path)
    logger.info(f"Loaded evaluation dataset: {eval_df.shape[0]:,} rows, {eval_df.shape[1]} columns.")

    # 2. Load Models
    logger.info("Loading Agent 1 (ThreatDetectionAgent) and Agent 2 (AnomalyDetectionAgent)...")
    threat_agent = ThreatDetectionAgent.load(threat_model_path)
    anomaly_agent = AnomalyDetectionAgent.load(anomaly_model_path)
    fusion_agent = EvidenceFusionAgent()

    metadata = get_system_metadata(BASE_DIR)

    # -------------------------------------------------------------------------
    # Phase 2: Classification Evaluation (Agent 1)
    # -------------------------------------------------------------------------
    logger.info("\n--- [Phase 2] Evaluating Agent 1 Classifier (Random Forest) ---")
    classification_report = evaluate_classifier(eval_df, threat_agent)
    save_evaluation_report("classification", classification_report, output_dir, metadata)
    logger.info(f"A1 Accuracy: {classification_report['metrics']['accuracy']:.6f} | "
                f"Macro F1: {classification_report['metrics']['macro_f1']:.6f} | "
                f"Benign FPR: {classification_report['metrics']['benign_false_positive_rate']:.6f}")

    # -------------------------------------------------------------------------
    # Phase 3: Classifier vs Fusion Evaluation (Agent 1 vs Agent 3)
    # -------------------------------------------------------------------------
    logger.info("\n--- [Phase 3] Evaluating Classifier vs Fusion (Agent 1 vs Agent 3) ---")
    fusion_report = evaluate_classifier_vs_fusion(eval_df, threat_agent, anomaly_agent, fusion_agent)
    save_evaluation_report("fusion", fusion_report, output_dir, metadata)
    logger.info(f"A1 Accuracy: {fusion_report['summary']['a1_accuracy']:.6f} -> "
                f"A3 Accuracy: {fusion_report['summary']['a3_accuracy']:.6f} | "
                f"Net Improvement: {fusion_report['summary']['net_improvement_percentage']:+.4f}% | "
                f"Action Distribution: {fusion_report['summary']['action_distribution']}")

    # -------------------------------------------------------------------------
    # Phase 4: Anomaly Detection Evaluation (Agent 2)
    # -------------------------------------------------------------------------
    logger.info("\n--- [Phase 4] Evaluating Agent 2 Anomaly Detection (Isolation Forest) ---")
    anomaly_report = evaluate_anomaly_detection(eval_df, anomaly_agent)
    save_evaluation_report("anomaly", anomaly_report, output_dir, metadata)
    logger.info(f"A2 ROC-AUC (Inverted): {anomaly_report['roc_auc']:.6f} | "
                f"PR-AUC (Avg Precision): {anomaly_report['average_precision']:.6f} | "
                f"Operational Benign FPR: {anomaly_report['operational_metrics']['benign_fpr']:.6f} | "
                f"Attack Recall: {anomaly_report['operational_metrics']['attack_recall']:.6f}")

    # -------------------------------------------------------------------------
    # Phase 5: Seen vs Unseen Generalization
    # -------------------------------------------------------------------------
    logger.info("\n--- [Phase 5] Evaluating Seen vs Unseen Generalization ---")
    logger.info(f"Reading training dataset from {train_data_path} for exact feature hashing...")
    train_df = pd.read_parquet(train_data_path)
    generalization_report = evaluate_seen_unseen_generalization(train_df, eval_df, threat_agent)
    save_evaluation_report("generalization", generalization_report, output_dir, metadata)
    gen_sum = generalization_report["generalization_summary"]
    logger.info(f"Generalization: {gen_sum['seen_samples_count']:,} seen ({gen_sum['seen_percentage']:.2f}%), "
                f"{gen_sum['unseen_samples_count']:,} unseen ({gen_sum['unseen_percentage']:.2f}%) | "
                f"Seen Acc: {generalization_report['seen_evaluation']['accuracy']:.6f} | "
                f"Unseen Acc: {generalization_report['unseen_evaluation']['accuracy']:.6f}")

    # -------------------------------------------------------------------------
    # Phase 6: Leave-One-Attack-Out (LOAO) Experiments
    # -------------------------------------------------------------------------
    logger.info("\n--- [Phase 6] Evaluating Leave-One-Attack-Out (LOAO) 4 Trials ---")
    loao_report = evaluate_leave_one_attack_out(
        train_df=train_df,
        eval_df=eval_df,
        omitted_classes=["BRUTE_FORCE", "DOS", "DDOS", "PORT_SCAN"],
        max_train_samples=80000,
    )
    save_evaluation_report("loao", loao_report, output_dir, metadata)
    loao_sum = loao_report["loao_summary"]
    logger.info(f"LOAO Mean Unseen Attack Detection (A1): {loao_sum['mean_a1_unseen_attack_detection']:.4f} | "
                f"Mean Unseen Anomaly Recall (A2): {loao_sum['mean_a2_unseen_anomaly_recall']:.4f} | "
                f"Mean Containment (A3): {loao_sum['mean_a3_unseen_containment_rate']:.4f}")

    # -------------------------------------------------------------------------
    # Phase 7: Probability Calibration (Agent 1)
    # -------------------------------------------------------------------------
    logger.info("\n--- [Phase 7] Evaluating Probability Calibration (Agent 1) ---")
    calibration_report = evaluate_probability_calibration(
        train_df=train_df,
        eval_df=eval_df,
        cal_fraction=0.20,
    )
    save_evaluation_report("calibration", calibration_report, output_dir, metadata)
    cal_eval = calibration_report["evaluation"]
    logger.info(f"Calibration Method: {cal_eval['method']} | "
                f"Uncalibrated ECE: {cal_eval['uncalibrated']['ece']:.6f} -> "
                f"Calibrated ECE: {cal_eval['calibrated']['ece']:.6f} | "
                f"Brier: {cal_eval['uncalibrated']['brier_score']:.6f} -> {cal_eval['calibrated']['brier_score']:.6f}")

    # -------------------------------------------------------------------------
    # Phase 8: Temporal Correlation Evaluation (Agent 4)
    # -------------------------------------------------------------------------
    logger.info("\n--- [Phase 8] Evaluating Agent 4 Temporal Correlation ---")
    temporal_report = evaluate_temporal_correlation(eval_df)
    save_evaluation_report("temporal", temporal_report, output_dir, metadata)
    t_sum = temporal_report["evaluation_summary"]
    logger.info(f"Total Campaigns: {t_sum['total_campaigns_detected']} | "
                f"Campaign Precision: {t_sum['campaign_precision']:.4f} | "
                f"DDoS: {t_sum['campaigns_by_type'].get('DDOS', 0)} | "
                f"PortScan: {t_sum['campaigns_by_type'].get('PORT_SCAN', 0)} | "
                f"Mean Delay: {t_sum['mean_detection_delay_flows']:.1f} flows")

    # -------------------------------------------------------------------------
    # Phase 9: Adaptive Defense Evaluation (Agent 5)
    # -------------------------------------------------------------------------
    logger.info("\n--- [Phase 9] Evaluating Agent 5 Adaptive Defense 4-Way Comparison ---")
    defense_report = evaluate_adaptive_defense(eval_df, threat_agent, anomaly_agent)
    save_evaluation_report("defense", defense_report, output_dir, metadata)
    def_comp = defense_report["comparison_table"]
    cfg4 = def_comp["config_4_temporal_plus_defense"]
    logger.info(f"Full System (Config 4): Containment Rate: {cfg4['containment_rate']:.6f} | "
                f"False Blocking: {cfg4['false_blocking_rate']:.6f} | "
                f"Benign Preservation: {cfg4['benign_preservation']:.6f} | "
                f"Policies: {cfg4['policies_created']}")

    # -------------------------------------------------------------------------
    # Phase 10: Master Summary & Plotting
    # -------------------------------------------------------------------------
    logger.info("\n--- [Phase 10] Assembling Master Summary and Visualizations ---")
    summary_report = build_master_summary(
        base_dir=BASE_DIR,
        classification_data=classification_report,
        fusion_data=fusion_report,
        anomaly_data=anomaly_report,
        generalization_data=generalization_report,
        calibration_data=calibration_report,
        loao_data=loao_report,
        temporal_data=temporal_report,
        defense_data=defense_report,
    )
    summary_file = save_evaluation_report("summary", summary_report, output_dir, metadata)
    logger.info(f"Master summary saved to: {summary_file}")

    plots = generate_all_plots(
        output_dir=plots_dir,
        classification_data=classification_report,
        fusion_data=fusion_report,
        anomaly_data=anomaly_report,
        generalization_data=generalization_report,
        calibration_data=calibration_report,
        loao_data=loao_report,
        temporal_data=temporal_report,
        defense_data=defense_report,
    )
    logger.info(f"Generated {len(plots)} publication-quality plot artifacts in {plots_dir}.")

    elapsed_total = time.perf_counter() - start_total
    logger.info(f"\n=======================================================")
    logger.info(f"FULL EVALUATION COMPLETE IN {elapsed_total:.2f}s ({elapsed_total/60:.2f} mins)")
    logger.info(f"Reports saved in: {output_dir}")
    logger.info(f"=======================================================\n")


if __name__ == "__main__":
    main()
