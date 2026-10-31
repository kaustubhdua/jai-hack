"""Visualization generators for CyberSentinel Evaluation Framework.

Generates publication-quality charts (PNG and SVG):
- Confusion matrices (A1 vs A3 Fusion)
- ROC and PR curves (A2 Anomaly Detection)
- Reliability diagrams & confidence calibration (A1)
- Generalization bars (Seen vs Unseen feature performance)
- Leave-One-Attack-Out (LOAO) detection and containment rates
- Temporal correlation campaign detection delay and precision
- Adaptive defense 4-way configuration comparison
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger("cybersentinel.evaluation.plots")


def generate_all_plots(
    output_dir: Path,
    classification_data: dict[str, Any],
    fusion_data: dict[str, Any],
    anomaly_data: dict[str, Any],
    generalization_data: dict[str, Any],
    calibration_data: dict[str, Any],
    loao_data: dict[str, Any],
    temporal_data: dict[str, Any],
    defense_data: dict[str, Any],
) -> list[Path]:
    """Generate all evaluation plots and save to output_dir."""
    output_dir.mkdir(parents=True, exist_ok=True)
    saved_plots: list[Path] = []

    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        import numpy as np

        # 1. Confusion Matrix Comparison (A1 vs A3 Fusion)
        try:
            fig, axes = plt.subplots(1, 2, figsize=(14, 6))
            classes = ["BENIGN", "BRUTE_FORCE", "DOS", "DDOS", "PORT_SCAN"]

            cm_a1 = np.array(classification_data.get("confusion_matrix", [[0]*5]*5))
            cm_a3 = np.array(fusion_data.get("confusion_matrix_after_fusion", cm_a1))

            im0 = axes[0].imshow(cm_a1, cmap="Blues", interpolation="nearest")
            axes[0].set_title("Agent 1 (Random Forest) Confusion Matrix", fontsize=12, fontweight="bold")
            axes[0].set_xticks(range(len(classes)))
            axes[0].set_xticklabels(classes, rotation=45, ha="right")
            axes[0].set_yticks(range(len(classes)))
            axes[0].set_yticklabels(classes)
            axes[0].set_ylabel("True Label")
            axes[0].set_xlabel("Predicted Label")
            fig.colorbar(im0, ax=axes[0], fraction=0.046, pad=0.04)

            im1 = axes[1].imshow(cm_a3, cmap="Greens", interpolation="nearest")
            axes[1].set_title("Agent 3 (Evidence Fusion) Confusion Matrix", fontsize=12, fontweight="bold")
            axes[1].set_xticks(range(len(classes)))
            axes[1].set_xticklabels(classes, rotation=45, ha="right")
            axes[1].set_yticks(range(len(classes)))
            axes[1].set_yticklabels(classes)
            axes[1].set_ylabel("True Label")
            axes[1].set_xlabel("Predicted Label")
            fig.colorbar(im1, ax=axes[1], fraction=0.046, pad=0.04)

            plt.tight_layout()
            p1 = output_dir / "confusion_matrix_comparison.png"
            plt.savefig(p1, dpi=200)
            p1_svg = output_dir / "confusion_matrix_comparison.svg"
            plt.savefig(p1_svg)
            plt.close(fig)
            saved_plots.extend([p1, p1_svg])
        except Exception as exc:
            logger.warning(f"Could not generate confusion matrix plot: {exc}")

        # 2. Anomaly Detection ROC & Precision-Recall Curves
        try:
            fig, axes = plt.subplots(1, 2, figsize=(14, 6))
            roc_curve = anomaly_data.get("roc_curve", {})
            fpr = roc_curve.get("fpr", [0, 1])
            tpr = roc_curve.get("tpr", [0, 1])
            roc_auc = anomaly_data.get("roc_auc", 0.5)

            axes[0].plot(fpr, tpr, color="#2563eb", lw=2, label=f"Isolation Forest (AUC = {roc_auc:.4f})")
            axes[0].plot([0, 1], [0, 1], color="#94a3b8", lw=1.5, linestyle="--", label="Random Chance")
            axes[0].set_xlim([0.0, 1.0])
            axes[0].set_ylim([0.0, 1.05])
            axes[0].set_xlabel("False Positive Rate (Benign FPR)")
            axes[0].set_ylabel("True Positive Rate (Attack Recall)")
            axes[0].set_title("Agent 2 ROC Curve (Score Inverted)", fontsize=12, fontweight="bold")
            axes[0].grid(True, alpha=0.3)
            axes[0].legend(loc="lower right")

            pr_curve = anomaly_data.get("precision_recall_curve", {})
            precision = pr_curve.get("precision", [1, 0])
            recall = pr_curve.get("recall", [0, 1])
            ap = anomaly_data.get("average_precision", 0.0)

            axes[1].plot(recall, precision, color="#10b981", lw=2, label=f"PR Curve (AP = {ap:.4f})")
            axes[1].set_xlim([0.0, 1.0])
            axes[1].set_ylim([0.0, 1.05])
            axes[1].set_xlabel("Recall (Attack Detection)")
            axes[1].set_ylabel("Precision")
            axes[1].set_title("Agent 2 Precision-Recall Curve", fontsize=12, fontweight="bold")
            axes[1].grid(True, alpha=0.3)
            axes[1].legend(loc="lower left")

            plt.tight_layout()
            p2 = output_dir / "anomaly_roc_pr_curves.png"
            plt.savefig(p2, dpi=200)
            p2_svg = output_dir / "anomaly_roc_pr_curves.svg"
            plt.savefig(p2_svg)
            plt.close(fig)
            saved_plots.extend([p2, p2_svg])
        except Exception as exc:
            logger.warning(f"Could not generate ROC/PR plots: {exc}")

        # 3. Probability Calibration & Reliability Diagram
        try:
            fig, ax = plt.subplots(figsize=(8, 6))
            cal_eval = calibration_data.get("evaluation", {})
            uncal = cal_eval.get("uncalibrated", {})
            cal = cal_eval.get("calibrated", {})

            uncal_bins = uncal.get("reliability_bins", [])
            cal_bins = cal.get("reliability_bins", [])

            ax.plot([0, 1], [0, 1], color="#94a3b8", linestyle="--", label="Perfect Calibration")

            if uncal_bins:
                u_conf = [b["mean_predicted_probability"] for b in uncal_bins]
                u_acc = [b["empirical_accuracy"] for b in uncal_bins]
                ax.plot(u_conf, u_acc, marker="o", color="#ef4444", label=f"Uncalibrated (ECE = {uncal.get('ece', 0):.4f})")

            if cal_bins:
                c_conf = [b["mean_predicted_probability"] for b in cal_bins]
                c_acc = [b["empirical_accuracy"] for b in cal_bins]
                ax.plot(c_conf, c_acc, marker="s", color="#10b981", label=f"Calibrated (ECE = {cal.get('ece', 0):.4f})")

            ax.set_xlabel("Mean Predicted Confidence")
            ax.set_ylabel("Empirical Accuracy")
            ax.set_title("A1 Classifier Reliability Diagram (Probability Calibration)", fontsize=12, fontweight="bold")
            ax.grid(True, alpha=0.3)
            ax.legend(loc="upper left")

            plt.tight_layout()
            p3 = output_dir / "calibration_reliability_diagram.png"
            plt.savefig(p3, dpi=200)
            p3_svg = output_dir / "calibration_reliability_diagram.svg"
            plt.savefig(p3_svg)
            plt.close(fig)
            saved_plots.extend([p3, p3_svg])
        except Exception as exc:
            logger.warning(f"Could not generate calibration plot: {exc}")

        # 4. Seen vs Unseen Generalization
        try:
            fig, ax = plt.subplots(figsize=(8, 5))
            seen_eval = generalization_data.get("seen_evaluation", {})
            unseen_eval = generalization_data.get("unseen_evaluation", {})

            metrics = ["Accuracy", "Macro Recall", "Attack Detection Rate"]
            seen_vals = [
                seen_eval.get("accuracy", 0.0),
                seen_eval.get("macro_recall", 0.0),
                seen_eval.get("attack_detection_rate", 0.0),
            ]
            unseen_vals = [
                unseen_eval.get("accuracy", 0.0),
                unseen_eval.get("macro_recall", 0.0),
                unseen_eval.get("attack_detection_rate", 0.0),
            ]

            x = np.arange(len(metrics))
            width = 0.35

            ax.bar(x - width/2, seen_vals, width, label="Seen Feature Patterns", color="#3b82f6")
            ax.bar(x + width/2, unseen_vals, width, label="Unseen Feature Patterns", color="#8b5cf6")

            ax.set_ylabel("Score (0.0 - 1.0)")
            ax.set_title("Generalization: Seen vs Unseen Feature-Vector Performance", fontsize=12, fontweight="bold")
            ax.set_xticks(x)
            ax.set_xticklabels(metrics)
            ax.set_ylim([0.0, 1.1])
            ax.grid(axis="y", alpha=0.3)
            ax.legend()

            plt.tight_layout()
            p4 = output_dir / "generalization_seen_vs_unseen.png"
            plt.savefig(p4, dpi=200)
            p4_svg = output_dir / "generalization_seen_vs_unseen.svg"
            plt.savefig(p4_svg)
            plt.close(fig)
            saved_plots.extend([p4, p4_svg])
        except Exception as exc:
            logger.warning(f"Could not generate generalization plot: {exc}")

        # 5. Leave-One-Attack-Out (LOAO) Comparison
        try:
            fig, ax = plt.subplots(figsize=(10, 6))
            trials = loao_data.get("trials", {})
            classes = list(trials.keys())
            if classes:
                a1_unseen = [trials[c].get("a1_unseen_attack_detection_rate", 0.0) for c in classes]
                a2_anomaly = [trials[c].get("a2_unseen_anomaly_recall", 0.0) for c in classes]
                a3_contain = [trials[c].get("a3_unseen_containment_rate", 0.0) for c in classes]

                x = np.arange(len(classes))
                w = 0.25

                ax.bar(x - w, a1_unseen, w, label="A1 Direct Attack Detection", color="#f59e0b")
                ax.bar(x, a2_anomaly, w, label="A2 Anomaly Detection Recall", color="#3b82f6")
                ax.bar(x + w, a3_contain, w, label="A3 Final Fusion Containment", color="#10b981")

                ax.set_ylabel("Detection / Containment Rate")
                ax.set_title("Leave-One-Attack-Out (LOAO) Zero-Day Attack Resilience", fontsize=12, fontweight="bold")
                ax.set_xticks(x)
                ax.set_xticklabels([f"Omitted: {c}" for c in classes])
                ax.set_ylim([0.0, 1.1])
                ax.grid(axis="y", alpha=0.3)
                ax.legend()

                plt.tight_layout()
                p5 = output_dir / "loao_evaluation.png"
                plt.savefig(p5, dpi=200)
                p5_svg = output_dir / "loao_evaluation.svg"
                plt.savefig(p5_svg)
                plt.close(fig)
                saved_plots.extend([p5, p5_svg])
        except Exception as exc:
            logger.warning(f"Could not generate LOAO plot: {exc}")

        # 6. Adaptive Defense 4-Way Configuration Comparison
        try:
            fig, ax = plt.subplots(figsize=(10, 6))
            comp_table = defense_data.get("comparison_table", {})
            cfg_names = [v.get("name", k) for k, v in comp_table.items()]
            containment = [v.get("containment_rate", 0.0) for v in comp_table.values()]
            false_blocks = [v.get("false_blocking_rate", 0.0) for v in comp_table.values()]

            x = np.arange(len(cfg_names))
            w = 0.35

            ax.bar(x - w/2, containment, w, label="Attack Containment Rate", color="#10b981")
            ax.bar(x + w/2, false_blocks, w, label="Benign False Blocking Rate", color="#ef4444")

            ax.set_ylabel("Rate (0.0 - 1.0)")
            ax.set_title("Adaptive Defense: 4-Way Multi-Agent Configuration Comparison", fontsize=12, fontweight="bold")
            ax.set_xticks(x)
            ax.set_xticklabels(cfg_names, rotation=20, ha="right", fontsize=9)
            ax.set_ylim([0.0, 1.1])
            ax.grid(axis="y", alpha=0.3)
            ax.legend()

            plt.tight_layout()
            p6 = output_dir / "adaptive_defense_comparison.png"
            plt.savefig(p6, dpi=200)
            p6_svg = output_dir / "adaptive_defense_comparison.svg"
            plt.savefig(p6_svg)
            plt.close(fig)
            saved_plots.extend([p6, p6_svg])
        except Exception as exc:
            logger.warning(f"Could not generate defense plot: {exc}")

    except ImportError:
        logger.warning("Matplotlib is not installed. Plot images could not be generated.")

    return saved_plots
