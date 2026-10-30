import json
import csv
import shutil
from pathlib import Path

profile_path = Path("data/processed/dataset_profile.json")
with open(profile_path, "r", encoding="utf-8") as f:
    profile = json.load(f)

prep_path = Path("data/processed/preprocessing_state.json")
with open(prep_path, "r", encoding="utf-8") as f:
    prep_state = json.load(f)

reports_dir = Path("reports")
reports_dir.mkdir(parents=True, exist_ok=True)

# 1. reports/dataset_schema.json
schema_info = {
    "total_columns": profile["schema"]["columns"],
    "columns": profile["schema"]["raw_columns"],
    "id_column": "record_id",
    "target_column": "label",
    "benchmark_classes": prep_state["labels"],
    "numeric_features_raw": profile["schema"]["numeric_features_before_pruning"],
    "numeric_features_prepared": len(prep_state["feature_columns"]),
    "retained_features": prep_state["feature_columns"],
    "dropped_constant_features": prep_state["constant_columns"],
    "dropped_duplicate_features": prep_state["duplicate_columns"]
}
with open(reports_dir / "dataset_schema.json", "w", encoding="utf-8") as f:
    json.dump(schema_info, f, indent=2)

# 2. reports/class_distribution.csv
with open(reports_dir / "class_distribution.csv", "w", newline="", encoding="utf-8") as f:
    writer = csv.writer(f)
    writer.writerow(["class", "training_count", "training_percent", "eval_count", "eval_percent", "total_count", "total_percent"])
    total_train = profile["training"]["rows"]
    total_eval = profile["eval"]["rows"]
    grand_total = total_train + total_eval
    for label, d in profile["class_distribution"].items():
        tot = d["training_count"] + d["eval_count"]
        writer.writerow([
            label,
            d["training_count"],
            f"{d['training_percent']:.4f}",
            d["eval_count"],
            f"{d['eval_percent']:.4f}",
            tot,
            f"{tot / grand_total * 100:.4f}"
        ])

# 3. reports/data_quality_report.json
quality_report = {
    "training_split": profile["training"],
    "eval_split": profile["eval"],
    "feature_overlap_across_splits": profile["feature_overlap_across_splits"],
    "record_id_leakage_diagnostic": profile["record_id_leakage_diagnostic"],
    "preprocessor_rules": {
        "retained_features": prep_state["feature_columns"],
        "dropped_constants": prep_state["constant_columns"],
        "dropped_duplicate_columns": prep_state["duplicate_columns"],
        "medians": prep_state["medians"],
        "robust_centers": prep_state["robust_centers"],
        "robust_scales": prep_state["robust_scales"]
    }
}
with open(reports_dir / "data_quality_report.json", "w", encoding="utf-8") as f:
    json.dump(quality_report, f, indent=2)

# 4. reports/dataset_audit.md
shutil.copy("data/processed/dataset_intelligence_report.md", reports_dir / "dataset_audit.md")
print("Reports generated successfully.")
