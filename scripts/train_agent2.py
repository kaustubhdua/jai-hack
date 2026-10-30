"""Train and save Agent 2 (Anomaly Detection) Isolation Forest model."""
import time
import json
from pathlib import Path
import pandas as pd
import numpy as np
import sklearn
from sklearn.ensemble import IsolationForest
import joblib

def train_agent2():
    train_path = Path("data/processed/training_prepared.parquet")
    eval_path = Path("data/processed/eval_prepared.parquet")
    model_dir = Path("models/anomaly_detection")
    model_dir.mkdir(parents=True, exist_ok=True)
    model_out = model_dir / "model.joblib"

    print("Loading prepared training data...")
    train_df = pd.read_parquet(train_path)
    benign_train = train_df[train_df["label"] == "BENIGN"].drop(columns=["label"])
    print(f"Loaded {len(benign_train):,} BENIGN training flows for unsupervised baseline.")

    feature_columns = list(benign_train.columns)

    print("Computing feature profiles on benign traffic...")
    feature_profiles = {}
    for col in feature_columns:
        vals = benign_train[col].to_numpy(dtype=np.float64)
        q01 = float(np.percentile(vals, 1))
        q25 = float(np.percentile(vals, 25))
        q50 = float(np.percentile(vals, 50))
        q75 = float(np.percentile(vals, 75))
        q99 = float(np.percentile(vals, 99))
        iqr = max(q75 - q25, 1e-6)
        feature_profiles[col] = {
            "median": q50,
            "iqr": iqr,
            "q01": q01,
            "q99": q99,
            "mean": float(np.mean(vals)),
            "std": float(np.std(vals))
        }

    print("Fitting Isolation Forest (100 estimators, contamination=0.01, n_jobs=-1)...")
    iso = IsolationForest(
        n_estimators=100,
        max_samples=min(50000, len(benign_train)),
        contamination=0.01,
        random_state=42,
        n_jobs=-1,
        verbose=1
    )

    t0 = time.time()
    iso.fit(benign_train)
    fit_duration = time.time() - t0
    print(f"Isolation Forest fitted in {fit_duration:.2f}s")

    # Compute defensible threshold: 1st percentile of benign decision function
    print("Calibrating anomaly threshold on benign sample...")
    sample_scores = iso.decision_function(benign_train.iloc[:20000])
    threshold = float(np.percentile(sample_scores, 1.0))
    print(f"Defensible anomaly threshold (1st percentile of benign): {threshold:.4f}")

    # Evaluate on eval dataset
    eval_df = pd.read_parquet(eval_path)
    X_eval = eval_df.drop(columns=["label"])
    y_eval = eval_df["label"].astype(str)

    print("Evaluating anomaly detection on eval split...")
    eval_scores = iso.decision_function(X_eval)
    eval_is_anomaly = eval_scores < threshold

    # Print anomaly detection rate per class
    eval_results = {}
    for cls in sorted(y_eval.unique()):
        cls_mask = (y_eval == cls)
        cls_total = int(cls_mask.sum())
        cls_anomalies = int((eval_is_anomaly & cls_mask).sum())
        rate = cls_anomalies / cls_total
        eval_results[cls] = {
            "total": cls_total,
            "flagged_as_anomaly": cls_anomalies,
            "anomaly_rate": rate
        }
        print(f"  Class {cls:12s}: {cls_anomalies:,} / {cls_total:,} flagged ({rate:.2%})")

    benign_fpr = eval_results["BENIGN"]["anomaly_rate"]
    attack_mask = (y_eval != "BENIGN")
    attack_recall = int((eval_is_anomaly & attack_mask).sum()) / int(attack_mask.sum())
    print(f"\nBenign False Positive Rate: {benign_fpr:.2%}")
    print(f"Overall Attack Detection Recall (as Anomaly): {attack_recall:.2%}")

    # Save model artifact
    metadata = {
        "artifact_format_version": 1,
        "algorithm": "IsolationForest",
        "training_rows": len(benign_train),
        "feature_count": len(feature_columns),
        "threshold": threshold,
        "threshold_strategy": "1st percentile of benign training flows (calibrated ~1% FPR)",
        "benign_fpr_eval": benign_fpr,
        "attack_recall_eval": attack_recall,
        "fit_duration_seconds": fit_duration
    }

    payload = {
        "artifact_format_version": 1,
        "estimator": iso,
        "feature_columns": feature_columns,
        "feature_profiles": feature_profiles,
        "threshold": threshold,
        "metadata": metadata
    }

    joblib.dump(payload, model_out, compress=3)
    print(f"Saved Anomaly Detection model to {model_out} ({model_out.stat().st_size:,} bytes)")

if __name__ == "__main__":
    train_agent2()

