"""Train and save Agent 1 (Threat Detection) model on official data."""
import time
import json
from pathlib import Path
import pandas as pd
import numpy as np
import sklearn
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, f1_score, accuracy_score
import joblib

def train_agent1():
    train_path = Path("data/processed/training_prepared.parquet")
    eval_path = Path("data/processed/eval_prepared.parquet")
    model_dir = Path("models/threat_detection")
    model_dir.mkdir(parents=True, exist_ok=True)
    model_out = model_dir / "model.joblib"

    print("Loading prepared training and eval datasets...")
    t0 = time.time()
    train_df = pd.read_parquet(train_path)
    eval_df = pd.read_parquet(eval_path)
    print(f"Loaded train ({len(train_df)} rows) and eval ({len(eval_df)} rows) in {time.time()-t0:.2f}s")

    X_train = train_df.drop(columns=["label"])
    y_train = train_df["label"].astype(str)

    X_eval = eval_df.drop(columns=["label"])
    y_eval = eval_df["label"].astype(str)

    feature_columns = list(X_train.columns)
    classes = sorted(y_train.unique())
    print(f"Features: {len(feature_columns)}, Target classes: {classes}")

    print("Fitting Random Forest classifier (100 estimators, balanced subsampling, n_jobs=-1)...")
    clf = RandomForestClassifier(
        n_estimators=100,
        max_depth=24,
        min_samples_leaf=2,
        class_weight="balanced_subsample",
        random_state=42,
        n_jobs=-1,
        verbose=1
    )

    t_train_start = time.time()
    clf.fit(X_train, y_train)
    train_duration = time.time() - t_train_start
    print(f"Model fitted in {train_duration:.2f}s")

    print("Saving model artifact...")
    metadata = {
        "artifact_format_version": 1,
        "backend": "random_forest",
        "sklearn_version": sklearn.__version__,
        "training_rows": len(y_train),
        "class_counts": y_train.value_counts().to_dict(),
        "feature_count": len(feature_columns),
        "feature_columns": feature_columns,
        "train_duration_seconds": train_duration,
        "n_estimators": 100,
        "max_depth": 24,
        "min_samples_leaf": 2,
        "random_state": 42
    }
    
    payload = {
        "artifact_format_version": 1,
        "backend": "random_forest",
        "estimator": clf,
        "feature_columns": feature_columns,
        "classes": list(clf.classes_),
        "metadata": metadata
    }
    joblib.dump(payload, model_out, compress=3)
    print(f"Saved model to {model_out} (size: {model_out.stat().st_size:,} bytes)")

    print("Evaluating on eval dataset...")
    t_inf_start = time.time()
    y_pred = clf.predict(X_eval)
    inf_duration = time.time() - t_inf_start
    inf_time_per_sample = inf_duration / len(X_eval)

    acc = accuracy_score(y_eval, y_pred)
    macro_f1 = f1_score(y_eval, y_pred, average="macro")
    print(f"Eval Accuracy: {acc:.4%}")
    print(f"Eval Macro-F1: {macro_f1:.4f}")
    print(f"Eval Inference Time: {inf_duration:.2f}s ({inf_time_per_sample*1000:.3f} ms/flow)")
    print("\nClassification Report:\n", classification_report(y_eval, y_pred, digits=4))

if __name__ == "__main__":
    train_agent1()

