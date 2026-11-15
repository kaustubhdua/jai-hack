"""Configurable training and cross-dataset evaluation.

This experiment pipeline is separate from the legacy five-class replay models:
it supports explicit arbitrary label taxonomies and records feature contracts.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import platform
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import LabelEncoder, StandardScaler


@dataclass
class ExperimentConfig:
    model: str = "random_forest"
    label_column: str = "label"
    feature_columns: list[str] | None = None
    drop_columns: list[str] | None = None
    label_mapping: dict[str, str] | None = None
    random_state: int = 42
    n_estimators: int = 300
    max_depth: int | None = None
    contamination: float = 0.02
    torch_epochs: int = 20
    torch_hidden: int = 128


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _features(frame: pd.DataFrame, config: ExperimentConfig) -> list[str]:
    if config.feature_columns:
        if config.label_column in config.feature_columns:
            raise ValueError("The target label column cannot be included in model features.")
        missing = sorted(set(config.feature_columns) - set(frame.columns))
        if missing:
            raise ValueError(f"Configured feature columns are missing: {missing}")
        columns = list(config.feature_columns)
    else:
        excluded = set(config.drop_columns or []) | {config.label_column}
        excluded |= {name for name in frame.columns if str(name).casefold() in {
            "id", "flow_id", "record_id", "timestamp", "stime", "srcip", "dstip",
            "source_ip", "destination_ip", "attack_cat", "label",
        }}
        columns = [name for name in frame.select_dtypes(include="number").columns if name not in excluded]
    if not columns:
        raise ValueError("No numeric model features remain after feature selection.")
    return columns


def _mapped_labels(series: pd.Series, mapping: dict[str, str] | None) -> pd.Series:
    labels = series.astype("string").str.strip()
    if labels.isna().any() or (labels == "").any():
        raise ValueError("Label column contains missing or empty values.")
    if mapping is None:
        return labels.astype(str)
    normalized_map = {str(key).strip(): str(value).strip() for key, value in mapping.items()}
    unknown = sorted(set(labels.astype(str)) - set(normalized_map))
    if unknown:
        raise ValueError(f"Label mapping does not cover source labels: {unknown[:20]}")
    return labels.map(normalized_map).astype(str)


def _build_estimator(config: ExperimentConfig, classification: bool = True):
    model = config.model.casefold()
    if model == "random_forest":
        return Pipeline([
            ("imputer", SimpleImputer(strategy="median")),
            ("model", RandomForestClassifier(
                n_estimators=config.n_estimators, max_depth=config.max_depth,
                class_weight="balanced_subsample", random_state=config.random_state,
                n_jobs=-1,
            )),
        ])
    if model == "xgboost":
        try:
            from xgboost import XGBClassifier, XGBRegressor
        except ImportError as exc:
            raise RuntimeError("Install the optional dependency with: pip install .[xgboost]") from exc
        return XGBoostClassifier(config)
    if model == "isolation_forest":
        return Pipeline([
            ("imputer", SimpleImputer(strategy="median")),
            ("model", IsolationForest(
                n_estimators=config.n_estimators, contamination=config.contamination,
                random_state=config.random_state, n_jobs=-1,
            )),
        ])
    if model == "pytorch_mlp":
        return TorchMLP(config)
    raise ValueError("model must be random_forest, xgboost, isolation_forest, or pytorch_mlp")


class XGBoostClassifier:
    """Label-encoding wrapper because XGBoost expects contiguous integer classes."""
    def __init__(self, config: ExperimentConfig):
        self.config = config
        self.imputer = SimpleImputer(strategy="median")
        self.encoder = LabelEncoder()
        self.estimator = None

    def fit(self, X, y):
        try:
            from xgboost import XGBClassifier
        except ImportError as exc:
            raise RuntimeError("Install the optional dependency with: pip install .[xgboost]") from exc
        values = self.imputer.fit_transform(X)
        encoded = self.encoder.fit_transform(y)
        self.estimator = XGBClassifier(
            n_estimators=self.config.n_estimators,
            max_depth=self.config.max_depth or 6,
            random_state=self.config.random_state, n_jobs=-1,
            eval_metric="mlogloss",
        )
        self.estimator.fit(values, encoded)
        return self

    def predict(self, X):
        values = self.imputer.transform(X)
        return self.encoder.inverse_transform(self.estimator.predict(values).astype(int))

    def predict_proba(self, X):
        return self.estimator.predict_proba(self.imputer.transform(X))


class TorchMLP:
    """Small optional PyTorch classifier; imported only when selected."""
    def __init__(self, config: ExperimentConfig):
        self.config = config
        self.imputer = SimpleImputer(strategy="median")
        self.scaler = StandardScaler()
        self.model = None
        self.classes_ = None

    def fit(self, X, y):
        try:
            import torch
            from torch import nn
        except ImportError as exc:
            raise RuntimeError("Install optional PyTorch before selecting pytorch_mlp.") from exc
        torch.manual_seed(self.config.random_state)
        Xv = self.scaler.fit_transform(self.imputer.fit_transform(X)).astype("float32")
        encoder = LabelEncoder()
        yv = encoder.fit_transform(y).astype("int64")
        self.classes_ = encoder.classes_
        self.model = nn.Sequential(
            nn.Linear(Xv.shape[1], self.config.torch_hidden), nn.ReLU(),
            nn.Dropout(0.2), nn.Linear(self.config.torch_hidden, len(self.classes_)),
        )
        optimizer = torch.optim.AdamW(self.model.parameters(), lr=1e-3)
        loss_fn = nn.CrossEntropyLoss()
        features = torch.from_numpy(Xv)
        targets = torch.from_numpy(yv)
        self.model.train()
        for _ in range(self.config.torch_epochs):
            optimizer.zero_grad()
            loss = loss_fn(self.model(features), targets)
            loss.backward()
            optimizer.step()
        return self

    def predict(self, X):
        import torch
        Xv = self.scaler.transform(self.imputer.transform(X)).astype("float32")
        self.model.eval()
        with torch.no_grad():
            indexes = self.model(torch.from_numpy(Xv)).argmax(dim=1).numpy()
        return self.classes_[indexes]

    def predict_proba(self, X):
        import torch
        Xv = self.scaler.transform(self.imputer.transform(X)).astype("float32")
        self.model.eval()
        with torch.no_grad():
            return torch.softmax(self.model(torch.from_numpy(Xv)), dim=1).numpy()


def train_experiment(
    training: pd.DataFrame,
    config: ExperimentConfig,
    output_dir: str | Path,
    dataset_manifest: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if config.label_column not in training.columns and config.model != "isolation_forest":
        raise ValueError(f"Training label column {config.label_column!r} is missing.")
    columns = _features(training, config)
    X = training[columns].apply(pd.to_numeric, errors="coerce").replace([np.inf, -np.inf], np.nan)
    X = X.loc[:, X.notna().any(axis=0)]
    columns = list(X.columns)
    if not columns:
        raise ValueError("Every selected training feature is empty or non-finite.")
    if len(training) < 2:
        raise ValueError("At least two training rows are required.")
    estimator = _build_estimator(config, config.model != "isolation_forest")
    labels = None
    if config.model == "isolation_forest":
        estimator.fit(X)
    else:
        labels = _mapped_labels(training[config.label_column], config.label_mapping)
        if labels.nunique() < 2:
            raise ValueError("Classification requires at least two distinct target classes.")
        estimator.fit(X, labels)
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    model_path = output / "model.joblib"
    training_stats = {
        column: {
            "mean": float(X[column].mean()),
            "std": float(X[column].std(ddof=0)) if float(X[column].std(ddof=0)) > 0 else 1.0,
            "median": float(X[column].median()),
            "q25": float(X[column].quantile(0.25)),
            "q75": float(X[column].quantile(0.75)),
        } for column in columns
    }
    joblib.dump({"artifact_version": 1, "estimator": estimator, "config": asdict(config), "features": columns,
                 "training_stats": training_stats,
                 "classes": sorted(labels.unique().tolist()) if labels is not None else None}, model_path)
    manifest = {
        "artifact_version": 1, "model_version": "cybersentinel-experiment-v1",
        "model": config.model, "config": asdict(config), "features": columns,
        "classes": sorted(labels.unique().tolist()) if labels is not None else None,
        "training_rows": int(len(training)), "dataset": dataset_manifest or {},
        "model_path": str(model_path), "model_sha256": _sha256(model_path),
        "runtime": {
            "python": platform.python_version(), "pandas": pd.__version__,
            "numpy": np.__version__, "scikit_learn": sklearn.__version__,
            "joblib": joblib.__version__,
        },
        "scoring_mode": "classification" if labels is not None else "unsupervised_anomaly",
    }
    (output / "experiment.json").write_text(json.dumps(manifest, indent=2, default=str), encoding="utf-8")
    return manifest


def evaluate_cross_dataset(
    model_path: str | Path,
    target: pd.DataFrame,
    label_column: str,
    label_mapping: dict[str, str] | None = None,
) -> dict[str, Any]:
    bundle = joblib.load(model_path)
    if bundle.get("artifact_version") != 1:
        raise ValueError("Unsupported model artifact version.")
    estimator, features = bundle["estimator"], bundle["features"]
    missing = sorted(set(features) - set(target.columns))
    if missing:
        raise ValueError(f"Target dataset is missing {len(missing)} trained feature(s): {missing[:30]}")
    X = target[features].apply(pd.to_numeric, errors="coerce").replace([np.inf, -np.inf], np.nan)
    drift = []
    for column in features:
        train_stats = bundle.get("training_stats", {}).get(column, {})
        target_mean = float(X[column].mean()) if X[column].notna().any() else None
        if target_mean is not None:
            scale = float(train_stats.get("std") or 1.0) or 1.0
            smd = abs(target_mean - float(train_stats.get("mean", 0.0))) / scale
            drift.append({"feature": column, "standardized_mean_difference": round(smd, 6)})
    drift.sort(key=lambda item: item["standardized_mean_difference"], reverse=True)
    drift_index = float(np.mean([item["standardized_mean_difference"] for item in drift])) if drift else 0.0
    drift_summary = {
        "index_mean_absolute_standardized_difference": round(drift_index, 6),
        "high_drift_features": [item for item in drift if item["standardized_mean_difference"] >= 0.5][:20],
        "top_features": drift[:20],
        "interpretation": "Descriptive feature-distribution shift only; not a causal explanation or performance metric.",
    }
    if bundle["config"]["model"] == "isolation_forest":
        scores = estimator.decision_function(X)
        predictions = estimator.predict(X)
        return {
            "mode": "unsupervised_anomaly", "rows": len(target),
            "anomaly_count": int((predictions == -1).sum()),
            "anomaly_fraction": float((predictions == -1).mean()),
            "mean_anomaly_score": float(np.mean(-scores)),
            "feature_drift": drift_summary,
            "domain_shift_warning": drift_index >= 0.25,
            "trained_features": features, "missing_features": [],
        }
    if label_column not in target.columns:
        raise ValueError(f"Target label column {label_column!r} is missing.")
    y_true = _mapped_labels(target[label_column], label_mapping)
    known = set(bundle["classes"])
    unknown = sorted(set(y_true) - known)
    y_pred = estimator.predict(X)
    return {
        "mode": "cross_dataset_classification", "rows": len(target),
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "macro_f1": float(f1_score(y_true, y_pred, average="macro", zero_division=0)),
        "weighted_f1": float(f1_score(y_true, y_pred, average="weighted", zero_division=0)),
        "classification_report": classification_report(y_true, y_pred, output_dict=True, zero_division=0),
        "confusion_matrix": confusion_matrix(
            y_true, y_pred, labels=list(bundle["classes"]) + unknown
        ).tolist(),
        "classes": list(bundle["classes"]) + unknown, "unknown_target_labels": unknown,
        "trained_features": features, "missing_features": [],
        "feature_drift": drift_summary,
        "domain_shift_warning": bool(unknown or len(set(y_true)) != len(known) or drift_index >= 0.25),
    }
