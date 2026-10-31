"""Versioned five-class supervised model for network-flow classification."""
from __future__ import annotations
import os, tempfile
from pathlib import Path
from typing import Any
import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import LabelEncoder

BENCHMARK_CLASSES = ("BENIGN", "BRUTE_FORCE", "DOS", "DDOS", "PORT_SCAN")
ARTIFACT_FORMAT_VERSION = 1
DEFAULT_DROP_COLUMNS = {"recordid", "flowid", "sourceip", "destinationip", "srcip", "dstip", "timestamp", "label"}
# Organizer replay metadata is for ordering/correlation, never a supervised feature.
# Match exact snake_case metadata names so the CICIDS feature "Destination Port"
# (with a space) remains a legitimate one of the 78 numeric flow features.
REPLAY_METADATA_COLUMNS = {"seq", "day", "time_offset", "source_port", "destination_port", "protocol"}

def _key(value: Any) -> str:
    return "".join(ch for ch in str(value).casefold() if ch.isalnum())

def numeric_features(frame: pd.DataFrame) -> pd.DataFrame:
    """Keep numeric flow measurements; remove identifiers and non-finite values."""
    if not isinstance(frame, pd.DataFrame):
        frame = pd.DataFrame(frame)
    data = frame.loc[:, ~frame.columns.duplicated()].copy()
    drop = [c for c in data.columns
            if _key(c) in DEFAULT_DROP_COLUMNS or str(c).strip().casefold() in REPLAY_METADATA_COLUMNS]
    if drop:
        data = data.drop(columns=drop)
    converted = {}
    for column in data.columns:
        series = pd.to_numeric(data[column], errors="coerce").replace([np.inf, -np.inf], np.nan)
        if series.notna().any():
            converted[str(column)] = series.astype("float64")
    if not converted:
        raise ValueError("No usable numeric flow features remain; check the CSV schema and label column.")
    return pd.DataFrame(converted, index=data.index)

class ThreatDetectionModel:
    """Random Forest baseline or optional XGBoost experiment.

    Confidence is max predict_proba output; it is model-derived but not calibrated.
    """
    def __init__(self, backend="random_forest", random_state=42, n_estimators=400,
                 max_depth=None, min_samples_leaf=2, n_jobs=-1):
        if backend not in {"random_forest", "xgboost"}:
            raise ValueError("backend must be random_forest or xgboost")
        self.backend, self.random_state = backend, int(random_state)
        self.n_estimators, self.max_depth = int(n_estimators), max_depth
        self.min_samples_leaf, self.n_jobs = int(min_samples_leaf), int(n_jobs)
        self.estimator = self.imputer = self.label_encoder = None
        self.calibration_temperature = 1.0
        self.feature_columns: list[str] = []
        self.metadata: dict[str, Any] = {}

    def fit(self, features: pd.DataFrame, labels) -> "ThreatDetectionModel":
        x = numeric_features(features)
        y = pd.Series(labels, index=features.index if isinstance(features, pd.DataFrame) else None)
        if len(x) != len(y):
            raise ValueError("Feature rows and labels must have the same length.")
        y = y.astype("string").str.strip()
        if y.isna().any() or (y == "").any():
            raise ValueError("Training labels contain missing or empty values.")
        unknown = sorted(set(y.unique()) - set(BENCHMARK_CLASSES))
        if unknown:
            raise ValueError(f"Labels outside the five benchmark classes: {unknown}")
        missing = sorted(set(BENCHMARK_CLASSES) - set(y.unique()))
        if missing:
            raise ValueError(f"Training data must contain all five benchmark classes; missing: {missing}")
        # Feature selection is fitted on training data only; validation never changes this schema.
        self.feature_columns = [str(c) for c in x.columns if x[c].nunique(dropna=True) > 1]
        if not self.feature_columns:
            raise ValueError("All numeric training features are constant.")
        x = x.reindex(columns=self.feature_columns)
        self.imputer = SimpleImputer(strategy="median")
        x_ready = self.imputer.fit_transform(x)
        self.label_encoder = LabelEncoder()
        y_encoded = self.label_encoder.fit_transform(y.astype(str))
        if self.backend == "random_forest":
            classifier = RandomForestClassifier(
                n_estimators=self.n_estimators, max_depth=self.max_depth,
                min_samples_leaf=self.min_samples_leaf, max_features="sqrt",
                class_weight="balanced_subsample", random_state=self.random_state,
                n_jobs=self.n_jobs,
            )
            classifier.fit(x_ready, y_encoded)
        else:
            try:
                from xgboost import XGBClassifier
            except ImportError as exc:
                raise ImportError("Install optional XGBoost with: pip install xgboost") from exc
            from sklearn.utils.class_weight import compute_sample_weight
            classifier = XGBClassifier(
                objective="multi:softprob", num_class=len(BENCHMARK_CLASSES),
                eval_metric="mlogloss", n_estimators=self.n_estimators,
                max_depth=8 if self.max_depth is None else self.max_depth,
                learning_rate=0.08, subsample=0.85, colsample_bytree=0.85,
                tree_method="hist", random_state=self.random_state, n_jobs=self.n_jobs,
            )
            classifier.fit(x_ready, y_encoded,
                           sample_weight=compute_sample_weight("balanced", y_encoded))
        self.estimator = classifier
        self.calibration_temperature = 1.0
        counts = y.value_counts().reindex(BENCHMARK_CLASSES, fill_value=0)
        self.metadata = {
            "artifact_format_version": ARTIFACT_FORMAT_VERSION, "backend": self.backend,
            "sklearn_version": sklearn.__version__, "training_rows": int(len(y)),
            "class_counts": {str(k): int(v) for k, v in counts.items()},
            "feature_count": len(self.feature_columns), "feature_columns": self.feature_columns,
            "excluded_identifier_columns": sorted(DEFAULT_DROP_COLUMNS - {"label"}),
            "excluded_target_columns": ["label"],
            "random_state": self.random_state,
            "confidence_definition": "maximum predict_proba value when temperature=1; temperature-scaled value after held-out validation calibration",
            "confidence_calibrated": False,
            "calibration_temperature": 1.0,
        }
        return self

    def calibrate_confidence(self, validation_features: pd.DataFrame, validation_labels) -> dict[str, float]:
        """Fit scalar temperature scaling on a separate labelled validation partition."""
        self._ready()
        from scipy.optimize import minimize_scalar

        x = numeric_features(validation_features).reindex(columns=self.feature_columns)
        labels = pd.Series(validation_labels).astype("string").str.strip()
        if len(x) != len(labels):
            raise ValueError("Validation features and labels must have equal lengths.")
        if labels.isna().any() or (labels == "").any():
            raise ValueError("Validation labels contain missing or empty values.")
        unknown = sorted(set(labels.astype(str).unique()) - set(BENCHMARK_CLASSES))
        if unknown:
            raise ValueError(f"Validation labels outside the five benchmark classes: {unknown}")
        missing = sorted(set(BENCHMARK_CLASSES) - set(labels.astype(str).unique()))
        if missing:
            raise ValueError(f"Calibration validation data must contain all five classes; missing: {missing}")

        encoded = self.label_encoder.transform(labels.astype(str))
        probabilities = np.asarray(
            self.estimator.predict_proba(self.imputer.transform(x)), dtype=float
        )
        if probabilities.shape[1] != len(self.label_encoder.classes_):
            raise ValueError("Model probability columns do not match the fitted label encoder.")
        eps = np.finfo(float).eps
        logits = np.log(np.clip(probabilities, eps, 1.0))

        def nll(log_temperature: float) -> float:
            temperature = float(np.exp(log_temperature))
            scaled = logits / temperature
            scaled -= scaled.max(axis=1, keepdims=True)
            exp_values = np.exp(scaled)
            calibrated = exp_values / exp_values.sum(axis=1, keepdims=True)
            return float(-np.log(np.clip(calibrated[np.arange(len(encoded)), encoded], eps, 1.0)).mean())

        result = minimize_scalar(nll, bounds=(np.log(0.05), np.log(20.0)), method="bounded")
        if not result.success or not np.isfinite(result.fun):
            raise RuntimeError("Temperature calibration failed to converge.")
        self.calibration_temperature = float(np.exp(result.x))
        self.metadata.update({
            "confidence_definition": "maximum temperature-scaled predict_proba value",
            "confidence_calibrated": True,
            "calibration_method": "scalar_temperature_scaling",
            "calibration_temperature": self.calibration_temperature,
            "calibration_validation_rows": int(len(labels)),
            "calibration_validation_classes": sorted(set(labels.astype(str).unique())),
            "calibration_validation_nll": float(result.fun),
            "calibration_uses_held_out_labels": True,
        })
        return {"temperature": self.calibration_temperature,
                "validation_negative_log_likelihood": float(result.fun),
                "validation_rows": float(len(labels))}

    def _ready(self):
        if any(x is None for x in (self.estimator, self.imputer, self.label_encoder)):
            raise RuntimeError("Threat detection model is not trained or loaded.")

    def predict_frame(self, features: pd.DataFrame) -> list[dict[str, Any]]:
        self._ready()
        x = numeric_features(features).reindex(columns=self.feature_columns)
        probabilities = np.asarray(self.estimator.predict_proba(self.imputer.transform(x)), dtype=float)
        temperature = max(float(self.calibration_temperature), 1e-6)
        logits = np.log(np.clip(probabilities, np.finfo(float).eps, 1.0)) / temperature
        logits -= logits.max(axis=1, keepdims=True)
        exp_values = np.exp(logits)
        probabilities = exp_values / exp_values.sum(axis=1, keepdims=True)
        classes = self.label_encoder.inverse_transform(np.asarray(self.estimator.classes_, dtype=int))
        results = []
        for row in probabilities:
            index = int(np.argmax(row))
            results.append({"agent": "threat_detection", "predicted_class": str(classes[index]),
                            "confidence": float(row[index]), "status": "success"})
        return results

    def predict_one(self, flow: dict[str, Any]) -> dict[str, Any]:
        return self.predict_frame(pd.DataFrame([flow]))[0]

    def save(self, path: str | Path) -> Path:
        self._ready()
        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "artifact_format_version": ARTIFACT_FORMAT_VERSION, "backend": self.backend,
            "estimator": self.estimator, "imputer": self.imputer,
            "label_encoder": self.label_encoder, "feature_columns": self.feature_columns,
            "metadata": self.metadata,
            "calibration_temperature": self.calibration_temperature,
            "config": {"random_state": self.random_state, "n_estimators": self.n_estimators,
                       "max_depth": self.max_depth, "min_samples_leaf": self.min_samples_leaf,
                       "n_jobs": self.n_jobs},
        }
        fd, temporary = tempfile.mkstemp(prefix=destination.name, suffix=".tmp", dir=str(destination.parent))
        os.close(fd)
        try:
            joblib.dump(payload, temporary, compress=3)
            os.replace(temporary, destination)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
        return destination

    @classmethod
    def load(cls, path: str | Path) -> "ThreatDetectionModel":
        payload = joblib.load(path)
        if payload.get("artifact_format_version") != ARTIFACT_FORMAT_VERSION:
            raise ValueError("Unsupported or incompatible model artifact version.")
        instance = cls(backend=payload["backend"], **payload["config"])
        instance.estimator, instance.imputer = payload["estimator"], payload["imputer"]
        instance.label_encoder = payload["label_encoder"]
        instance.feature_columns = list(payload["feature_columns"])
        instance.metadata = dict(payload["metadata"])
        instance.calibration_temperature = float(payload.get("calibration_temperature", 1.0))
        return instance
