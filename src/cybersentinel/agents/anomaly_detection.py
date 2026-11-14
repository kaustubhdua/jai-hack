"""Independent benign-baseline anomaly detector for network flows.

Agent 2 is trained only on benign rows from the training partition. It does not
consume Agent 1 predictions or labels during scoring. Thresholds and imputation
statistics are learned from training data and persisted with the artifact.
"""
from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.impute import SimpleImputer

from cybersentinel.contracts import AnomalyDetectionResult


FEATURE_EVIDENCE_MAP = {
    "Flow Packets/s": "unusual_packet_rate",
    "Flow Bytes/s": "abnormal_byte_rate",
    "Flow Duration": "abnormal_flow_duration",
    "Total Fwd Packets": "high_forward_packet_volume",
    "Total Length of Fwd Packets": "abnormal_payload_size",
    "Fwd Packet Length Max": "unusually_large_packet",
    "FIN Flag Count": "abnormal_fin_flag_activity",
    "SYN Flag Count": "unusual_syn_flag_pattern",
    "RST Flag Count": "high_rst_teardown_rate",
    "PSH Flag Count": "abnormal_psh_flag_rate",
    "Destination Port": "anomalous_service_port",
}
ARTIFACT_FORMAT_VERSION = 2


def _numeric_frame(frame: pd.DataFrame) -> pd.DataFrame:
    if not isinstance(frame, pd.DataFrame):
        frame = pd.DataFrame(frame)
    data = frame.loc[:, ~frame.columns.duplicated()].copy()
    excluded = {"recordid", "label", "flowid", "sourceip", "destinationip", "srcip", "dstip", "timestamp"}
    # Exact organizer metadata names are excluded without dropping the CICIDS
    # feature "Destination Port" (space-separated) from the 78-feature vector.
    replay_metadata = {"seq", "day", "time_offset", "source_port", "destination_port", "protocol"}
    def normalized(name: Any) -> str:
        return "".join(ch for ch in str(name).casefold() if ch.isalnum())
    data = data.drop(columns=[
        c for c in data.columns
        if normalized(c) in excluded or str(c).strip().casefold() in replay_metadata
    ], errors="ignore")
    numeric = {}
    for col in data.columns:
        values = pd.to_numeric(data[col], errors="coerce").replace([np.inf, -np.inf], np.nan)
        if values.notna().any():
            numeric[str(col)] = values.astype("float64")
    if not numeric:
        raise ValueError("No usable numeric flow features were supplied.")
    return pd.DataFrame(numeric, index=data.index)


class AnomalyDetectionAgent:
    """Isolation Forest over a benign-only training baseline."""

    def __init__(self, estimator: Any = None, feature_columns: list[str] | None = None,
                 imputer: SimpleImputer | None = None,
                 profiles: dict[str, dict[str, float]] | None = None,
                 threshold: float | None = None, metadata: dict[str, Any] | None = None, score_scale: float | None = None):
        self.estimator = estimator
        self.feature_columns = list(feature_columns or [])
        self.imputer = imputer
        self.profiles = profiles or {}
        self.threshold = threshold
        self.metadata = metadata or {}
        self.score_scale = score_scale

    def fit(self, benign_training_features: pd.DataFrame) -> "AnomalyDetectionAgent":
        x = _numeric_frame(benign_training_features)
        # Fit feature selection and imputation on benign training data only.
        self.feature_columns = [c for c in x.columns if x[c].nunique(dropna=True) > 1]
        if not self.feature_columns:
            raise ValueError("Benign training data has no varying numeric features.")
        x = x.reindex(columns=self.feature_columns)
        self.imputer = SimpleImputer(strategy="median")
        matrix = self.imputer.fit_transform(x)
        self.estimator = IsolationForest(
            n_estimators=200,
            max_samples=min(50000, len(matrix)),
            contamination="auto",
            random_state=42,
            n_jobs=-1,
        )
        self.estimator.fit(matrix)
        training_scores = self.estimator.decision_function(matrix)
        # The 1st percentile of benign training scores defines the operating point.
        self.threshold = float(np.percentile(training_scores, 1.0))
        self.score_scale = float(max(np.std(training_scores), 1e-6))
        self.profiles = {}
        for index, col in enumerate(self.feature_columns):
            values = matrix[:, index]
            q01, q25, q50, q75, q99 = np.percentile(values, [1, 25, 50, 75, 99])
            self.profiles[col] = {
                "median": float(q50),
                "iqr": float(max(q75 - q25, 1e-9)),
                "q01": float(q01),
                "q99": float(q99),
            }
        self.metadata = {
            "artifact_format_version": ARTIFACT_FORMAT_VERSION,
            "algorithm": "IsolationForest",
            "training_rows": int(len(matrix)),
            "feature_count": len(self.feature_columns),
            "feature_columns": self.feature_columns,
            "threshold_method": "1st percentile of benign training decision_function scores",
            "score_definition": "bounded logistic anomaly index from raw decision_function margin to threshold, scaled by benign-training score standard deviation; range [0,1], larger is more anomalous",
            "score_is_probability": False,
            "training_scope": "benign rows from training partition only",
        }
        return self

    def calibrate_threshold(
        self,
        validation_features: pd.DataFrame,
        validation_labels,
        max_benign_fpr: float = 0.02,
    ) -> dict[str, float]:
        """Select an anomaly threshold on a separate labelled validation partition.

        Labels are used only to tune/evaluate this threshold; they are never used
        by score()/score_frame() or by replay decisions for an individual record.
        """
        if self.estimator is None or self.imputer is None:
            raise RuntimeError("Fit or load the anomaly detector before threshold calibration.")
        if not 0.0 <= max_benign_fpr <= 1.0:
            raise ValueError("max_benign_fpr must be between 0 and 1.")
        labels = pd.Series(validation_labels).astype("string").str.strip().str.upper()
        if len(labels) != len(validation_features):
            raise ValueError("Validation features and labels must have equal lengths.")
        if labels.isna().any() or (labels == "").any():
            raise ValueError("Validation labels contain missing or empty values.")
        truth = (labels != "BENIGN").to_numpy(dtype=bool)
        benign_count = int((~truth).sum())
        attack_count = int(truth.sum())
        if benign_count == 0 or attack_count == 0:
            raise ValueError("Threshold calibration requires both BENIGN and attack validation rows.")

        raw = _numeric_frame(validation_features).reindex(columns=self.feature_columns)
        scores = np.asarray(self.estimator.decision_function(self.imputer.transform(raw)), dtype=float)
        if len(scores) != len(truth) or not np.isfinite(scores).all():
            raise ValueError("Validation scores are missing or non-finite.")

        # Evaluate every distinct threshold in O(n log n), not O(n^2).
        # Sorting once and using prefix counts preserves the exact '< threshold'
        # semantics and the original tie-break: recall, then lower FPR, then
        # the larger threshold.
        candidates = np.unique(np.concatenate((scores, [np.nextafter(float(scores.max()), np.inf)])))
        order = np.argsort(scores, kind="mergesort")
        sorted_scores = scores[order]
        sorted_truth = truth[order]
        prefix_attack = np.concatenate(([0], np.cumsum(sorted_truth, dtype=np.int64)))
        prefix_benign = np.concatenate(([0], np.cumsum(~sorted_truth, dtype=np.int64)))
        positions = np.searchsorted(sorted_scores, candidates, side="left")
        false_positive_rates = prefix_benign[positions] / benign_count
        attack_recalls = prefix_attack[positions] / attack_count
        eligible = np.flatnonzero(false_positive_rates <= max_benign_fpr)
        if eligible.size == 0:
            raise RuntimeError("No validation threshold satisfies the configured benign false-positive limit.")
        ranked = np.lexsort((
            candidates[eligible],
            -false_positive_rates[eligible],
            attack_recalls[eligible],
        ))
        best_index = int(eligible[ranked[-1]])
        self.threshold = float(candidates[best_index])
        fpr = float(false_positive_rates[best_index])
        recall = float(attack_recalls[best_index])
        self.metadata.update({
            "threshold_method": "validation-selected maximum attack recall subject to benign FPR constraint",
            "threshold_validation_rows": int(len(labels)),
            "threshold_validation_benign_rows": benign_count,
            "threshold_validation_attack_rows": attack_count,
            "threshold_max_benign_fpr": float(max_benign_fpr),
            "threshold_validation_benign_fpr": fpr,
            "threshold_validation_attack_recall": recall,
            "threshold_selection_uses_labels": True,
            "labels_used_during_scoring": False,
        })
        return {"threshold": float(self.threshold), "benign_false_positive_rate": fpr,
                "attack_recall": recall, "validation_rows": float(len(labels))}

    def _anomaly_index(self, raw_score: float) -> float:
        if self.threshold is None or self.score_scale is None or not np.isfinite(self.score_scale) or self.score_scale <= 0:
            raise RuntimeError("Anomaly score calibration is unavailable.")
        margin = float(np.clip((self.threshold - raw_score) / self.score_scale, -30.0, 30.0))
        return float(1.0 / (1.0 + np.exp(-margin)))

    def _aligned(self, flow: dict[str, Any]) -> pd.DataFrame:
        raw = _numeric_frame(pd.DataFrame([flow]))
        return raw.reindex(columns=self.feature_columns)

    def _evidence(self, flow: dict[str, Any]) -> list[dict[str, Any]]:
        """Return inspectable deviations; these are indicators, not proof of attack."""
        deviations = []
        for col, profile in self.profiles.items():
            if col not in flow:
                continue
            try:
                value = float(flow[col])
            except (TypeError, ValueError):
                continue
            if not np.isfinite(value):
                continue
            if value < profile["q01"] or value > profile["q99"]:
                strength = abs(value - profile["median"]) / profile["iqr"]
                deviations.append((col, value, strength, profile))
        deviations.sort(key=lambda item: item[2], reverse=True)
        return [
            {
                "feature": col,
                "evidence_code": FEATURE_EVIDENCE_MAP.get(
                    col, "unusual_" + col.casefold().replace(" ", "_").replace("/", "_per_")
                ),
                "observed_value": float(value),
                "baseline_q01": float(profile["q01"]),
                "baseline_median": float(profile["median"]),
                "baseline_q99": float(profile["q99"]),
                "deviation_strength_iqr": float(strength),
                "interpretation": "statistical deviation from benign training baseline; not proof of malicious activity",
            }
            for col, value, strength, profile in deviations[:5]
        ]

    def score(self, flow: dict[str, Any]) -> AnomalyDetectionResult:
        if self.estimator is None or self.imputer is None or self.threshold is None:
            return AnomalyDetectionResult(None, None, [], status="not_ready",
                                           message="Anomaly detector has not been trained or loaded.")
        if not isinstance(flow, dict) or not flow:
            return AnomalyDetectionResult(None, None, [], status="error",
                                           message="Flow must be a non-empty object.")
        try:
            matrix = self.imputer.transform(self._aligned(flow))
            score = float(self.estimator.decision_function(matrix)[0])
            flagged = bool(score < self.threshold)
            return AnomalyDetectionResult(
                anomaly_score=self._anomaly_index(score),
                is_anomaly=flagged,
                evidence=self._evidence(flow) if flagged else [],
                status="success",
            )
        except Exception as exc:
            return AnomalyDetectionResult(None, None, [], status="error",
                                           message=f"Anomaly scoring failed: {type(exc).__name__}")

    def score_frame(self, features: pd.DataFrame) -> list[AnomalyDetectionResult]:
        if self.estimator is None or self.imputer is None or self.threshold is None:
            return [AnomalyDetectionResult(None, None, [], status="not_ready",
                                           message="Anomaly detector has not been trained or loaded.")] * len(features)
        try:
            raw = _numeric_frame(features).reindex(columns=self.feature_columns)
            matrix = self.imputer.transform(raw)
            scores = self.estimator.decision_function(matrix)
            flagged_indices = np.where(scores < self.threshold)[0]
            flagged_set = set(flagged_indices)

            # Extract evidence only for flagged flows to preserve high throughput
            evidence_dict = {}
            if flagged_indices.size > 0:
                for idx in flagged_indices:
                    flow_dict = features.iloc[int(idx)].to_dict()
                    evidence_dict[idx] = self._evidence(flow_dict)

            results = []
            for idx, score_val in enumerate(scores):
                raw_score = float(score_val)
                flagged = idx in flagged_set
                results.append(AnomalyDetectionResult(
                    anomaly_score=self._anomaly_index(raw_score),
                    is_anomaly=flagged,
                    evidence=evidence_dict.get(idx, []) if flagged else [],
                    status="success",
                ))
            return results
        except Exception as exc:
            return [AnomalyDetectionResult(None, None, [], status="error",
                                           message=f"Anomaly scoring failed: {type(exc).__name__}")] * len(features)

    def save(self, path: str | Path) -> Path:
        if self.estimator is None or self.imputer is None or self.threshold is None or self.score_scale is None:
            raise RuntimeError("Cannot save an untrained anomaly detector.")
        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix=destination.name, suffix=".tmp", dir=str(destination.parent))
        os.close(fd)
        try:
            joblib.dump({
                "artifact_format_version": ARTIFACT_FORMAT_VERSION,
                "estimator": self.estimator,
                "imputer": self.imputer,
                "feature_columns": self.feature_columns,
                "profiles": self.profiles,
                "threshold": self.threshold,
                "score_scale": self.score_scale,
                "metadata": self.metadata,
            }, temporary, compress=3)
            os.replace(temporary, destination)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
        return destination

    @classmethod
    def load(cls, path: str | Path) -> "AnomalyDetectionAgent":
        payload = joblib.load(path)
        if not isinstance(payload, dict):
            raise ValueError("Anomaly model artifact must be a mapping.")
        metadata = payload.get("metadata") or {}
        if not isinstance(metadata, dict):
            raise ValueError("Anomaly model metadata must be a mapping.")
        # Version 1 artifacts predate the top-level format marker and calibrated
        # score_scale field. Accept that known legacy layout only when all core
        # fitted objects and the feature contract are present.
        artifact_version = payload.get(
            "artifact_format_version", metadata.get("artifact_format_version", 1)
        )
        if artifact_version not in (1, ARTIFACT_FORMAT_VERSION):
            raise ValueError("Unsupported anomaly model artifact version.")
        required = ("estimator", "imputer", "feature_columns", "threshold")
        missing = [key for key in required if key not in payload]
        if missing:
            raise ValueError("Anomaly model artifact is missing required fields.")
        feature_columns = payload["feature_columns"]
        if not isinstance(feature_columns, (list, tuple)) or not feature_columns:
            raise ValueError("Anomaly model artifact has no feature columns.")
        threshold = float(payload["threshold"])
        if not np.isfinite(threshold):
            raise ValueError("Anomaly model threshold must be finite.")
        score_scale_value = payload.get("score_scale", metadata.get("score_scale"))
        if score_scale_value is None and artifact_version == 1:
            score_scale_value = 1.0
            metadata = {**metadata, "legacy_score_scale_fallback": True}
        if score_scale_value is None:
            raise ValueError("Anomaly model artifact is missing score calibration.")
        score_scale = float(score_scale_value)
        if not np.isfinite(score_scale) or score_scale <= 0:
            raise ValueError("Anomaly model score scale must be finite and positive.")
        metadata = {**metadata, "artifact_format_version": int(artifact_version)}
        return cls(
            estimator=payload["estimator"],
            feature_columns=list(feature_columns),
            imputer=payload["imputer"],
            profiles=payload.get("profiles", {}),
            threshold=threshold,
            metadata=metadata,
            score_scale=score_scale,
        )
