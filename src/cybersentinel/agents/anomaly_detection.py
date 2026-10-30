"""Independent Anomaly Detection Agent using Isolation Forest."""
from __future__ import annotations

from pathlib import Path
from typing import Any
import joblib
import numpy as np
import pandas as pd

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
    "Init_Win_bytes_forward": "unusual_tcp_window_size",
    "Destination Port": "anomalous_service_port",
}


class AnomalyDetectionAgent:
    """Agent 2 — Unsupervised network anomaly detector.

    Learns baseline normal traffic distributions and scores flows independently of Agent 1.
    """

    def __init__(
        self,
        estimator: Any = None,
        feature_columns: list[str] | None = None,
        feature_profiles: dict[str, dict[str, float]] | None = None,
        threshold: float = -0.0232,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        self.estimator = estimator
        self.feature_columns = feature_columns or []
        self.feature_profiles = feature_profiles or {}
        self.threshold = threshold
        self.metadata = metadata or {}

    @classmethod
    def load(cls, path: str | Path = "models/anomaly_detection/model.joblib") -> "AnomalyDetectionAgent":
        model_path = Path(path)
        if not model_path.exists():
            raise FileNotFoundError(f"Agent 2 model artifact not found: {model_path}")
        payload = joblib.load(model_path)
        return cls(
            estimator=payload["estimator"],
            feature_columns=payload["feature_columns"],
            feature_profiles=payload.get("feature_profiles", {}),
            threshold=float(payload.get("threshold", -0.0232)),
            metadata=payload.get("metadata", {}),
        )

    def fit(self, benign_training_features: pd.DataFrame) -> "AnomalyDetectionAgent":
        from sklearn.ensemble import IsolationForest

        df = benign_training_features.copy()
        for col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0.0)

        self.feature_columns = list(df.columns)
        self.feature_profiles = {}
        for col in self.feature_columns:
            vals = df[col].to_numpy(dtype=np.float64)
            q01 = float(np.percentile(vals, 1))
            q25 = float(np.percentile(vals, 25))
            q50 = float(np.percentile(vals, 50))
            q75 = float(np.percentile(vals, 75))
            q99 = float(np.percentile(vals, 99))
            iqr = max(q75 - q25, 1e-6)
            self.feature_profiles[col] = {
                "median": q50,
                "iqr": iqr,
                "q01": q01,
                "q99": q99,
                "mean": float(np.mean(vals)),
                "std": float(np.std(vals)),
            }

        self.estimator = IsolationForest(
            n_estimators=100,
            max_samples=min(50000, len(df)),
            contamination=0.01,
            random_state=42,
            n_jobs=-1,
        )
        self.estimator.fit(df)
        sample_scores = self.estimator.decision_function(df.iloc[:20000])
        self.threshold = float(np.percentile(sample_scores, 1.0))
        return self

    def _extract_evidence(self, flow: dict[str, Any]) -> list[str]:
        """Identify concrete features deviating significantly from the benign baseline."""
        deviations: list[tuple[str, float]] = []

        for col, profile in self.feature_profiles.items():
            if col not in flow or flow[col] is None:
                continue
            try:
                val = float(flow[col])
            except (ValueError, TypeError):
                continue

            median = profile["median"]
            iqr = profile["iqr"]
            q99 = profile["q99"]
            q01 = profile["q01"]

            # Check for significant outlier deviation
            if val > q99 or val < q01:
                z_robust = abs(val - median) / iqr
                deviations.append((col, z_robust))

        # Sort by strongest deviation
        deviations.sort(key=lambda x: x[1], reverse=True)

        evidence: list[str] = []
        for col, _ in deviations[:4]:
            mapped = FEATURE_EVIDENCE_MAP.get(col)
            if mapped:
                evidence.append(mapped)
            else:
                clean_name = col.lower().replace(" ", "_").replace("/", "_per_")
                evidence.append(f"unusual_{clean_name}")

        return evidence

    def score(self, flow: dict[str, Any]) -> AnomalyDetectionResult:
        """Independently assess an incoming flow dictionary.

        Returns AnomalyDetectionResult contract matching expected output:
        {
          "agent": "anomaly_detection",
          "anomaly_score": -0.32,
          "is_anomaly": true,
          "evidence": ["unusual_packet_rate", "abnormal_flow_duration"],
          "status": "success"
        }
        """
        if self.estimator is None:
            return AnomalyDetectionResult(
                anomaly_score=None,
                is_anomaly=None,
                evidence=[],
                status="not_ready",
                message="Anomaly detection model is not loaded.",
            )

        if not isinstance(flow, dict) or not flow:
            return AnomalyDetectionResult(
                anomaly_score=None,
                is_anomaly=None,
                evidence=[],
                status="error",
                message="Input flow must be a non-empty dictionary",
            )

        try:
            # Build 1-row vector aligned with trained feature columns
            row = []
            for col in self.feature_columns:
                val = flow.get(col)
                if val is None or val == "":
                    val = self.feature_profiles.get(col, {}).get("median", 0.0)
                try:
                    num_val = float(val)
                    if np.isinf(num_val) or np.isnan(num_val):
                        num_val = self.feature_profiles.get(col, {}).get("median", 0.0)
                except (ValueError, TypeError):
                    num_val = self.feature_profiles.get(col, {}).get("median", 0.0)
                row.append(num_val)

            arr = np.array([row], dtype=np.float64)
            raw_score = float(self.estimator.decision_function(arr)[0])
            is_anomaly = bool(raw_score < self.threshold)
            evidence = self._extract_evidence(flow) if is_anomaly else []

            return AnomalyDetectionResult(
                anomaly_score=float(round(raw_score, 4)),
                is_anomaly=is_anomaly,
                evidence=evidence,
                status="success",
            )
        except Exception as exc:
            return AnomalyDetectionResult(
                anomaly_score=None,
                is_anomaly=None,
                evidence=[],
                status="error",
                message=str(exc),
            )

    def save(self, path: str | Path) -> Path:
        if self.estimator is None:
            raise RuntimeError("Cannot save untrained anomaly detector.")
        dest = Path(path)
        dest.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "artifact_format_version": 1,
            "estimator": self.estimator,
            "feature_columns": self.feature_columns,
            "feature_profiles": self.feature_profiles,
            "threshold": self.threshold,
            "metadata": self.metadata,
        }
        joblib.dump(payload, dest, compress=3)
        return dest
