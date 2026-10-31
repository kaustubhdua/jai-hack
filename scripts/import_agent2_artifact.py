"""Convert the earlier standalone Agent 2 artifact to CyberSentinel's versioned format.

Only run this on a model artifact you created/trust: joblib/pickle loading can execute
code. The legacy trainer used numeric coercion + fillna(0), so this adapter preserves
that zero-imputation behavior and the stored decision-score threshold.
"""
from __future__ import annotations

import argparse
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.impute import SimpleImputer

from cybersentinel.agents.anomaly_detection import AnomalyDetectionAgent


def convert(source: str | Path, destination: str | Path) -> Path:
    payload = joblib.load(source)  # trusted local artifact only
    if not isinstance(payload, dict) or "model" not in payload or "threshold" not in payload:
        raise ValueError("Expected legacy artifact dictionary with 'model' and 'threshold'.")

    estimator = payload["model"]
    threshold = float(payload["threshold"])
    feature_names = payload.get("feature_names")
    if feature_names is None:
        feature_names = getattr(estimator, "feature_names_in_", None)
    if feature_names is None:
        raise ValueError("Artifact does not contain feature_names or estimator.feature_names_in_.")
    feature_columns = [str(name) for name in feature_names]
    if not feature_columns or len(feature_columns) != int(estimator.n_features_in_):
        raise ValueError("Stored feature list does not match estimator input width.")
    if not np.isfinite(threshold) or not hasattr(estimator, "decision_function"):
        raise ValueError("Invalid threshold or estimator does not support decision_function.")

    # Legacy training replaced missing/non-finite values with zero before fit.
    imputer = SimpleImputer(strategy="constant", fill_value=0)
    imputer.fit(pd.DataFrame(np.zeros((1, len(feature_columns))), columns=feature_columns))
    agent = AnomalyDetectionAgent(
        estimator=estimator,
        feature_columns=feature_columns,
        imputer=imputer,
        profiles={},
        threshold=threshold,
        metadata={
            "artifact_format_version": 1,
            "algorithm": "IsolationForest",
            "training_rows": payload.get("training_rows"),
            "feature_count": len(feature_columns),
            "feature_columns": feature_columns,
            "threshold_method": "1st percentile of benign training decision_function scores (legacy artifact)",
            "training_scope": "BENIGN rows only (legacy artifact)",
            "imported_from_legacy_artifact": True,
        },
    )
    return agent.save(destination)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, help="Trusted legacy model2(1).joblib")
    parser.add_argument("--destination", default="models/anomaly_detection/model.joblib")
    args = parser.parse_args()
    result = convert(args.source, args.destination)
    print(f"Converted Agent 2 artifact: {result}")


if __name__ == "__main__":
    main()
