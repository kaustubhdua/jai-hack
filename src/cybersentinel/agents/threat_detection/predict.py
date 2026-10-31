"""Agent 1 adapter; preserves the existing pipeline's .predict(flow) interface."""
from pathlib import Path
from typing import Any
import numpy as np
import pandas as pd
from cybersentinel.contracts import ThreatDetectionResult
from .model import ThreatDetectionModel

class ThreatDetectionAgent:
    def __init__(self, model: ThreatDetectionModel | None = None):
        self.model = model

    def fit(self, features: pd.DataFrame, labels) -> "ThreatDetectionAgent":
        if self.model is None:
            self.model = ThreatDetectionModel()
        self.model.fit(features, labels)
        return self

    def predict(self, flow: dict[str, Any]) -> ThreatDetectionResult:
        if self.model is None:
            raise RuntimeError("ThreatDetectionAgent has no trained model.")
        result = self.model.predict_one(flow)
        return ThreatDetectionResult(result["predicted_class"], result["confidence"],
                                     status="success",
                                     model_version=str(self.model.metadata.get("artifact_format_version", 1)))

    def predict_many(self, flows: pd.DataFrame) -> list[dict[str, Any]]:
        if self.model is None:
            raise RuntimeError("ThreatDetectionAgent has no trained model.")
        return self.model.predict_frame(flows)

    def predict_proba_canonical(self, flows: pd.DataFrame) -> np.ndarray:
        if self.model is None:
            raise RuntimeError("ThreatDetectionAgent has no trained model.")
        return self.model.predict_proba_canonical(flows)

    def save(self, path: str | Path) -> Path:
        if self.model is None:
            raise RuntimeError("Cannot save an untrained agent.")
        return self.model.save(path)

    @classmethod
    def load(cls, path: str | Path) -> "ThreatDetectionAgent":
        return cls(ThreatDetectionModel.load(path))
