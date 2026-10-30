"""Deterministic, explainable evidence fusion for CyberSentinel."""
from __future__ import annotations

from typing import Any

from cybersentinel.contracts import FusionResult


VALID_CLASSES = {"BENIGN", "BRUTE_FORCE", "DOS", "DDOS", "PORT_SCAN"}
HIGH_CONFIDENCE = 0.85


class EvidenceFusionAgent:
    """Combine independent classifier and anomaly evidence into a simulated action.

    This module never applies network controls. Incomplete evidence fails closed
    to REVIEW; a BLOCK/ALLOW value is a recommendation for offline replay only.
    """

    def fuse(self, threat_result: Any, anomaly_result: Any) -> FusionResult:
        threat = self._value(threat_result)
        anomaly = self._value(anomaly_result)

        t_ok = (
            threat is not None
            and self._get(threat, "status", "success") == "success"
            and self._get(threat, "predicted_class") in VALID_CLASSES
            and self._number(self._get(threat, "confidence")) is not None
        )
        a_ok = (
            anomaly is not None
            and self._get(anomaly, "status", "success") == "success"
            and isinstance(self._get(anomaly, "is_anomaly"), bool)
        )

        if not t_ok or not a_ok:
            return FusionResult(
                final_class=self._get(threat, "predicted_class") if t_ok else None,
                evidence_status="INCOMPLETE",
                action="REVIEW",
                rationale=[
                    "One or more agents did not return valid evidence.",
                    "Simulated action defaulted to REVIEW; analyst verification is required.",
                ],
                threat_detection=threat_result,
                anomaly_detection=anomaly_result,
            )

        predicted = self._get(threat, "predicted_class")
        confidence = float(self._get(threat, "confidence"))
        is_anomaly = self._get(anomaly, "is_anomaly")
        evidence_status = "AGREE" if ((predicted == "BENIGN") == (not is_anomaly)) else "DISAGREE"

        if evidence_status == "AGREE" and predicted == "BENIGN":
            action = "ALLOW" if confidence >= HIGH_CONFIDENCE else "REVIEW"
            rationale = ["Classifier predicts BENIGN and anomaly detector reports baseline-consistent traffic."]
        elif evidence_status == "AGREE":
            action = "BLOCK" if confidence >= HIGH_CONFIDENCE else "REVIEW"
            rationale = ["Classifier predicts an attack and anomaly detector independently flags the flow."]
        else:
            action = "REVIEW"
            rationale = ["Classifier and anomaly detector disagree; human review is required."]

        rationale.append(f"Classifier confidence: {confidence:.4f}.")
        rationale.append(f"Anomaly detector flag: {is_anomaly}.")
        rationale.append("Policy action is simulated only; no firewall or live network control is performed.")
        return FusionResult(
            final_class=predicted,
            evidence_status=evidence_status,
            action=action,
            rationale=rationale,
            threat_detection=threat_result,
            anomaly_detection=anomaly_result,
        )

    @staticmethod
    def _value(value: Any) -> Any:
        if isinstance(value, dict):
            return value
        return value

    @staticmethod
    def _get(value: Any, key: str, default: Any = None) -> Any:
        if value is None:
            return default
        if isinstance(value, dict):
            return value.get(key, default)
        return getattr(value, key, default)

    @staticmethod
    def _number(value: Any) -> float | None:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return None
        if not 0.0 <= float(value) <= 1.0:
            return None
        return float(value)
