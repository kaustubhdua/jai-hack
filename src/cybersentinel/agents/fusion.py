"""Deterministic, explainable evidence fusion system for CyberSentinel."""
from __future__ import annotations

from typing import Any
from cybersentinel.contracts import (
    AnomalyDetectionResult,
    BenchmarkClass,
    FusionResult,
    PolicyAction,
    ThreatDetectionResult,
)


class EvidenceFusionAgent:
    """Agent 3 — Combines evidence from Threat Detection (A1) and Anomaly Detection (A2).

    Produces deterministic, explainable ALLOW, BLOCK, or REVIEW decisions without blind overrides.
    """

    CONFIDENCE_HIGH_THRESHOLD: float = 0.85
    CONFIDENCE_LOW_THRESHOLD: float = 0.60

    def fuse(
        self,
        threat_result: ThreatDetectionResult | dict[str, Any] | None,
        anomaly_result: AnomalyDetectionResult | dict[str, Any] | None,
    ) -> FusionResult:
        """Combine Agent 1 and Agent 2 results deterministically across all 11 operational scenarios."""

        # Case 11: Invalid or incomplete input
        if threat_result is None and anomaly_result is None:
            return FusionResult(
                final_class=None,
                evidence_status="INCOMPLETE",
                action="REVIEW",
                agent_agreement="NO_INPUT",
                confidence=0.0,
                rationale=["Invalid or missing agent inputs provided to fusion agent.", "Defaulted to simulated REVIEW."],
            )

        # Normalize threat_result
        if isinstance(threat_result, dict):
            threat = ThreatDetectionResult(
                predicted_class=threat_result.get("predicted_class"),
                confidence=threat_result.get("confidence"),
                status=threat_result.get("status", "error"),
                agent=threat_result.get("agent", "threat_detection"),
                model_version=threat_result.get("model_version"),
                message=threat_result.get("message"),
            )
        else:
            threat = threat_result

        # Normalize anomaly_result
        if isinstance(anomaly_result, dict):
            anomaly = AnomalyDetectionResult(
                anomaly_score=anomaly_result.get("anomaly_score"),
                is_anomaly=anomaly_result.get("is_anomaly"),
                evidence=anomaly_result.get("evidence", []),
                status=anomaly_result.get("status", "error"),
                agent=anomaly_result.get("agent", "anomaly_detection"),
                message=anomaly_result.get("message"),
            )
        else:
            anomaly = anomaly_result

        t_ok = threat is not None and threat.status == "success" and threat.predicted_class is not None
        a_ok = anomaly is not None and anomaly.status == "success"

        # Case 8: Both agents fail
        if not t_ok and not a_ok:
            return FusionResult(
                final_class=None,
                evidence_status="INCOMPLETE",
                action="REVIEW",
                agent_agreement="BOTH_FAILED",
                confidence=0.0,
                rationale=[
                    "System degradation: Both threat detection and anomaly detection agents failed or are unavailable.",
                    f"Agent 1 error: {threat.message if threat else 'Missing'}",
                    f"Agent 2 error: {anomaly.message if anomaly else 'Missing'}",
                    "Simulated policy action defaulted to REVIEW for failsafe security posture.",
                ],
                threat_detection=threat,
                anomaly_detection=anomaly,
            )

        # Case 6: Agent 1 fails
        if not t_ok:
            is_anom = bool(anomaly.is_anomaly) if (anomaly and anomaly.is_anomaly is not None) else False
            action: PolicyAction = "REVIEW"
            rationale = [
                "Agent 1 (Threat Detection) unavailable; operating in degraded mode with anomaly sensor only.",
                f"Agent 1 message: {threat.message if threat else 'Unavailable'}",
            ]
            if is_anom:
                rationale.append(
                    f"Agent 2 flagged statistical anomaly (score {anomaly.anomaly_score}). Evidence: {anomaly.evidence}"
                )
                rationale.append("Simulated action: REVIEW pending human analyst inspection.")
            else:
                rationale.append("Agent 2 observed normal baseline statistics; reviewing due to unconfirmed classification.")
            return FusionResult(
                final_class=None,
                evidence_status="INCOMPLETE",
                action=action,
                agent_agreement="A1_FAILED_A2_ACTIVE",
                confidence=0.5 if is_anom else 0.7,
                rationale=rationale,
                supporting_evidence=anomaly.evidence if anomaly else [],
                threat_detection=threat,
                anomaly_detection=anomaly,
            )

        # Case 7: Agent 2 fails
        if not a_ok:
            pred = threat.predicted_class
            conf = float(threat.confidence or 0.0)
            if pred != "BENIGN" and conf >= self.CONFIDENCE_HIGH_THRESHOLD:
                action = "BLOCK"
            elif pred == "BENIGN" and conf >= self.CONFIDENCE_HIGH_THRESHOLD:
                action = "ALLOW"
            else:
                action = "REVIEW"

            return FusionResult(
                final_class=pred,
                evidence_status="INCOMPLETE",
                action=action,
                agent_agreement="A2_FAILED_A1_ACTIVE",
                confidence=conf,
                rationale=[
                    "Agent 2 (Anomaly Detection) unavailable; evaluating threat classifier in isolation.",
                    f"Agent 1 predicted {pred} with confidence {conf:.2f}.",
                    f"Agent 2 message: {anomaly.message if anomaly else 'Unavailable'}",
                ],
                threat_detection=threat,
                anomaly_detection=anomaly,
            )

        # Case 10: Anomaly score is unavailable despite status success
        if anomaly.anomaly_score is None:
            pred = threat.predicted_class
            conf = float(threat.confidence or 0.0)
            return FusionResult(
                final_class=pred,
                evidence_status="INCOMPLETE",
                action="REVIEW" if conf < self.CONFIDENCE_HIGH_THRESHOLD else ("BLOCK" if pred != "BENIGN" else "ALLOW"),
                agent_agreement="ANOMALY_SCORE_UNAVAILABLE",
                confidence=conf,
                rationale=[
                    "Anomaly detection score is null/uncomputed.",
                    f"Agent 1 predicted {pred} with confidence {conf:.2f}.",
                    "Cautionary policy applied.",
                ],
                threat_detection=threat,
                anomaly_detection=anomaly,
            )

        # Both agents succeeded with valid measurements
        pred_class = threat.predicted_class
        conf = float(threat.confidence if threat.confidence is not None else 0.0)
        is_anomaly = bool(anomaly.is_anomaly)
        score = float(anomaly.anomaly_score)
        evidence = list(anomaly.evidence or [])

        # Case 9: Confidence is low
        if conf < self.CONFIDENCE_LOW_THRESHOLD:
            return FusionResult(
                final_class=pred_class,
                evidence_status="DISAGREE" if is_anomaly != (pred_class != "BENIGN") else "AGREE",
                action="REVIEW",
                agent_agreement="LOW_CONFIDENCE",
                confidence=conf,
                rationale=[
                    f"Agent 1 prediction ({pred_class}) has low confidence ({conf:.2f} < {self.CONFIDENCE_LOW_THRESHOLD}).",
                    f"Agent 2 anomaly evaluation: is_anomaly={is_anomaly} (score: {score:.4f}).",
                    "Simulated policy action held for human analyst REVIEW due to classification uncertainty.",
                ],
                supporting_evidence=evidence,
                threat_detection=threat,
                anomaly_detection=anomaly,
            )

        # Case 2: Both agents identify suspicious activity (Agreement on Attack)
        if pred_class != "BENIGN" and is_anomaly:
            return FusionResult(
                final_class=pred_class,
                evidence_status="AGREE",
                action="BLOCK",
                agent_agreement="ATTACK_CONFIRMED",
                confidence=conf,
                rationale=[
                    f"Dual agent consensus: Agent 1 classified attack as {pred_class} (confidence {conf:.2f}).",
                    f"Agent 2 independently corroborated with anomaly score {score:.4f}.",
                    f"Feature evidence: {', '.join(evidence) if evidence else 'Multiple metric deviations'}.",
                    f"Policy action: Simulated BLOCK enforced for {pred_class}.",
                ],
                supporting_evidence=evidence,
                threat_detection=threat,
                anomaly_detection=anomaly,
            )

        # Case 1: Both agents agree on normal traffic (Agreement on Benign)
        if pred_class == "BENIGN" and not is_anomaly:
            return FusionResult(
                final_class="BENIGN",
                evidence_status="AGREE",
                action="ALLOW",
                agent_agreement="BENIGN_CONFIRMED",
                confidence=conf,
                rationale=[
                    f"Dual agent consensus: Flow classified as BENIGN (confidence {conf:.2f}).",
                    f"Agent 2 verified traffic within normal baseline parameters (anomaly score {score:.4f}).",
                    "Policy action: Simulated ALLOW permitted.",
                ],
                supporting_evidence=[],
                threat_detection=threat,
                anomaly_detection=anomaly,
            )

        # Case 3 & 5: Classifier identifies an attack but anomaly agent does not
        # (Stealth / low-volume attack or disagreement)
        if pred_class != "BENIGN" and not is_anomaly:
            if conf >= self.CONFIDENCE_HIGH_THRESHOLD:
                action = "BLOCK"
                rationale = [
                    f"Disagreement: Agent 1 detected {pred_class} with high confidence ({conf:.2f} >= {self.CONFIDENCE_HIGH_THRESHOLD}).",
                    f"Agent 2 did not observe global statistical anomaly (score {score:.4f}), characteristic of low-volume/stealth attacks.",
                    f"Policy action: Simulated BLOCK applied based on high-confidence signature match.",
                ]
            else:
                action = "REVIEW"
                rationale = [
                    f"Disagreement: Agent 1 predicted {pred_class} with moderate confidence ({conf:.2f}), but Agent 2 found no anomaly.",
                    "Potential false alarm or borderline attack signature.",
                    "Policy action: Simulated REVIEW requested.",
                ]
            return FusionResult(
                final_class=pred_class,
                evidence_status="DISAGREE",
                action=action,
                agent_agreement="SUPERVISED_ATTACK_UNSUPERVISED_NORMAL",
                confidence=conf,
                rationale=rationale,
                supporting_evidence=evidence,
                threat_detection=threat,
                anomaly_detection=anomaly,
            )

        # Case 4: Classifier predicts BENIGN but anomaly agent flags an anomaly (Potential Zero-Day)
        action = "REVIEW"
        return FusionResult(
            final_class="BENIGN",
            evidence_status="DISAGREE",
            action=action,
            agent_agreement="POTENTIAL_ZERO_DAY",
            confidence=conf,
            rationale=[
                f"Disagreement: Agent 1 classified flow as BENIGN (confidence {conf:.2f}), but Agent 2 detected a statistical anomaly (score {score:.4f}).",
                "Potential zero-day exploit, novel attack vector, or unusual legitimate spike.",
                f"Feature evidence: {', '.join(evidence) if evidence else 'Significant distribution deviation'}.",
                "Policy action: Simulated REVIEW triggered to protect against uncatalogued threats.",
            ],
            supporting_evidence=evidence,
            threat_detection=threat,
            anomaly_detection=anomaly,
        )
