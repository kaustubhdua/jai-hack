from cybersentinel.contracts import FusionResult, ThreatDetectionResult
from cybersentinel.evaluation.anomaly import evaluate_anomaly_detector
from cybersentinel.evaluation.fusion import evaluate_fusion_comparison


def test_fusion_metrics_read_dataclass_threat_predictions():
    result = evaluate_fusion_comparison(
        y_true=["BENIGN", "DOS"],
        a1_predictions=[
            ThreatDetectionResult("BENIGN", 0.99),
            ThreatDetectionResult("DOS", 0.98),
        ],
        a3_fusion_results=[
            FusionResult("BENIGN", "AGREE", "ALLOW"),
            FusionResult("DOS", "AGREE", "BLOCK"),
        ],
    )
    assert result["a1_classification_metrics"]["accuracy"] == 1.0
    assert result["a3_fusion_classification_metrics"]["accuracy"] == 1.0


def test_normalized_anomaly_index_is_not_inverted_twice():
    result = evaluate_anomaly_detector(
        y_true=["BENIGN", "BENIGN", "DOS", "DOS"],
        raw_scores=[0.1, 0.2, 0.8, 0.9],
        operational_threshold=0.5,
        is_anomaly_flags=[False, False, True, True],
        higher_score_is_anomaly=True,
    )
    assert result["roc_auc"] == 1.0
    assert result["score_direction"] == "higher_is_more_anomalous"
    assert result["operational_metrics"]["attack_recall"] == 1.0
    assert result["operational_metrics"]["benign_fpr"] == 0.0
