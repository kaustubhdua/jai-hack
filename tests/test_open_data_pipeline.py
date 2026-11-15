import json

import pandas as pd
import pytest

from cybersentinel.data.adapters import load_dataset, normalize_dataset
from cybersentinel.experiments.pipeline import ExperimentConfig, evaluate_cross_dataset, train_experiment
from cybersentinel.integrations.logs import load_suricata_eve, load_wazuh_alerts, load_zeek_conn


def test_cic_style_aliases_normalize_without_rewriting_labels():
    source = pd.DataFrame({
        "Source IP": ["192.0.2.1"], "Destination IP": ["198.51.100.1"],
        "Flow Duration": [10], " Label": ["DoS"],
    })
    frame, label, mapping, warnings = normalize_dataset(source, "cic-ids2017")
    assert {"source_ip", "destination_ip", "flow_duration", "label"} <= set(frame.columns)
    assert label == "label"
    assert frame["label"].iloc[0] == "DoS"
    assert not warnings


def test_dataset_loader_hashes_original_file(tmp_path):
    path = tmp_path / "unsw.csv"
    pd.DataFrame({"attack_cat": ["Normal", "DoS"], "sbytes": [1, 2], "sttl": [64, 32]}).to_csv(path, index=False)
    bundle = load_dataset(path, "auto")
    assert bundle.dataset_type == "unsw-nb15"
    assert len(bundle.source_sha256) == 64
    assert bundle.label_column == "label"
    assert bundle.frame["label"].tolist() == ["Normal", "DoS"]


def test_cic_duration_is_normalized_from_microseconds_to_seconds():
    source = pd.DataFrame({"Flow Duration": [1_000_000], " Label": ["BENIGN"]})
    frame, _, _, _ = normalize_dataset(source, "cic-ids2017")
    assert frame["flow_duration"].iloc[0] == 1.0


def test_explicit_feature_allowlist_rejects_target_leakage():
    frame = pd.DataFrame({"feature": [1, 2], "label": ["a", "b"]})
    config = ExperimentConfig(label_column="label", feature_columns=["feature", "label"])
    with pytest.raises(ValueError, match="target label column"):
        train_experiment(frame, config, "unused-model-output")


def test_isolation_forest_runs_without_labels(tmp_path):
    frame = pd.DataFrame({"f1": [0, 1, 2, 3, 4], "f2": [2, 1, 2, 1, 2]})
    config = ExperimentConfig(model="isolation_forest", n_estimators=10)
    manifest = train_experiment(frame, config, tmp_path)
    assert manifest["scoring_mode"] == "unsupervised_anomaly"
    report = evaluate_cross_dataset(tmp_path / "model.joblib", frame, "label")
    assert report["mode"] == "unsupervised_anomaly"
    assert report["rows"] == 5


def test_explicit_mapping_rejects_unknown_source_labels():
    with pytest.raises(ValueError, match="does not cover"):
        from cybersentinel.experiments.pipeline import _mapped_labels
        _mapped_labels(pd.Series(["normal", "weird"]), {"normal": "BENIGN"})


def test_random_forest_training_and_cross_dataset_evaluation(tmp_path):
    train = pd.DataFrame({"f1": [0, 1, 2, 3, 4, 5], "f2": [1, 1, 2, 2, 3, 3],
                          "label": ["benign", "benign", "attack", "attack", "benign", "attack"]})
    target = pd.DataFrame({"f1": [0.2, 4.8], "f2": [1, 3], "label": ["benign", "attack"]})
    config = ExperimentConfig(model="random_forest", label_column="label", n_estimators=10)
    manifest = train_experiment(train, config, tmp_path)
    assert len(manifest["model_sha256"]) == 64
    result = evaluate_cross_dataset(tmp_path / "model.joblib", target, "label")
    assert result["rows"] == 2
    assert 0 <= result["macro_f1"] <= 1


def test_suricata_and_wazuh_ingestion(tmp_path):
    eve = tmp_path / "eve.json"
    eve.write_text(json.dumps({"timestamp": "2025-01-01T00:00:00Z", "event_type": "alert",
        "src_ip": "192.0.2.1", "dest_ip": "198.51.100.1", "proto": "TCP",
        "alert": {"signature": "test", "severity": 2}}) + "\n", encoding="utf-8")
    assert load_suricata_eve(eve).iloc[0]["signature"] == "test"

    wazuh = tmp_path / "wazuh.json"
    wazuh.write_text(json.dumps({"alerts": [{"timestamp": "2025-01-01T00:00:00Z",
        "agent": {"id": "001"}, "rule": {"id": "5710", "level": 5}}]}), encoding="utf-8")
    assert load_wazuh_alerts(wazuh).iloc[0]["rule_id"] == "5710"
    single = tmp_path / "single-wazuh.json"
    single.write_text(json.dumps({"timestamp": "2025-01-01T00:00:00Z", "rule": {"id": "1001"}}), encoding="utf-8")
    assert load_wazuh_alerts(single).iloc[0]["rule_id"] == "1001"


def test_zeek_conn_header_parser(tmp_path):
    path = tmp_path / "conn.log"
    path.write_text("#separator \\x09\n#fields\tts\tid.orig_h\tid.resp_h\n1.0\t192.0.2.1\t198.51.100.1\n", encoding="utf-8")
    frame = load_zeek_conn(path)
    assert frame.iloc[0]["id.orig_h"] == "192.0.2.1"



def test_unsw_attack_category_takes_precedence_over_binary_label():
    source = pd.DataFrame({
        "attack_cat": ["Normal", "DoS", "Exploits"],
        "label": [0, 1, 1],
        "sbytes": [10, 20, 30],
        "sttl": [64, 32, 48],
    })
    frame, label, _, _ = normalize_dataset(source, "unsw-nb15")
    assert label == "label"
    assert frame["label"].tolist() == ["Normal", "DoS", "Exploits"]
    assert frame["source_label"].tolist() == [0, 1, 1]


def test_secondary_unsw_binary_label_is_not_used_as_a_feature(tmp_path):
    from cybersentinel.experiments.pipeline import _features

    frame = pd.DataFrame({
        "label": ["Normal", "DoS", "Normal", "DoS"],
        "source_label": [0, 1, 0, 1],
        "sbytes": [10, 100, 12, 110],
        "sttl": [64, 32, 62, 30],
    })
    selected = _features(frame, ExperimentConfig(label_column="label"))
    assert selected == ["sbytes", "sttl"]
    manifest = train_experiment(frame, ExperimentConfig(n_estimators=10), tmp_path)
    assert "source_label" not in manifest["features"]


def test_allowlist_rejects_secondary_label_leakage():
    from cybersentinel.experiments.pipeline import _features

    frame = pd.DataFrame({
        "label": ["Normal", "DoS"],
        "source_label": [0, 1],
        "sbytes": [10, 100],
    })
    config = ExperimentConfig(label_column="label", feature_columns=["sbytes", "source_label"])
    with pytest.raises(ValueError, match="Potential target-label leakage"):
        _features(frame, config)


def test_cross_dataset_coverage_does_not_mislabel_missing_classes_as_domain_shift(tmp_path):
    train = pd.DataFrame({
        "f1": [0, 1, 2, 3, 4, 5],
        "label": ["benign", "benign", "attack", "attack", "scan", "scan"],
    })
    target = pd.DataFrame({"f1": [2, 3], "label": ["benign", "benign"]})
    train_experiment(train, ExperimentConfig(n_estimators=10), tmp_path)
    report = evaluate_cross_dataset(tmp_path / "model.joblib", target, "label")
    assert report["target_class_coverage"]["unobserved_training_classes"] == ["attack", "scan"]
    assert report["domain_shift_warning"] is False


def test_ton_iot_autodetection_precedes_cic_flow_signature(tmp_path):
    path = tmp_path / "ton-iot.csv"
    pd.DataFrame({
        "ts": ["2025-01-01T00:00:00Z", "2025-01-01T00:00:01Z"],
        "src_ip": ["192.0.2.1", "192.0.2.2"],
        "dst_ip": ["198.51.100.1", "198.51.100.2"],
        "flow_duration": [1.0, 2.0],
        "type": ["normal", "ddos"],
        "src_bytes": [10, 100],
    }).to_csv(path, index=False)
    bundle = load_dataset(path, "auto")
    assert bundle.dataset_type == "ton-iot"
    assert bundle.label_column == "label"
    assert bundle.frame["label"].tolist() == ["normal", "ddos"]
