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


def test_zeek_conn_header_parser(tmp_path):
    path = tmp_path / "conn.log"
    path.write_text("#separator \\x09\n#fields\tts\tid.orig_h\tid.resp_h\n1.0\t192.0.2.1\t198.51.100.1\n", encoding="utf-8")
    frame = load_zeek_conn(path)
    assert frame.iloc[0]["id.orig_h"] == "192.0.2.1"
