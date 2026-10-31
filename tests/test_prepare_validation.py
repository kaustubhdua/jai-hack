import pandas as pd
import pytest
from cybersentinel.data.cleaning import FlowPreprocessor
from scripts.prepare_validation import prepare_validation


def test_prepare_validation_reuses_training_preprocessor_and_excludes_ids(tmp_path):
    train = pd.DataFrame({
        "record_id": ["t1", "t2", "t3", "t4", "t5"],
        "Flow Duration": [1, 2, 3, 4, 5],
        "Total Fwd Packets": [2, 3, 4, 5, 6],
        "label": ["BENIGN", "BRUTE_FORCE", "DOS", "DDOS", "PORT_SCAN"],
    })
    validation = pd.DataFrame({
        "record_id": ["v1", "v2"], "Flow Duration": [2.5, 3.5],
        "Total Fwd Packets": [3.5, 4.5], "label": ["BENIGN", "DOS"],
    })
    processor = FlowPreprocessor().fit(train)
    state_path = tmp_path / "preprocessing_state.json"
    processor.save(state_path)
    input_path, output_path = tmp_path / "validation.csv", tmp_path / "prepared.csv"
    validation.to_csv(input_path, index=False)
    report = prepare_validation(input_path, state_path, output_path)
    prepared = pd.read_csv(output_path)
    assert report["rows"] == 2
    assert "record_id" not in prepared.columns
    assert prepared["label"].tolist() == ["BENIGN", "DOS"]


def test_prepare_validation_rejects_schema_drift(tmp_path):
    train = pd.DataFrame({
        "record_id": ["t1", "t2", "t3", "t4", "t5"],
        "Flow Duration": [1, 2, 3, 4, 5],
        "Total Fwd Packets": [2, 3, 4, 5, 6],
        "label": ["BENIGN", "BRUTE_FORCE", "DOS", "DDOS", "PORT_SCAN"],
    })
    processor = FlowPreprocessor().fit(train)
    state_path = tmp_path / "state.json"
    processor.save(state_path)
    drift = pd.DataFrame({"record_id": ["v1"], "Flow Duration": [2], "label": ["BENIGN"]})
    input_path = tmp_path / "drift.csv"
    drift.to_csv(input_path, index=False)
    with pytest.raises(ValueError, match="Schema mismatch"):
        prepare_validation(input_path, state_path, tmp_path / "out.csv")
