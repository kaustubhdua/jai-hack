import pandas as pd

from cybersentinel.replay.input_validation import validate_replay_input


def _valid_input():
    return pd.DataFrame({
        "record_id": ["F000001", "F000002"],
        "seq": [1, 2],
        "day": ["2017-07-04", "2017-07-04"],
        "time_offset": ["00:49.8", "02:14.1"],
        "source_ip": ["192.0.2.10", "192.0.2.10"],
        "destination_ip": ["192.0.2.20", "192.0.2.20"],
        "source_port": [50000, 50001],
        "destination_port": [443, 443],
        "protocol": [6, 6],
        "Flow Duration": [1000.0, 2000.0],
        "Flow Packets/s": [20.0, 30.0],
    })


def test_valid_observed_endpoint_replay_input_passes():
    report = validate_replay_input(_valid_input())
    assert report["valid"] is True
    assert report["rows"] == 2
    assert report["feature_count"] == 2
    assert report["source_ip_observed_rows"] == 2
    assert report["rows_with_both_observed_endpoints"] == 2


def test_replay_input_rejects_non_causal_sequence():
    frame = _valid_input()
    frame.loc[1, "seq"] = 3
    report = validate_replay_input(frame)
    assert report["valid"] is False
    assert any("seq must be the exact" in error for error in report["errors"])


def test_replay_input_rejects_ground_truth_label_column():
    frame = _valid_input()
    frame["Label"] = ["BENIGN", "DOS"]
    report = validate_replay_input(frame)
    assert report["valid"] is False
    assert any("must not contain ground-truth label" in error for error in report["errors"])


def test_replay_input_does_not_invent_missing_source_identity():
    frame = _valid_input()
    frame.loc[0, "source_ip"] = ""
    report = validate_replay_input(frame)
    assert report["valid"] is True
    assert report["source_ip_observed_rows"] == 1
    assert report["rows_without_valid_source_ip"] == 1
    assert any("no valid observed source IP" in warning for warning in report["warnings"])


def test_replay_input_rejects_non_monotonic_timestamps():
    frame = _valid_input()
    frame.loc[1, "time_offset"] = "00:10.0"
    report = validate_replay_input(frame)
    assert report["valid"] is False
    assert any("timestamps must all parse and be non-decreasing" in error for error in report["errors"])


def test_replay_input_checks_model_feature_compatibility():
    report = validate_replay_input(_valid_input(), {"Agent 1": ["Flow Duration", "Missing Feature"]})
    assert report["valid"] is False
    assert report["model_feature_schema_missing"]["Agent 1"] == ["Missing Feature"]


def test_replay_input_rejects_invalid_port_values():
    frame = _valid_input()
    frame.loc[0, "destination_port"] = 70000
    report = validate_replay_input(frame)
    assert report["valid"] is False
    assert any("destination_port must contain only integer values" in error for error in report["errors"])
