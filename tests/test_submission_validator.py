import pandas as pd

from cybersentinel.replay.submission import SubmissionValidator
from scripts.validate_submissions import validate as validate_official_csvs


def test_submission_validator_valid_bundle(tmp_path):
    output = tmp_path / "submission"
    output.mkdir()
    pd.DataFrame([
        ["rec-1", "BENIGN", 0.01, "AGREE"],
        ["rec-2", "DOS", 0.85, "AGREE"],
    ], columns=["record_id", "predicted_class", "anomaly_score", "evidence_status"]).to_csv(output / "classification.csv", index=False)
    pd.DataFrame([
        ["POL-00001", "rec-1", "SOURCE_IP", "10.0.0.99", "rec-2"],
    ], columns=["policy_id", "activated_after_record_id", "scope_type", "scope_value", "expires_after_record_id"]).to_csv(output / "policies.csv", index=False)
    pd.DataFrame([
        ["rec-1", "ALLOW", "NONE"],
        ["rec-2", "BLOCK", "POL-00001"],
    ], columns=["record_id", "action", "active_policy_id"]).to_csv(output / "replay.csv", index=False)

    report = SubmissionValidator.validate_submission_bundle(output, ["rec-1", "rec-2"])
    assert report["all_valid"] is True


def test_submission_validator_rejects_invalid_classification(tmp_path):
    output = tmp_path / "submission"
    output.mkdir()
    pd.DataFrame([
        ["rec-1", "UNKNOWN", 0.01, "AGREE"],
    ], columns=["record_id", "predicted_class", "anomaly_score", "evidence_status"]).to_csv(output / "classification.csv", index=False)
    pd.DataFrame(columns=["policy_id", "activated_after_record_id", "scope_type", "scope_value", "expires_after_record_id"]).to_csv(output / "policies.csv", index=False)
    pd.DataFrame([
        ["rec-1", "ALLOW", "NONE"],
    ], columns=["record_id", "action", "active_policy_id"]).to_csv(output / "replay.csv", index=False)

    report = SubmissionValidator.validate_submission_bundle(output, ["rec-1"])
    assert report["all_valid"] is False
    assert report["classification"]["valid"] is False


def test_submission_validator_accepts_exact_organizer_headers_and_empty_policy_ledger(tmp_path):
    output = tmp_path / "submission"
    output.mkdir()
    pd.DataFrame([
        ["rec-1", "BENIGN", 0.01, "AGREE"],
    ], columns=["record_id", "predicted_class", "anomaly_score", "evidence_status"]).to_csv(output / "classification.csv", index=False)
    pd.DataFrame(columns=["policy_id", "activated_after_record_id", "scope_type", "scope_value", "expires_after_record_id"]).to_csv(output / "policies.csv", index=False)
    pd.DataFrame([
        ["rec-1", "ALLOW", "NONE"],
    ], columns=["record_id", "action", "active_policy_id"]).to_csv(output / "replay.csv", index=False)

    report = SubmissionValidator.validate_submission_bundle(output, ["rec-1"])
    assert report["all_valid"] is True


def test_bundle_validator_rejects_blocked_record_with_different_observed_source_ip(tmp_path):
    output = tmp_path / "source_mismatch"
    output.mkdir()
    pd.DataFrame([
        ["rec-1", "DOS", 0.1, "AGREE"],
        ["rec-2", "DOS", 0.2, "AGREE"],
    ], columns=["record_id", "predicted_class", "anomaly_score", "evidence_status"]).to_csv(output / "classification.csv", index=False)
    pd.DataFrame([
        ["POL-00001", "rec-1", "SOURCE_IP", "192.0.2.10", "rec-2"],
    ], columns=["policy_id", "activated_after_record_id", "scope_type", "scope_value", "expires_after_record_id"]).to_csv(output / "policies.csv", index=False)
    pd.DataFrame([
        ["rec-1", "ALLOW", "NONE"],
        ["rec-2", "BLOCK", "POL-00001"],
    ], columns=["record_id", "action", "active_policy_id"]).to_csv(output / "replay.csv", index=False)
    source = pd.DataFrame({"record_id": ["rec-1", "rec-2"], "source_ip": ["192.0.2.10", "192.0.2.11"]})

    report = SubmissionValidator.validate_submission_bundle(output, ["rec-1", "rec-2"], source_frame=source)
    assert report["all_valid"] is False
    assert any("BLOCK has no matching active observed-endpoint policy" in error for error in report["replay"]["errors"])


def _write_official_bundle(tmp_path):
    input_frame = pd.DataFrame({
        "record_id": [101, 102, 103],
        "seq": [1, 2, 3],
        "source_ip": ["192.0.2.1", "192.0.2.1", "192.0.2.2"],
        "destination_ip": ["198.51.100.1", "198.51.100.1", "198.51.100.2"],
    })
    input_path = tmp_path / "hidden.csv"
    input_frame.to_csv(input_path, index=False)
    pd.DataFrame([
        [101, "DOS", 0.1, "AGREE"], [102, "DOS", 0.2, "AGREE"], [103, "BENIGN", 0.3, "UNCERTAIN"],
    ], columns=["record_id", "predicted_class", "anomaly_score", "evidence_status"]).to_csv(tmp_path / "classification.csv", index=False)
    pd.DataFrame([
        ["POL-00001", 101, "SOURCE_IP", "192.0.2.1", 103],
    ], columns=["policy_id", "activated_after_record_id", "scope_type", "scope_value", "expires_after_record_id"]).to_csv(tmp_path / "policies.csv", index=False)
    pd.DataFrame([
        [101, "ALLOW", "NONE"], [102, "BLOCK", "POL-00001"], [103, "ALLOW", "NONE"],
    ], columns=["record_id", "action", "active_policy_id"]).to_csv(tmp_path / "replay.csv", index=False)
    return input_path


def test_independent_official_csv_validator_accepts_valid_bundle(tmp_path):
    input_path = _write_official_bundle(tmp_path)
    assert validate_official_csvs(input_path, tmp_path) == []


def test_independent_official_csv_validator_rejects_block_before_activation(tmp_path):
    input_path = _write_official_bundle(tmp_path)
    replay = pd.read_csv(tmp_path / "replay.csv", dtype=str, keep_default_na=False)
    replay.loc[0, ["action", "active_policy_id"]] = ["BLOCK", "POL-00001"]
    replay.to_csv(tmp_path / "replay.csv", index=False)
    errors = validate_official_csvs(input_path, tmp_path)
    assert any("BLOCK has no active policy matching" in error for error in errors)


def test_independent_official_csv_validator_rejects_fingerprint_derived_source_scope(tmp_path):
    input_frame = pd.DataFrame([
        {"record_id": 201, "seq": 1, "Init_Win_bytes_forward": 64240, "min_seg_size_forward": 20},
        {"record_id": 202, "seq": 2, "Init_Win_bytes_forward": 64240, "min_seg_size_forward": 20},
    ])
    input_path = tmp_path / "fingerprint-input.csv"
    input_frame.to_csv(input_path, index=False)
    pd.DataFrame([
        [201, "DOS", 0.1, "AGREE"], [202, "DOS", 0.2, "AGREE"],
    ], columns=["record_id", "predicted_class", "anomaly_score", "evidence_status"]).to_csv(tmp_path / "classification.csv", index=False)
    pd.DataFrame([
        ["POL-00001", 201, "SOURCE_IP", "10.1.2.3", 202],
    ], columns=["policy_id", "activated_after_record_id", "scope_type", "scope_value", "expires_after_record_id"]).to_csv(tmp_path / "policies.csv", index=False)
    pd.DataFrame([
        [201, "ALLOW", "NONE"], [202, "BLOCK", "POL-00001"],
    ], columns=["record_id", "action", "active_policy_id"]).to_csv(tmp_path / "replay.csv", index=False)
    errors = validate_official_csvs(input_path, tmp_path)
    assert any("scope_value must exactly match the observed SOURCE_IP" in error for error in errors)


def test_independent_validator_enforces_lexicographically_smallest_matching_policy(tmp_path):
    input_path = _write_official_bundle(tmp_path)
    policies = pd.read_csv(tmp_path / "policies.csv")
    duplicate_scope = policies.iloc[0].copy()
    duplicate_scope["policy_id"] = "POL-00002"
    policies = pd.concat([policies, duplicate_scope.to_frame().T], ignore_index=True)
    policies.to_csv(tmp_path / "policies.csv", index=False)
    replay = pd.read_csv(tmp_path / "replay.csv", dtype=str, keep_default_na=False)
    replay.loc[1, "active_policy_id"] = "POL-00002"
    replay.to_csv(tmp_path / "replay.csv", index=False)
    errors = validate_official_csvs(input_path, tmp_path)
    assert any("lexicographically smallest matching policy_id POL-00001" in error for error in errors)


def test_independent_validator_rejects_allow_when_an_active_policy_matches(tmp_path):
    input_path = _write_official_bundle(tmp_path)
    replay = pd.read_csv(tmp_path / "replay.csv", dtype=str, keep_default_na=False)
    replay.loc[1, ["action", "active_policy_id"]] = ["ALLOW", "NONE"]
    replay.to_csv(tmp_path / "replay.csv", index=False)
    errors = validate_official_csvs(input_path, tmp_path)
    assert any("ALLOW is invalid because active policy POL-00001 matches this flow" in error for error in errors)
