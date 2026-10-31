#!/usr/bin/env python3
"""Independent validator for the organizer's exact Level 2 CSV templates."""
from __future__ import annotations

import argparse
import ipaddress
from pathlib import Path
import sys

import numpy as np
import pandas as pd

CLASSES = {"BENIGN", "BRUTE_FORCE", "DOS", "DDOS", "PORT_SCAN"}
EVIDENCE = {"AGREE", "CONFLICT", "UNCERTAIN"}
ACTIONS = {"ALLOW", "BLOCK"}
SCOPES = {"SOURCE_IP", "DESTINATION_IP", "SRC_DST_PAIR"}
ALLOW_SENTINEL = "NONE"
CLASS_COLUMNS = ["record_id", "predicted_class", "anomaly_score", "evidence_status"]
POLICY_COLUMNS = [
    "policy_id", "activated_after_record_id", "scope_type",
    "scope_value", "expires_after_record_id",
]
REPLAY_COLUMNS = ["record_id", "action", "active_policy_id"]

SOURCE_COLUMNS = ("source_ip", "Source IP", "Source_IP", "src_ip", "src")
DESTINATION_COLUMNS = (
    "destination_ip", "Destination IP", "Destination_IP", "dst_ip", "dst",
)


def _read(path: Path, expected: list[str]) -> pd.DataFrame:
    if not path.is_file():
        raise ValueError(f"Required submission file is missing: {path.name}")
    frame = pd.read_csv(path, dtype=str, keep_default_na=False)
    if list(frame.columns) != expected:
        raise ValueError(f"{path.name}: expected exact columns {expected}, got {list(frame.columns)}")
    return frame


def _ip(value: object) -> str:
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except (ValueError, TypeError):
        return ""


def _observed_endpoint(row: pd.Series | dict, columns: tuple[str, ...]) -> str:
    for column in columns:
        if column not in row:
            continue
        value = _ip(row.get(column))
        if value:
            return value
    return ""


def _scope_for_row(row: pd.Series | dict, scope_type: str) -> str:
    source = _observed_endpoint(row, SOURCE_COLUMNS)
    destination = _observed_endpoint(row, DESTINATION_COLUMNS)
    if scope_type == "SOURCE_IP":
        return source
    if scope_type == "DESTINATION_IP":
        return destination
    if scope_type == "SRC_DST_PAIR":
        return f"{source}|{destination}" if source and destination else ""
    return ""


def validate(input_path: Path, output_dir: Path) -> list[str]:
    """Validate exact templates, complete coverage, causal windows and scope matches."""
    errors: list[str] = []
    source = (
        pd.read_parquet(input_path)
        if input_path.suffix.lower() in {".parquet", ".pq"}
        else pd.read_csv(input_path, dtype={"record_id": str}, keep_default_na=False)
    )
    if "record_id" not in source.columns:
        raise ValueError("Original hidden input must contain organizer-provided record_id values.")

    ids = source["record_id"].astype(str).tolist()
    if not ids:
        errors.append("Hidden input contains no records.")
    if any(not value for value in ids) or len(ids) != len(set(ids)):
        errors.append("Hidden input record_id values must be non-empty and unique.")
    positions = {record_id: index for index, record_id in enumerate(ids)}

    if "seq" not in source.columns:
        errors.append("Hidden input is missing the organizer seq field.")
    else:
        sequence = pd.to_numeric(source["seq"], errors="coerce")
        if sequence.isna().any() or sequence.duplicated().any() or sequence.tolist() != list(range(1, len(source) + 1)):
            errors.append("Hidden input seq must be the exact 1-based organizer replay order.")

    classification = _read(output_dir / "classification.csv", CLASS_COLUMNS)
    policies = _read(output_dir / "policies.csv", POLICY_COLUMNS)
    replay = _read(output_dir / "replay.csv", REPLAY_COLUMNS)

    for filename, frame in (
        ("classification.csv", classification),
        ("replay.csv", replay),
    ):
        observed_ids = frame["record_id"].astype(str).tolist()
        if observed_ids != ids:
            errors.append(f"{filename}: must contain every hidden record exactly once in original seq order.")

    if not set(classification["predicted_class"]).issubset(CLASSES):
        errors.append("classification.csv predicted_class must be one of the five organizer classes.")
    if not set(classification["evidence_status"]).issubset(EVIDENCE):
        errors.append("classification.csv evidence_status must be AGREE, CONFLICT, or UNCERTAIN.")
    scores = pd.to_numeric(classification["anomaly_score"], errors="coerce")
    if scores.isna().any() or not np.isfinite(scores.to_numpy(dtype=float)).all():
        errors.append("classification.csv anomaly_score must be finite for every hidden record.")
    elif ((scores < 0.0) | (scores > 1.0)).any():
        errors.append("classification.csv anomaly_score values must be within [0,1].")

    policy_ids = policies["policy_id"].tolist()
    if any(not value for value in policy_ids) or len(policy_ids) != len(set(policy_ids)):
        errors.append("policies.csv policy_id values must be non-empty and unique.")

    policy_map = {row["policy_id"]: row for _, row in policies.iterrows()}
    valid_policies = []
    for _, policy in policies.iterrows():
        policy_id = policy["policy_id"]
        scope_type = policy["scope_type"]
        activation_id = policy["activated_after_record_id"]
        expiry_id = policy["expires_after_record_id"]
        if scope_type not in SCOPES:
            errors.append(f"Policy {policy_id}: scope_type must be SOURCE_IP, DESTINATION_IP, or SRC_DST_PAIR.")
            continue
        if activation_id not in positions or expiry_id not in positions:
            errors.append(f"Policy {policy_id}: activation and expiry IDs must exist in hidden input.")
            continue
        activation_pos, expiry_pos = positions[activation_id], positions[expiry_id]
        if activation_pos >= expiry_pos:
            errors.append(f"Policy {policy_id}: expiry must follow activation.")
            continue
        expected_scope = _scope_for_row(source.iloc[activation_pos], scope_type)
        if not expected_scope or policy["scope_value"] != expected_scope:
            errors.append(f"Policy {policy_id}: scope_value must exactly match the observed {scope_type} on its activation record.")
            continue
        valid_policies.append({
            "policy_id": policy_id,
            "scope_type": scope_type,
            "scope_value": expected_scope,
            "activation_pos": activation_pos,
            "expiry_pos": expiry_pos,
        })

    if not set(replay["action"]).issubset(ACTIONS):
        errors.append("replay.csv action must be ALLOW or BLOCK.")

    # Recompute every active match from the original endpoint fields. This proves
    # ALLOW/BLOCK correctness and the lexicographically smallest policy tie-break.
    for position, row in replay.iterrows():
        record_id = str(row["record_id"])
        action = row["action"]
        active_policy_id = row["active_policy_id"]
        if position >= len(source):
            continue
        matches = []
        for policy in valid_policies:
            if policy["activation_pos"] < position <= policy["expiry_pos"]:
                observed_scope = _scope_for_row(source.iloc[position], policy["scope_type"])
                if observed_scope and observed_scope == policy["scope_value"]:
                    matches.append(policy["policy_id"])
        expected_policy = min(matches) if matches else ALLOW_SENTINEL

        if action == "ALLOW":
            if active_policy_id != ALLOW_SENTINEL:
                errors.append(f"Record {record_id}: ALLOW must use active_policy_id=NONE.")
            if matches:
                errors.append(f"Record {record_id}: ALLOW is invalid because active policy {expected_policy} matches this flow.")
        elif action == "BLOCK":
            if not matches:
                errors.append(f"Record {record_id}: BLOCK has no active policy matching the observed endpoint scope.")
            elif active_policy_id != expected_policy:
                errors.append(
                    f"Record {record_id}: BLOCK must reference lexicographically smallest matching policy_id {expected_policy}."
                )

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True, help="Original unlabelled organizer hidden replay input CSV or Parquet")
    parser.add_argument("--output-dir", type=Path, required=True, help="Directory containing classification.csv, policies.csv and replay.csv")
    args = parser.parse_args()
    try:
        errors = validate(args.input, args.output_dir)
    except Exception as exc:
        print(f"SUBMISSION VALIDATION COULD NOT RUN: {type(exc).__name__}: {exc}")
        return 2
    if errors:
        print("SUBMISSION VALIDATION FAILED")
        for error in errors:
            print(f"- {error}")
        return 1
    print("SUBMISSION VALIDATION PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
