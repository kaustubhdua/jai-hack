#!/usr/bin/env python3
"""Verify and install the organizer's CyberSentinel data packs into ignored local paths."""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import tempfile
import zipfile

import pandas as pd
import numpy as np

TRAIN_MEMBER = "Cyber/training/flows.parquet"
EVAL_MEMBER = "Cyber/eval/flows.parquet"
HIDDEN_MEMBER = "Cyber/hidden/records.csv"
HIDDEN_REQUIRED = {
    "record_id", "seq", "day", "time_offset", "source_ip",
    "destination_ip", "source_port", "destination_port", "protocol",
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def prepare(training_pack: Path, hidden_pack: Path, data_dir: Path) -> dict:
    if not training_pack.is_file() or not hidden_pack.is_file():
        raise FileNotFoundError("Both cyber-pack.zip and cyber-hidden.zip must be provided.")

    with zipfile.ZipFile(training_pack) as archive:
        manifest = json.loads(archive.read("manifest.json"))
        cyber = manifest["tracks"]["cyber"]["partitions"]
        training_bytes = archive.read(TRAIN_MEMBER)
        evaluation_bytes = archive.read(EVAL_MEMBER)
        for partition, payload in (("training", training_bytes), ("eval", evaluation_bytes)):
            expected = cyber[partition]
            actual_hash = sha256(payload)
            if len(payload) != int(expected["bytes"]) or actual_hash != expected["sha256"]:
                raise ValueError(f"{partition} partition failed organizer manifest size/SHA-256 verification.")
            if int(expected["rows"]) <= 0:
                raise ValueError(f"{partition} manifest row count is invalid.")

    with zipfile.ZipFile(hidden_pack) as archive:
        hidden_bytes = archive.read(HIDDEN_MEMBER)
        readme = archive.read("README.md").decode("utf-8")
        if "There is **no label column**" not in readme:
            raise ValueError("Hidden archive README does not confirm the unlabelled organizer input contract.")

    hidden = pd.read_csv(pd.io.common.BytesIO(hidden_bytes), dtype={"record_id": str})
    missing = sorted(HIDDEN_REQUIRED - set(hidden.columns))
    if missing:
        raise ValueError(f"Hidden input is missing required organizer metadata: {missing}")
    if "label" in {str(column).strip().casefold() for column in hidden.columns}:
        raise ValueError("Hidden input unexpectedly contains a label column.")
    if len(hidden) != 200:
        raise ValueError(f"Expected exactly 200 hidden records, found {len(hidden)}.")
    if hidden["record_id"].isna().any() or hidden["record_id"].astype(str).duplicated().any():
        raise ValueError("Hidden record IDs must be non-empty and unique.")
    sequence = pd.to_numeric(hidden["seq"], errors="coerce")
    if sequence.isna().any() or sequence.tolist() != list(range(1, 201)):
        raise ValueError("Hidden seq must be exactly 1..200 in organizer order.")
    expected_ids = [f"F{index:06d}" for index in range(1, 201)]
    if hidden["record_id"].astype(str).tolist() != expected_ids:
        raise ValueError("Hidden record IDs must be F000001 through F000200 in organizer order.")
    days = pd.to_datetime(hidden["day"], errors="coerce", utc=True)
    offsets = hidden["time_offset"].astype(str).str.extract(r"^(?P<minutes>\d+):(?P<seconds>\d{1,2}(?:\.\d+)?)$")
    if days.isna().any() or offsets.isna().any(axis=None):
        raise ValueError("Hidden day/time_offset metadata contains an invalid value.")
    elapsed = pd.to_numeric(offsets["minutes"], errors="coerce") * 60 + pd.to_numeric(offsets["seconds"], errors="coerce")
    timestamps = days + pd.to_timedelta(elapsed, unit="s")
    if timestamps.isna().any() or not timestamps.is_monotonic_increasing:
        raise ValueError("Hidden day/time_offset values must form valid increasing timestamps.")
    if hidden["source_ip"].map(lambda value: _valid_ip(value)).eq(False).any():
        raise ValueError("Hidden input contains a missing or invalid observed source_ip.")
    if hidden["destination_ip"].map(lambda value: _valid_ip(value)).eq(False).any():
        raise ValueError("Hidden input contains a missing or invalid observed destination_ip.")
    feature_metadata = HIDDEN_REQUIRED
    feature_columns = [column for column in hidden.columns if column not in feature_metadata]
    numeric_features = hidden[feature_columns].apply(pd.to_numeric, errors="coerce")
    if len(feature_columns) != 78 or numeric_features.isna().any(axis=None):
        raise ValueError(f"Expected exactly 78 complete numeric flow features; found {len(feature_columns)} columns.")
    if not np.isfinite(numeric_features.to_numpy(dtype=float)).all():
        raise ValueError("Hidden flow features must contain only finite numeric values.")

    paths = {
        data_dir / "raw" / "training" / "flows.parquet": training_bytes,
        data_dir / "raw" / "evaluation" / "flows.parquet": evaluation_bytes,
        data_dir / "processed" / "hidden_replay_input.csv": hidden_bytes,
    }
    for path, payload in paths.items():
        atomic_write(path, payload)

    report = {
        "source_archives": {
            "training_pack": {"name": training_pack.name, "sha256": file_sha256(training_pack)},
            "hidden_pack": {"name": hidden_pack.name, "sha256": file_sha256(hidden_pack)},
        },
        "training": {
            "path": str(next(path for path in paths if path.parts[-3:] == ("raw", "training", "flows.parquet")).relative_to(data_dir)),
            "rows": int(cyber["training"]["rows"]),
            "sha256": sha256(training_bytes),
        },
        "evaluation": {
            "rows": int(cyber["eval"]["rows"]),
            "sha256": sha256(evaluation_bytes),
            "note": "Held-out labelled evaluation partition; do not use for training or calibration.",
        },
        "hidden": {
            "path": "processed/hidden_replay_input.csv",
            "rows": len(hidden),
            "features": len(feature_columns),
            "first_record_id": str(hidden.iloc[0]["record_id"]),
            "last_record_id": str(hidden.iloc[-1]["record_id"]),
            "sha256": sha256(hidden_bytes),
            "labels_present": False,
        },
    }
    report_path = data_dir / "processed" / "input_manifest.json"
    atomic_write(report_path, json.dumps(report, indent=2).encode("utf-8"))
    return report


def _valid_ip(value: object) -> bool:
    try:
        ipaddress.ip_address(str(value).strip())
        return True
    except (ValueError, TypeError):
        return False


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--training-pack", type=Path, required=True, help="Organizer cyber-pack.zip")
    parser.add_argument("--hidden-pack", type=Path, required=True, help="Organizer cyber-hidden.zip")
    parser.add_argument("--data-dir", type=Path, default=Path("data"))
    args = parser.parse_args()
    print(json.dumps(prepare(args.training_pack, args.hidden_pack, args.data_dir), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
