"""Strict input checks for chronological, endpoint-enriched flow replay.

This module validates provenance and shape only. It never fabricates endpoints,
fills missing endpoint values, or derives timestamps from row numbers.
"""
from __future__ import annotations

import ipaddress
import re
from typing import Any

import numpy as np
import pandas as pd

_REQUIRED_COLUMNS = (
    "record_id", "seq", "source_ip", "destination_ip",
    "source_port", "destination_port", "protocol",
)
_SOURCE_KEYS = ("source_ip", "Source IP", "Source_IP", "src_ip", "src")
_DESTINATION_KEYS = ("destination_ip", "Destination IP", "Destination_IP", "dst_ip", "dst")
_TIMESTAMP_KEYS = ("Timestamp", "timestamp", "Flow Start", "flow_start", "start_time")
_METADATA_NAMES = {
    "record_id", "seq", "day", "time_offset", "source_ip", "destination_ip",
    "source_port", "destination_port", "protocol", "timestamp", "flow_id",
}
_LABEL_NAMES = {"label", "class", "groundtruth", "groundtruthlabel", "attacklabel"}


def _normalise(name: Any) -> str:
    return "".join(ch for ch in str(name).casefold() if ch.isalnum())


def _valid_ip(value: Any) -> bool:
    if value is None or pd.isna(value) or not str(value).strip():
        return False
    try:
        ipaddress.ip_address(str(value).strip())
        return True
    except ValueError:
        return False


def _timestamp_series(frame: pd.DataFrame) -> pd.Series | None:
    timestamp_column = next((name for name in _TIMESTAMP_KEYS if name in frame.columns), None)
    if timestamp_column:
        return pd.to_datetime(frame[timestamp_column], utc=True, errors="coerce")
    if not {"day", "time_offset"}.issubset(frame.columns):
        return None
    dates = pd.to_datetime(frame["day"], utc=True, errors="coerce")
    parts = frame["time_offset"].astype(str).str.extract(
        r"^(?P<minutes>\d+):(?P<seconds>\d{1,2}(?:\.\d+)?)$"
    )
    seconds = (
        pd.to_numeric(parts["minutes"], errors="coerce") * 60
        + pd.to_numeric(parts["seconds"], errors="coerce")
    )
    return dates + pd.to_timedelta(seconds, unit="s")


def validate_replay_input(
    frame: pd.DataFrame,
    model_feature_sets: dict[str, list[str]] | None = None,
) -> dict[str, Any]:
    """Validate organizer-style replay input without modifying or imputing it."""
    errors: list[str] = []
    warnings: list[str] = []
    if not isinstance(frame, pd.DataFrame) or frame.empty:
        return {"valid": False, "rows": 0, "errors": ["Replay input must be a non-empty table."], "warnings": []}
    if frame.columns.duplicated().any():
        errors.append("Replay input contains duplicate column names.")

    missing_columns = [name for name in _REQUIRED_COLUMNS if name not in frame.columns]
    if missing_columns:
        errors.append("Replay input is missing required organizer columns: " + ", ".join(missing_columns))

    normalised_columns = {_normalise(name) for name in frame.columns}
    leaked_labels = sorted(normalised_columns & _LABEL_NAMES)
    if leaked_labels:
        errors.append("Unlabelled replay input must not contain ground-truth label columns: " + ", ".join(leaked_labels))

    record_ids: list[str] = []
    if "record_id" in frame.columns:
        record_ids = frame["record_id"].astype(str).str.strip().tolist()
        if any(not value or value.casefold() in {"nan", "none"} for value in record_ids):
            errors.append("record_id values must be present and non-empty.")
        if len(record_ids) != len(set(record_ids)):
            errors.append("record_id values must be unique.")

    if "seq" in frame.columns:
        sequence = pd.to_numeric(frame["seq"], errors="coerce")
        expected = list(range(1, len(frame) + 1))
        if sequence.isna().any() or sequence.duplicated().any() or sequence.tolist() != expected:
            errors.append("seq must be the exact 1-based organizer replay order in input order.")

    for name, maximum in (("source_port", 65535), ("destination_port", 65535), ("protocol", 255)):
        if name not in frame.columns:
            continue
        values = pd.to_numeric(frame[name], errors="coerce")
        invalid = values.isna() | ~np.isfinite(values.to_numpy(dtype=float, na_value=np.nan)) | (values % 1 != 0) | (values < 0) | (values > maximum)
        if bool(invalid.any()):
            errors.append(f"{name} must contain only integer values in the range 0..{maximum}.")

    source_column = next((name for name in _SOURCE_KEYS if name in frame.columns), None)
    destination_column = next((name for name in _DESTINATION_KEYS if name in frame.columns), None)
    source_valid = frame[source_column].map(_valid_ip) if source_column else pd.Series(False, index=frame.index)
    destination_valid = frame[destination_column].map(_valid_ip) if destination_column else pd.Series(False, index=frame.index)
    source_count = int(source_valid.sum())
    destination_count = int(destination_valid.sum())
    both_count = int((source_valid & destination_valid).sum())
    if source_count < len(frame):
        warnings.append(
            f"{len(frame) - source_count} rows have no valid observed source IP; no source-scoped policy may be created for those rows."
        )
    if destination_count < len(frame):
        warnings.append(
            f"{len(frame) - destination_count} rows have no valid observed destination IP; destination-scoped correlation is unavailable for those rows."
        )

    timestamps = _timestamp_series(frame)
    if timestamps is None:
        errors.append("Replay input must contain a timestamp column or organizer day and time_offset fields.")
    elif timestamps.isna().any() or not timestamps.is_monotonic_increasing:
        errors.append("Replay timestamps must all parse and be non-decreasing in organizer seq order.")

    metadata = set(_METADATA_NAMES)
    feature_columns = [name for name in frame.columns if str(name).strip().casefold() not in metadata and _normalise(name) not in _LABEL_NAMES]
    numeric_features: dict[str, pd.Series] = {}
    for name in feature_columns:
        values = pd.to_numeric(frame[name], errors="coerce")
        if values.notna().any():
            numeric_features[str(name)] = values
    if not numeric_features:
        errors.append("Replay input contains no usable numeric flow-feature columns.")

    missing_by_model: dict[str, list[str]] = {}
    for model_name, required in (model_feature_sets or {}).items():
        missing = sorted(set(required) - set(frame.columns))
        if missing:
            missing_by_model[model_name] = missing
            errors.append(f"{model_name} model feature schema is not satisfied; missing {len(missing)} required feature(s).")

    missing_feature_cells = 0
    nonfinite_feature_cells = 0
    for values in numeric_features.values():
        missing_feature_cells += int(values.isna().sum())
        array = values.to_numpy(dtype=float, na_value=np.nan)
        nonfinite_feature_cells += int((~np.isfinite(array) & ~np.isnan(array)).sum())

    return {
        "valid": not errors,
        "rows": int(len(frame)),
        "feature_count": int(len(numeric_features)),
        "source_ip_observed_rows": source_count,
        "destination_ip_observed_rows": destination_count,
        "rows_with_both_observed_endpoints": both_count,
        "rows_without_valid_source_ip": int(len(frame) - source_count),
        "rows_without_valid_destination_ip": int(len(frame) - destination_count),
        "missing_numeric_feature_cells": missing_feature_cells,
        "nonfinite_numeric_feature_cells": nonfinite_feature_cells,
        "model_feature_schema_missing": missing_by_model,
        "errors": errors,
        "warnings": warnings,
    }
