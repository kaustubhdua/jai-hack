"""Explicit, provenance-preserving adapters for public network-security datasets.

Adapters normalize column names and common feature aliases only. They never
rewrite source labels into a shared taxonomy unless the caller supplies a map.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path
import re
from typing import Any

import pandas as pd

ALIASES: dict[str, tuple[str, ...]] = {
    "flow_duration": ("flow duration", "flow_duration", "dur", "duration"),
    "protocol": ("protocol", "proto"),
    "source_port": ("source port", "src port", "src_port", "sport"),
    "destination_port": ("destination port", "dst port", "dst_port", "dsport"),
    "source_ip": ("source ip", "src ip", "src_ip", "srcip"),
    "destination_ip": ("destination ip", "dst ip", "dst_ip", "dstip"),
    "timestamp": ("timestamp", "stime", "start time", "flow start"),
    "label": ("label", " Label", "attack", "attack_cat", "category", "type"),
    "flow_bytes": ("flow bytes/s", "flow_byts/s", "totlen_fwd_pkts", "totlen_bwd_pkts"),
    "flow_packets": ("flow packets/s", "flow_pkts/s", "total fwd packets", "total backward packets"),
}

DATASET_PROFILES: dict[str, dict[str, Any]] = {
    "cic-ids2017": {"label_candidates": ["Label"], "families": ["BENIGN", "FTP-Patator", "SSH-Patator", "DoS", "DDoS", "PortScan", "Bot", "Infiltration", "Web Attack"]},
    "unsw-nb15": {"label_candidates": ["attack_cat", "label"], "families": ["Normal", "Fuzzers", "Analysis", "Backdoors", "DoS", "Exploits", "Generic", "Reconnaissance", "Shellcode", "Worms"]},
    "ton-iot": {"label_candidates": ["type", "label"], "families": ["normal", "backdoor", "ddos", "dos", "injection", "password", "ransomware", "scanning", "xss"]},
    "generic": {"label_candidates": ["label", "class", "attack", "category", "target"], "families": []},
}


def _key(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(value).casefold())


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


@dataclass
class DatasetBundle:
    frame: pd.DataFrame
    source_path: str
    source_sha256: str
    format: str
    dataset_type: str
    rows: int
    columns: list[str]
    label_column: str | None
    normalized_columns: dict[str, str]
    warnings: list[str]

    def manifest(self) -> dict[str, Any]:
        result = asdict(self)
        result.pop("frame")
        return result


def _read(path: Path) -> pd.DataFrame:
    suffix = path.suffix.casefold()
    if suffix == ".csv":
        return pd.read_csv(path, low_memory=False)
    if suffix in {".parquet", ".pq"}:
        return pd.read_parquet(path)
    if suffix in {".feather", ".arrow"}:
        return pd.read_feather(path)
    raise ValueError("Supported tabular formats: CSV, Parquet, Feather/Arrow.")


def normalize_dataset(
    frame: pd.DataFrame,
    dataset_type: str = "generic",
    label_column: str | None = None,
) -> tuple[pd.DataFrame, str | None, dict[str, str], list[str]]:
    if frame.empty:
        raise ValueError("Dataset is empty.")
    if frame.columns.duplicated().any():
        raise ValueError("Dataset has duplicate column names.")
    profile = DATASET_PROFILES.get(dataset_type.casefold(), DATASET_PROFILES["generic"])
    source_columns = list(frame.columns)
    normalized = frame.copy()
    rename: dict[str, str] = {}
    by_key = {_key(column): column for column in source_columns}
    for canonical, aliases in ALIASES.items():
        if canonical == "label" and label_column:
            candidate = label_column
        else:
            candidate = next((by_key.get(_key(alias)) for alias in aliases if by_key.get(_key(alias)) is not None), None)
            if candidate is None:
                candidate = next((by_key.get(_key(name)) for name in profile["label_candidates"] if by_key.get(_key(name)) is not None), None) if canonical == "label" else None
        if candidate is not None and candidate in normalized.columns and candidate != canonical:
            if canonical not in normalized.columns:
                rename[candidate] = canonical
    normalized = normalized.rename(columns=rename)
    resolved_label = "label" if "label" in normalized.columns else None
    if label_column and label_column in normalized.columns:
        resolved_label = label_column
    warnings: list[str] = []
    if resolved_label is None:
        warnings.append("No label column was identified; this dataset can be used for unsupervised analysis only.")
    if resolved_label:
        normalized[resolved_label] = normalized[resolved_label].astype("string").str.strip()
    return normalized, resolved_label, rename, warnings


def load_dataset(
    path: str | Path,
    dataset_type: str = "auto",
    label_column: str | None = None,
) -> DatasetBundle:
    source = Path(path)
    if not source.is_file():
        raise FileNotFoundError(f"Dataset not found: {source}")
    frame = _read(source)
    selected_type = dataset_type.casefold()
    if selected_type == "auto":
        names = {_key(column) for column in frame.columns}
        if {"attackcat", "sttl", "sbytes"}.issubset(names):
            selected_type = "unsw-nb15"
        elif {"srcip", "dstip", "flowduration"}.issubset(names):
            selected_type = "cic-ids2017"
        elif {"ts", "srcip", "dstip"}.issubset(names):
            selected_type = "ton-iot"
        else:
            selected_type = "generic"
    if selected_type not in DATASET_PROFILES:
        raise ValueError(f"Unsupported dataset type: {dataset_type}")
    normalized, label, renamed, warnings = normalize_dataset(frame, selected_type, label_column)
    return DatasetBundle(
        frame=normalized,
        source_path=str(source.resolve()),
        source_sha256=sha256_file(source),
        format=source.suffix.lstrip(".").casefold(),
        dataset_type=selected_type,
        rows=len(normalized),
        columns=[str(column) for column in normalized.columns],
        label_column=label,
        normalized_columns=renamed,
        warnings=warnings,
    )


def write_manifest(bundle: DatasetBundle, path: str | Path) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(bundle.manifest(), indent=2), encoding="utf-8")
    return target
