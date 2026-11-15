#!/usr/bin/env python3
"""Profile a local CSV/Parquet dataset before mapping or training it.

This utility is intentionally read-only: it never edits source data, guesses
labels, downloads datasets, or silently converts attack taxonomies.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

import pandas as pd

LABEL_CANDIDATES = (
    "attack_cat", " Label", "label", "type", "class", "attack", "category",
    "target", "ground_truth", "groundtruth",
)


def read_dataset(path: Path) -> pd.DataFrame:
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(f"Dataset not found: {path}")
    suffix = path.suffix.casefold()
    if suffix == ".csv":
        return pd.read_csv(path, low_memory=False)
    if suffix in {".parquet", ".pq"}:
        return pd.read_parquet(path)
    raise ValueError("Supported formats are .csv, .parquet, and .pq")


def profile_frame(frame: pd.DataFrame, label_column: str | None = None) -> dict[str, Any]:
    if frame.empty:
        raise ValueError("Dataset is empty.")
    if frame.columns.duplicated().any():
        raise ValueError("Dataset has duplicate column names.")

    selected_label = label_column
    if selected_label and selected_label not in frame.columns:
        raise ValueError(f"Label column {selected_label!r} does not exist.")
    if selected_label is None:
        selected_label = next(
            (column for candidate in LABEL_CANDIDATES
             for column in frame.columns
             if str(column).strip().casefold() == candidate.strip().casefold()),
            None,
        )

    numeric = frame.select_dtypes(include="number")
    columns = []
    for name in frame.columns:
        series = frame[name]
        columns.append({
            "name": str(name),
            "dtype": str(series.dtype),
            "missing": int(series.isna().sum()),
            "missing_fraction": round(float(series.isna().mean()), 6),
            "unique": int(series.nunique(dropna=True)),
            "numeric": bool(pd.api.types.is_numeric_dtype(series)),
        })

    labels = None
    if selected_label:
        counts = frame[selected_label].astype("string").fillna("<MISSING>").value_counts(dropna=False)
        labels = {
            "column": str(selected_label),
            "classes": int(len(counts)),
            "distribution": {str(key): int(value) for key, value in counts.items()},
        }

    return {
        "rows": int(len(frame)),
        "columns": int(len(frame.columns)),
        "numeric_columns": int(len(numeric.columns)),
        "duplicate_rows": int(frame.duplicated().sum()),
        "label": labels,
        "label_candidates_found": [
            str(column) for column in frame.columns
            if str(column).strip().casefold() in {x.strip().casefold() for x in LABEL_CANDIDATES}
        ],
        "schema": columns,
        "safety_notes": [
            "Source data was read only; no rows or labels were changed.",
            "Label detection is a hint, not a semantic mapping.",
            "Remove identifiers and leakage-prone columns deliberately before training.",
            "Check dataset licence, citation, collection context, and split provenance.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dataset", type=Path, help="Input CSV or Parquet file")
    parser.add_argument("--label-column", help="Explicit target column; otherwise report a likely candidate")
    parser.add_argument("--output", type=Path, help="Optional JSON report path")
    args = parser.parse_args()

    report = profile_frame(read_dataset(args.dataset), args.label_column)
    digest = hashlib.sha256()
    with args.dataset.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    report["source"] = {"path": str(args.dataset.resolve()), "sha256": digest.hexdigest()}
    rendered = json.dumps(report, indent=2, ensure_ascii=False)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
