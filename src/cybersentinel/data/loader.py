"""Safe, validated flow dataset loading for Parquet and CSV files."""
from __future__ import annotations

from pathlib import Path
from typing import Tuple

import pandas as pd

from cybersentinel.data.schema import ID_COLUMN, TARGET_COLUMN


def load_flow_dataset(
    path: str | Path,
    expected_columns: list[str] | None = None,
) -> pd.DataFrame:
    """Load a flow dataset from Parquet or CSV with ordering preserved."""
    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"Dataset file not found: {file_path}")

    suffix = file_path.suffix.lower()
    if suffix in (".parquet", ".pq"):
        df = pd.read_parquet(file_path)
    elif suffix in (".csv", ".txt"):
        df = pd.read_csv(file_path, low_memory=False)
    else:
        raise ValueError(f"Unsupported dataset format '{suffix}'. Expected .parquet or .csv")

    if expected_columns is not None:
        missing = [col for col in expected_columns if col not in df.columns]
        if missing:
            raise ValueError(f"Dataset missing {len(missing)} required columns: {missing[:5]}")

    return df


def split_metadata(df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.Series | None, pd.Series | None]:
    """Separate features, target label series, and record IDs without altering ordering."""
    record_ids = df[ID_COLUMN] if ID_COLUMN in df.columns else None
    labels = df[TARGET_COLUMN] if TARGET_COLUMN in df.columns else None

    cols_to_drop = [c for c in (ID_COLUMN, TARGET_COLUMN) if c in df.columns]
    features = df.drop(columns=cols_to_drop)

    return features, labels, record_ids

