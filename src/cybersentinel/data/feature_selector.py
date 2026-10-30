"""Feature selector to detect and remove constant and duplicate feature columns."""
from __future__ import annotations

import pandas as pd


def identify_constant_features(df: pd.DataFrame, feature_columns: list[str]) -> list[str]:
    """Find columns with <= 1 unique value on training data."""
    return [col for col in feature_columns if df[col].nunique(dropna=False) <= 1]


def identify_duplicate_features(df: pd.DataFrame, feature_columns: list[str]) -> dict[str, str]:
    """Find duplicate feature columns on training data, mapping duplicated -> original."""
    duplicates: dict[str, str] = {}
    for idx, col1 in enumerate(feature_columns):
        if col1 in duplicates:
            continue
        for col2 in feature_columns[idx + 1:]:
            if col2 in duplicates:
                continue
            if df[col1].equals(df[col2]):
                duplicates[col2] = col1
    return duplicates

