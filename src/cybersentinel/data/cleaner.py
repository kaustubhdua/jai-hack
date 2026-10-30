"""Data cleaning, sanitization, and missing/infinite value handling."""
from __future__ import annotations

from typing import Mapping

import numpy as np
import pandas as pd

from cybersentinel.data.schema import NONNEGATIVE_LENGTH_COLUMNS


def sanitize_flow_features(
    df: pd.DataFrame,
    feature_columns: list[str],
) -> pd.DataFrame:
    """Coerce features to numeric, map infinities and negative lengths to NaN."""
    cleaned = df[feature_columns].copy()

    for col in feature_columns:
        if not np.issubdtype(cleaned[col].dtype, np.number):
            cleaned[col] = pd.to_numeric(cleaned[col], errors="coerce")

    # Replace inf and -inf with NaN
    cleaned = cleaned.replace([np.inf, -np.inf], np.nan)

    # Replace invalid negative header lengths with NaN
    for col in NONNEGATIVE_LENGTH_COLUMNS:
        if col in cleaned.columns:
            cleaned.loc[cleaned[col] < 0, col] = np.nan

    return cleaned


def impute_missing(
    df: pd.DataFrame,
    medians: Mapping[str, float],
) -> pd.DataFrame:
    """Impute NaNs using pre-fitted training medians."""
    imputed = df.copy()
    for col, med in medians.items():
        if col in imputed.columns:
            imputed[col] = imputed[col].fillna(med)
    return imputed

