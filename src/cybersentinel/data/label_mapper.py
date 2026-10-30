"""Strict, deterministic label mapping for benchmark classes."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Mapping

import pandas as pd

from cybersentinel.data.schema import BENCHMARK_CLASSES, TARGET_COLUMN


class LabelMapper:
    """Validate or map incoming labels strictly into canonical benchmark classes."""

    def __init__(self, mapping: Mapping[str, str] | None = None) -> None:
        self.mapping = dict(mapping) if mapping is not None else None

    @classmethod
    def from_file(cls, path: str | Path) -> "LabelMapper":
        with open(path, "r", encoding="utf-8") as f:
            mapping = json.load(f)
        if not isinstance(mapping, dict):
            raise ValueError(f"Label map file must be a JSON dictionary, got {type(mapping).__name__}")
        return cls(mapping=mapping)

    def map_series(self, series: pd.Series) -> pd.Series:
        """Map raw target series to benchmark classes, verifying every value."""
        str_series = series.astype(str).str.strip()
        if self.mapping is not None:
            # Check for unknown source labels
            unmapped = set(str_series.unique()) - set(self.mapping.keys())
            if unmapped:
                raise ValueError(
                    f"Found {len(unmapped)} unknown labels without official mapping: {sorted(list(unmapped))[:10]}"
                )
            str_series = str_series.map(self.mapping)

        # Verify all mapped values belong to BENCHMARK_CLASSES
        invalid = set(str_series.unique()) - set(BENCHMARK_CLASSES)
        if invalid:
            raise ValueError(
                f"Dataset contains invalid benchmark labels: {sorted(list(invalid))}. Expected subset of {BENCHMARK_CLASSES}"
            )
        return str_series

    def map_single(self, raw_label: str) -> str:
        clean = str(raw_label).strip()
        if self.mapping is not None:
            if clean not in self.mapping:
                raise ValueError(f"Label '{clean}' not found in official mapping table")
            clean = self.mapping[clean]
        if clean not in BENCHMARK_CLASSES:
            raise ValueError(f"Label '{clean}' is not an official benchmark class ({BENCHMARK_CLASSES})")
        return clean

