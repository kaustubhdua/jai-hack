"""Canonical schemas and definitions for CyberSentinel flow datasets."""
from typing import Final, Sequence

BENCHMARK_CLASSES: Final[tuple[str, ...]] = (
    "BENIGN",
    "BRUTE_FORCE",
    "DOS",
    "DDOS",
    "PORT_SCAN",
)

LABEL_TO_ID: Final[dict[str, int]] = {label: idx for idx, label in enumerate(BENCHMARK_CLASSES)}
ID_TO_LABEL: Final[dict[int, str]] = {idx: label for idx, label in enumerate(BENCHMARK_CLASSES)}

ID_COLUMN: Final[str] = "record_id"
TARGET_COLUMN: Final[str] = "label"

NONNEGATIVE_LENGTH_COLUMNS: Final[tuple[str, ...]] = (
    "Fwd Header Length",
    "Bwd Header Length",
    "Fwd Header Length_duplicated_0",
)

CONSTANT_COLUMNS_IN_TRAINING: Final[tuple[str, ...]] = (
    "Fwd URG Flags",
    "Bwd URG Flags",
    "URG Flag Count",
)

DUPLICATE_COLUMNS_IN_TRAINING: Final[dict[str, str]] = {
    "Average Packet Size": "Packet Length Mean",
    "Avg Fwd Segment Size": "Fwd Packet Length Mean",
    "Avg Bwd Segment Size": "Bwd Packet Length Mean",
    "Fwd Header Length_duplicated_0": "Fwd Header Length",
}

