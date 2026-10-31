#!/usr/bin/env python3
"""Validate an unlabelled chronological replay CSV/Parquet before model inference."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

import pandas as pd

from cybersentinel.replay.input_validation import validate_replay_input


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True, help="Organizer replay CSV or Parquet")
    args = parser.parse_args()
    if not args.input.is_file():
        print(f"INPUT VALIDATION FAILED: file not found: {args.input}")
        return 2
    try:
        frame = pd.read_parquet(args.input) if args.input.suffix.lower() in {".parquet", ".pq"} else pd.read_csv(args.input)
        report = validate_replay_input(frame)
    except Exception as exc:
        print(f"INPUT VALIDATION COULD NOT RUN: {type(exc).__name__}: {exc}")
        return 2
    print(json.dumps(report, indent=2))
    print("REPLAY INPUT VALIDATION PASSED" if report["valid"] else "REPLAY INPUT VALIDATION FAILED")
    return 0 if report["valid"] else 1


if __name__ == "__main__":
    sys.exit(main())
