#!/usr/bin/env python
"""CLI tool to strictly validate the CyberSentinel 3-file submission bundle."""
from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path
import sys

import pandas as pd

from cybersentinel.replay.submission import SubmissionValidator

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("validate_submissions")


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate CyberSentinel Level 2 submission bundle.")
    parser.add_argument(
        "--input",
        type=Path,
        required=True,
        help="Path to input test/eval dataset (parquet or csv) to get expected record IDs",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        required=True,
        help="Directory containing classification.csv, policy.csv, and replay.csv",
    )
    args = parser.parse_args()

    if not args.input.is_file():
        logger.error("Input file not found: %s", args.input)
        return 1

    if not args.output_dir.is_dir():
        logger.error("Output directory not found: %s", args.output_dir)
        return 1

    logger.info("Reading expected record IDs from %s...", args.input)
    if args.input.suffix.lower() == ".parquet":
        df = pd.read_parquet(args.input)
    else:
        df = pd.read_csv(args.input)

    if "record_id" in df.columns:
        expected_records = df["record_id"].tolist()
    else:
        expected_records = list(range(len(df)))

    logger.info("Found %d expected record IDs. Validating submission bundle in %s...", len(expected_records), args.output_dir)
    report = SubmissionValidator.validate_submission_bundle(args.output_dir, expected_records)

    logger.info("Validation Status: %s (all_valid: %s)", report["status"], report["all_valid"])
    logger.info("Classification valid: %s, errors: %d", report["classification"]["valid"], report["classification"]["total_errors"])
    logger.info("Policy valid: %s, errors: %d", report["policy"]["valid"], report["policy"]["total_errors"])
    logger.info("Replay valid: %s, errors: %d", report["replay"]["valid"], report["replay"]["total_errors"])

    if not report["all_valid"]:
        logger.error("Validation failed! Details written to %s", args.output_dir / "validation_report.json")
        return 1

    logger.info("All submission files passed strict validation! Ready for upload.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
