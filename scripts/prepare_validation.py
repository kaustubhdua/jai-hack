"""Apply the training-fitted flow preprocessor to a separate labelled validation file."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import pandas as pd
from cybersentinel.data.cleaning import FlowPreprocessor

def read_frame(path: Path) -> pd.DataFrame:
    if path.suffix.lower() in {".parquet", ".pq"}:
        return pd.read_parquet(path)
    return pd.read_csv(path, low_memory=False)

def prepare_validation(input_path: Path, state_path: Path, output_path: Path) -> dict:
    if not input_path.is_file():
        raise FileNotFoundError(f"Validation input not found: {input_path}")
    if not state_path.is_file():
        raise FileNotFoundError(f"Training-fitted preprocessing state not found: {state_path}")
    raw = read_frame(input_path)
    processor = FlowPreprocessor.load(state_path)
    if "record_id" not in raw.columns or "label" not in raw.columns:
        raise ValueError("Labelled validation input must contain organizer record_id and label columns.")
    prepared = processor.transform(raw, include_label=True)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if output_path.suffix.lower() in {".parquet", ".pq"}:
        prepared.to_parquet(output_path, index=False)
    else:
        prepared.to_csv(output_path, index=False)
    return {
        "input": str(input_path), "output": str(output_path),
        "rows": int(len(prepared)), "feature_count": int(len(processor.feature_columns)),
        "classes": sorted(prepared["label"].astype(str).unique().tolist()),
        "record_id_retained_in_model_matrix": False,
        "preprocessing_state": str(state_path),
    }

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True, help="Separate labelled validation CSV or Parquet")
    parser.add_argument("--preprocessor-state", type=Path, default=Path("data/processed/preprocessing_state.json"))
    parser.add_argument("--output", type=Path, default=Path("data/processed/labelled_validation_prepared.parquet"))
    args = parser.parse_args()
    print(json.dumps(prepare_validation(args.input, args.preprocessor_state, args.output), indent=2))

if __name__ == "__main__":
    main()
