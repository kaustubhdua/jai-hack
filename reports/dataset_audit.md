# CyberSentinel dataset intelligence report

## Scope

This audit covers the provided training and eval Parquet files. It is a data-preparation handoff for Member 1; no classifier, anomaly detector, fusion policy, or API submission was performed.

## Schema and labels

- Training: **456,737 rows**; eval: **114,185 rows**.
- Both files have **80 columns** in the same order: **78 numeric traffic features**, `record_id`, and `label`.
- The target is `label`. The labels already match the five organizer classes: `BENIGN, BRUTE_FORCE, DOS, DDOS, PORT_SCAN`.
- `record_id` is retained in the raw data for tracing but excluded from prepared model inputs.

| Class | Training rows | Training % | Eval rows | Eval % |
|---|---:|---:|---:|---:|
| BENIGN | 240,000 | 52.55% | 60,001 | 52.55% |
| BRUTE_FORCE | 5,537 | 1.21% | 1,384 | 1.21% |
| DOS | 96,000 | 21.02% | 24,000 | 21.02% |
| DDOS | 57,600 | 12.61% | 14,400 | 12.61% |
| PORT_SCAN | 57,600 | 12.61% | 14,400 | 12.61% |

BRUTE_FORCE is the minority class at about 1.21% of each split (about 43 times fewer rows than BENIGN). Use class-aware training and report macro-F1; do not rebalance the official eval split.

## Data quality findings

- Null cells: **0 training**, **0 eval**. Infinite numeric values: **0 training**, **0 eval**.
- Full-row duplicates: **0 training**, **0 eval**. Duplicate IDs: **0 training**, **0 eval**.
- Repeated feature vectors (excluding ID and label): **39,423 training rows** across 15,291 repeated groups; **4,066 eval rows** across 1,793 repeated groups. Feature groups with label conflicts: **0 training**, **0 eval**.
- Cross-split feature overlap: **9,795 eval rows (8.58%)** have a feature vector also seen in training. Shared vectors have 0 label-set conflicts. Keep the official eval records unchanged, and disclose this overlap when interpreting scores.
- Negative byte-header lengths appear in a small number of rows despite being impossible for a length field:
  - training: `Fwd Header Length` 37, `Bwd Header Length` 70, `Fwd Header Length_duplicated_0` 37.
  - eval: `Fwd Header Length` 10, `Bwd Header Length` 16, `Fwd Header Length_duplicated_0` 10.
- All negative header-length values are in BENIGN rows. The preprocessor treats them as invalid/missing and fills them with the corresponding **training median**; eval medians are never fitted.

## Leakage and redundant columns

- A diagnostic using only ten `record_id` ranges, with majority labels learned from training, gets **69.1% eval accuracy** and **0.513 macro-F1**. This is evidence that IDs encode source-row ordering associated with labels. Never pass `record_id` to either ML agent.
- Constant training features removed: `Fwd URG Flags`, `Bwd URG Flags`, `URG Flag Count`.
- Exact duplicate columns removed (the first schema occurrence is retained): `Average Packet Size` (same as `Packet Length Mean`), `Avg Fwd Segment Size` (same as `Fwd Packet Length Mean`), `Avg Bwd Segment Size` (same as `Bwd Packet Length Mean`), `Fwd Header Length_duplicated_0` (same as `Fwd Header Length`).
- Prepared matrix has **71 numeric features** after removing constants and duplicate columns, with the original row order preserved.

## Handoff artifacts

- `data/processed/`: local model-ready Parquet files and preprocessing state. These are generated from organiser data and are git-ignored.
- `preprocessing_state.json`: fitted feature list, dropped-column reasons, medians, and robust-scaling statistics. Load it with `FlowPreprocessor.load(...)` to apply the exact same transform later.
- `training_prepared.parquet` and `eval_prepared.parquet`: all original rows, model-ready numeric features plus string label, no ID, no full-row drops. Training-only imputation values are used in both.
- `dataset_profile.json`: machine-readable audit summary.

Example use:
```python
from pathlib import Path
import pandas as pd
from flow_preprocessor import FlowPreprocessor
processor = FlowPreprocessor.load(Path('preprocessing_state.json'))
raw_eval = pd.read_parquet('/path/to/eval/flows.parquet')
X_eval_scaled = processor.transform_features(raw_eval, scaled=True)  # anomaly agent
y_eval, eval_ids = processor.labels_and_ids(raw_eval)  # metadata stays separate
```

Dependencies: Python 3, pandas, NumPy, and PyArrow.
