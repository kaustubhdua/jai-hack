# Public benchmark model provenance

These are the runtime model files currently tracked by the repository:

| Artifact | SHA-256 | Size |
|---|---|---:|
| `threat_detection/model.joblib` | `3f419b27dcee2250284c65f1014a7b00d953bdd775304e9f7ce6df1981b51bc2` | 4,684,363 bytes |
| `anomaly_detection/model.joblib` | `42c395dad43b4dbdfda961120767ef3e4cca28345913ae756965cf3f2d21db09` | 7,580,156 bytes |

## Training and evaluation boundary

- Dataset: CIC-IDS2017, using the pinned Parquet mirror revision documented in [the benchmark procedure](../../docs/open-source-benchmark.md).
- Agent 1: five-class Random Forest trained on the documented subset.
- Agent 2: Isolation Forest fitted on BENIGN rows only; threshold selected on a training-side calibration holdout.
- Public evaluation partition: 42,747 records; not used for fitting or threshold calibration.
- The SHA-256 values above are verified by the publishing workflow against the original benchmark artifact manifest.
- Supporting training, evaluation and dataset manifests are in this directory.
- No raw dataset rows are stored in this repository.

## Critical interpretation

These models make the hosted prototype loadable and provide a reproducible public engineering baseline. They are **not** official JAI organizer models, and their metrics are **not** official challenge results. Agent 2 is supplementary, not a strong standalone detector. See [deployed model artifact provenance](../../docs/deployed-model-artifacts.md) for the limitations and release boundary.
