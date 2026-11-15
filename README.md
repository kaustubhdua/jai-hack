# CyberSentinel

**Offline-first cybersecurity analytics and multi-agent threat detection.**

CyberSentinel is a personal, open-data security analytics workspace for importing network-flow datasets, training reproducible detection models, measuring cross-dataset generalization, and investigating security telemetry. It combines a React/TypeScript analyst console with a FastAPI/Python ML backend and local SQLite experiment history.

The application does not require Supabase, Neon, login/signup, a hosted database, paid APIs, or an external identity provider.

> **Safety boundary:** the five-agent replay engine and the new Universal Data Lab operate on supplied files and logs. ALLOW/BLOCK decisions are simulated. CyberSentinel does not capture live packets, monitor sockets, execute Sigma rules, or modify operating-system firewalls.

## Product capabilities

| Capability | Implementation |
|---|---|
| Dataset import | CSV, Parquet, Feather/Arrow |
| Dataset adapters | CIC-IDS2017-style flows, UNSW-NB15, ToN-IoT, Bot-IoT, CSE-CIC-IDS2018, CICIoT2023, generic tabular data |
| Provenance | SHA-256 source hashes, model hashes, versioned experiment manifests |
| Supervised models | Random Forest; optional XGBoost |
| Unsupervised detection | Isolation Forest |
| Deep learning | Optional PyTorch MLP |
| Evaluation | Held-out evaluation and cross-dataset classification metrics |
| Domain shift | Feature-wise standardized mean difference (descriptive drift indicator) |
| Security telemetry | Zeek conn.log, Suricata EVE JSONL, Wazuh alert JSON |
| Detection content | Sigma YAML metadata import (rules are not executed) |
| History | Local SQLite experiment registry |
| Exports | Prediction, alert, evaluation and manifest JSON/CSV |

## Quick start

Requirements: Python 3.10+, Node.js 20+, and npm.

```bash
git clone https://github.com/kaustubhdua/jai-hack.git
cd jai-hack
python -m venv .venv
# Windows: .venv\Scripts\activate
source .venv/bin/activate
pip install -e ".[dev,ml]"
npm install
```

Start the API on loopback and the frontend in separate terminals:

```bash
uvicorn api.index:app --host 127.0.0.1 --port 8000
npm run dev
```

Open **Universal Data Lab** in the analyst console. Upload a dataset, inspect its schema and label distribution, choose a model and feature contract, train an experiment, then evaluate against a different dataset or run detection and export alerts.

### Optional model and parser dependencies

```bash
pip install -e ".[xgboost]"       # XGBoost classifier
pip install -e ".[pytorch]"       # PyTorch MLP classifier
pip install -e ".[integrations]"  # Sigma YAML parser
```

Optional dependencies are imported only when the corresponding model or parser is selected.

## Open datasets

Use the original provider page for downloads, licence terms, citations, and collection details. Public availability does not automatically grant redistribution or commercial-use rights.

| Dataset | Primary source |
|---|---|
| CIC-IDS2017 | https://www.unb.ca/cic/datasets/ids-2017.html |
| CSE-CIC-IDS2018 | https://www.unb.ca/cic/datasets/ids-2018.html |
| UNSW-NB15 | https://research.unsw.edu.au/projects/unsw-nb15-dataset |
| Bot-IoT | https://research.unsw.edu.au/research/bot-iot-dataset |
| ToN-IoT | https://research.unsw.edu.au/projects/toniot-datasets |
| CICIoT2023 | https://www.unb.ca/cic/datasets/iotdataset-2023.html |
| UQ NetFlow datasets | https://www.cyber.uq.edu.au/project/machine-learning-based-nids-datasets |
| Dataset discovery index | https://github.com/shramos/Awesome-Cybersecurity-Datasets |

Keep the original archive, provider URL, retrieval date, licence, citation, and SHA-256 checksum with every local dataset. Do not commit raw datasets, packet captures, personal telemetry, or generated model artifacts containing sensitive data.

See [dataset adapter contracts](docs/DATASET_ADAPTERS.md) for the exact label priorities, canonical feature names, unit conversions, and rules for adding a new adapter.

## Dataset profiling and adapters

Profile a local dataset before training:

```bash
python scripts/profile_dataset.py /path/to/flows.csv --output reports/generated/profile.json
python scripts/profile_dataset.py /path/to/flows.parquet --label-column attack_cat
```

The profiler is read-only. The adapters normalize selected column aliases and retain the original label values. They do not guess that labels such as `DoS`, `DDoS`, `Exploits`, `Reconnaissance`, `Normal`, and `BENIGN` mean the same thing.

For reproducible classification, supply an explicit label mapping when source taxonomies differ. Unknown labels fail validation rather than being silently removed.

## Model and experiment pipeline

The Universal Data Lab supports:

- **Random Forest** — supervised multi-class baseline.
- **XGBoost** — optional supervised boosted trees.
- **Isolation Forest** — unsupervised anomaly detection; no label column required.
- **PyTorch MLP** — optional neural classifier.

Feature selection can be an explicit allow-list or a drop-list. The saved model artifact includes its version, estimator, feature contract, label classes, training feature statistics and configuration. The experiment manifest includes dataset provenance, source hash, model hash, random seed, runtime versions and training row count.

### Cross-dataset evaluation

Train on one dataset and evaluate on a separate dataset using the same canonical feature contract and explicit label mapping. Reports include accuracy, macro/weighted F1, per-class metrics, confusion matrix, unknown target labels and a feature-drift summary.

The feature-drift index uses mean absolute standardized mean differences between training and target feature distributions. It is a descriptive warning, **not** a causal explanation or a substitute for held-out performance metrics. A high score can reflect units, preprocessing, collection environment, or genuine distribution shift.

For CIC-IDS2017 and UNSW-NB15, select features that are semantically aligned across both sources. Do not compare identically named fields whose units differ without normalization. Prefer time-, host-, campaign-, or source-group-aware splits; avoid random row splits where near-duplicate flows can leak across partitions.

## Open-source integrations

The local workspace can ingest:

- **Zeek** `conn.log` with its `#fields` header.
- **Suricata** EVE JSON Lines, including alert signature and severity metadata.
- **Wazuh** JSON alert exports.
- **Sigma** YAML rule metadata.

The importers parse and normalize records; they do not run detection engines or execute Sigma rules. Event logs without ground-truth labels can be explored or used for unsupervised analysis, but must not be treated as labelled benchmark data.

## API workspace routes

All workspace routes are under `/api/workspace`:

| Route | Purpose |
|---|---|
| `POST /datasets` | Upload CSV/Parquet/Feather |
| `GET /datasets` | List local datasets |
| `GET /datasets/{id}/profile` | Inspect schema and labels |
| `POST /train` | Train a versioned experiment |
| `GET /experiments` | Local experiment history |
| `POST /evaluate` | Cross-dataset evaluation |
| `POST /detect/{experiment_id}?dataset_id=...` | Run inference and export alerts |
| `POST /integrations/{zeek\|suricata\|wazuh\|sigma}` | Import security telemetry/rule metadata |
| `GET /exports/{filename}` | Download generated CSV/JSON |

## Privacy and deployment boundary

The analyst workspace writes uploaded datasets, model files and experiment history to local storage under `data/workspace/`. Bind the development API to `127.0.0.1` and do not expose it to an untrusted network.

Write-capable workspace routes are disabled on Vercel. Serverless storage is ephemeral and the public, account-free demo must not accept arbitrary public model-training jobs or private telemetry. The hosted deployment remains a read-only demonstration; use local execution for personal data and durable experiments.

## Existing five-agent replay system

The original five-agent network-flow pipeline remains available:

1. Supervised threat classification.
2. Benign-baseline anomaly scoring.
3. Deterministic evidence fusion.
4. Chronological temporal correlation.
5. Forward-looking simulated adaptive-defense policies.

Its checked-in model artifacts are public-baseline smoke-test models. They are not proof of universal performance. Re-train and evaluate for each dataset and preserve the associated manifest.

## Development and tests

```bash
pytest
ruff check src api scripts tests
npm run build
```

Use synthetic fixtures for automated tests. Keep downloaded public datasets outside the repository and never fabricate evaluation results when labels or source data are unavailable.

## Documentation

- [Open-data workflow](docs/OPEN_DATA_WORKFLOW.md)
- [Synthetic judge demo](docs/synthetic-judge-demo.md)
- [Source code](https://github.com/kaustubhdua/jai-hack)
