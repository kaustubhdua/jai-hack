# Open-data workflow

CyberSentinel is a personal, offline-first network-flow analysis project. It is
not tied to a hackathon organizer, private dataset, hosted database, identity
provider, or paid threat-intelligence API.

## Dataset sources to start with

Use the original provider page as the source of truth. Download datasets
yourself and retain the original archive and its licence/citation notes.

| Dataset | What it adds | Primary source |
|---|---|---|
| CIC-IDS2017 | Enterprise network-flow intrusion benchmark | https://www.unb.ca/cic/datasets/ids-2017.html |
| CSE-CIC-IDS2018 | Larger enterprise traffic and attack scenarios | https://www.unb.ca/cic/datasets/ids-2018.html |
| UNSW-NB15 | Modern synthetic/lab network traffic with multiple attack families | https://research.unsw.edu.au/projects/unsw-nb15-dataset |
| Bot-IoT | IoT botnet and attack traffic | https://research.unsw.edu.au/research/bot-iot-dataset |
| ToN-IoT | IoT/IIoT telemetry and network security events | https://research.unsw.edu.au/projects/toniot-datasets |
| UQ NetFlow datasets | Harmonised NetFlow feature sets across several benchmarks | https://www.cyber.uq.edu.au/project/machine-learning-based-nids-datasets |
| CICIoT2023 | Large-scale IoT attack traffic | https://www.unb.ca/cic/datasets/iotdataset-2023.html |

A curated index can help discover additional sources:
https://github.com/shramos/Awesome-Cybersecurity-Datasets

**Licensing is dataset-specific.** Do not assume that public download means
unrestricted redistribution or commercial use. Keep each dataset's original
licence, paper citation, download URL, retrieval date, and checksum with your
local copy. Do not commit raw datasets or private packet captures to Git.

## Inspect before training

Install the project dependencies, then profile any CSV or Parquet file:

```bash
python scripts/profile_dataset.py /path/to/flows.csv --output reports/generated/dataset-profile.json
python scripts/profile_dataset.py /path/to/flows.parquet --label-column attack_cat
```

The profiler reports dimensions, data types, missingness, duplicate rows,
numeric columns, and a likely label distribution. It is read-only and does not
infer semantic equivalence between labels such as `DoS`, `DDoS`, `Exploits`,
`Reconnaissance`, or `BENIGN`.

## Map labels deliberately

The current production model contract uses five classes:
`BENIGN`, `BRUTE_FORCE`, `DOS`, `DDOS`, and `PORT_SCAN`. A dataset with
different classes must not be passed directly to the current trainer and
silently coerced. Create and review an explicit mapping for the source dataset.
Keep unknown or ambiguous classes out of training until their treatment is
documented. Preserve the original label column in the immutable source file.

## Reproducible training and evaluation

The existing trainer supports CSV and Parquet, and requires all five canonical
classes. It creates a leakage-aware internal calibration holdout by default:

```bash
python scripts/train_models.py --help
python scripts/train_models.py \
  --train data/local/my-training.csv \
  --label-column label \
  --model-dir models/local \
  --report-dir reports/generated/local
```

Use the exact CLI flags shown by `--help` for the checked-out version. Prefer
provider-supplied train/test partitions where available. Never randomly mix
near-duplicate flows across train and test; use time-, host-, campaign-, or
source-group-aware splits when the dataset supports them. Fit preprocessing
only on training data. Evaluate on a separate labelled test partition and
report per-class precision/recall/F1, confusion matrix, PR-AUC where meaningful,
false-positive rate, calibration, and inference cost.

The checked-in model files are public-baseline artifacts. They are useful for
smoke tests and exploration, not proof of performance on every dataset or on
live networks. Re-train and evaluate for each new dataset; record its source,
licence, SHA-256, mapping, split strategy, feature schema, random seed, package
versions, model hash, and report hash.

## Local analyst workspace

Start the API on loopback for personal use:

```bash
uvicorn api.index:app --host 127.0.0.1 --port 8000
npm run dev
```

Open **Universal Data Lab** in the analyst console. Upload CSV/Parquet/Feather,
inspect the data, choose a model and explicit label mapping, train, then
evaluate on a separate dataset or run detection and export prediction/alert
CSVs. Experiment metadata and model hashes are stored in local SQLite/JSON.

Write-capable upload, training, detection and telemetry-ingestion routes are
disabled on Vercel. The hosted demo is public and account-free, so it must not
accept arbitrary public training jobs or private telemetry. Run the API locally
to use the personal workspace. Optional integrations are installed with
`pip install .[integrations]`; XGBoost and PyTorch are separate extras.

## Runtime and safety boundaries

- No Supabase, Neon, login, signup, hosted database, or paid API is required.
- Local history uses SQLite. Serverless deployments are stateless by design.
- The current five-agent inference contract is a network-flow feature contract;
  arbitrary CSV columns are not automatically valid model input.
- Replay actions are simulations. The app does not capture live traffic or
  change host firewalls.
- Do not upload sensitive production telemetry to a public deployment. Use
  local execution for private data.

## Next expansion path

1. Add explicit, tested adapters for each chosen dataset's column and label
   conventions.
2. Add schema-versioned model bundles so each model declares its feature set
   and label taxonomy.
3. Add cross-dataset evaluation to measure domain shift rather than claiming
   universal accuracy from one benchmark.
4. Add optional Zeek/Suricata/Wazuh log import as separate, opt-in integrations.
5. Add streaming ingestion only after validating resource limits, privacy, and
   operational safety.
