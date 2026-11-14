# Open-source benchmark bootstrap

## Purpose and boundary

The JAI organizer's private training, evaluation, and hidden replay packs are not present in a clean checkout. This workflow uses the public **CIC-IDS2017** dataset to make the learned agents trainable and independently testable without fabricating challenge data.

This is an external engineering benchmark only. It does **not** replace organizer-provided inputs, prove JAI challenge performance, or generate the organizer's hidden-set submissions. Keep public benchmark results clearly labelled as CIC-IDS2017 results.

## Dataset source and reproducibility

- Original publisher: Canadian Institute for Cybersecurity, University of New Brunswick.
- Canonical page: https://www.unb.ca/cic/datasets/ids-2017.html
- Machine-learning Parquet mirror: https://huggingface.co/datasets/bvsam/cic-ids-2017
- Pinned mirror revision: `a6628f1c99a39fd23b614a2d926ed679c264dd9b`
- Research citation: Iman Sharafaldin, Arash Habibi Lashkari, and Ali A. Ghorbani, “Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization”, ICISSP 2018.

The publisher describes CIC-IDS2017 as publicly available for researchers and requests citation. Verify current publisher terms before commercial use or redistribution. This repository downloads the Parquet files at run time and does not commit or redistribute the dataset.

## Explicit five-class mapping

CyberSentinel's current Agent 1 contract requires exactly five classes. The preparation script applies only these explicit mappings:

| CIC-IDS2017 raw label | CyberSentinel class |
|---|---|
| BENIGN | BENIGN |
| FTP-Patator, SSH-Patator | BRUTE_FORCE |
| DoS Hulk, DoS GoldenEye, DoS slowloris, DoS Slowhttptest | DOS |
| DDoS | DDOS |
| PortScan | PORT_SCAN |

Other attack families (including Bot, Infiltration, Heartbleed, and Web Attack variants) are excluded, counted, and written to the manifest. They are never silently relabelled into a class.

## Prepare, train, and evaluate

Install the project ML dependencies:

```bash
python -m pip install -e ".[dev,ml]"
```

Download the pinned dataset, apply the documented class mapping, remove ambiguous identical-feature groups, and create a stratified group-isolated train/evaluation split:

```bash
python scripts/prepare_public_benchmark.py \
  --output-dir data/raw/public-benchmark \
  --max-per-class 50000 \
  --seed 42
```

Train Agent 1 and Agent 2 from the public benchmark training partition:

```bash
python scripts/train_models.py \
  --train data/raw/public-benchmark/training.parquet \
  --label-column label \
  --model-dir models \
  --report-dir reports/generated \
  --n-estimators 200
```

Evaluate the saved artifacts on the untouched public benchmark holdout:

```bash
python scripts/evaluate_benchmark.py \
  --eval data/raw/public-benchmark/evaluation.parquet \
  --threat-model models/threat_detection/model.joblib \
  --anomaly-model models/anomaly_detection/model.joblib \
  --output reports/generated/cic_ids2017_public_evaluation.json
```

The evaluation command loads models only; it does not fit, calibrate, or select thresholds. The training manifest and benchmark manifest record dataset revision, source hashes, split details, label mapping, class counts, model hashes, and training/evaluation boundaries.

## Automated execution

GitHub Actions includes a manually triggered workflow named **Public CIC-IDS2017 benchmark**. It downloads the pinned public benchmark, prepares a group-isolated split, trains both learned agents, evaluates on the holdout, runs the full test suite, and uploads model binaries plus provenance/evaluation reports as a 30-day Actions artifact. Raw datasets are not uploaded as workflow artifacts.

Run it from GitHub Actions → Public CIC-IDS2017 benchmark → Run workflow. The artifact is for local/offline engineering validation; it is not automatically installed into Vercel or Supabase.

## Independent generalisation

UNSW-NB15 is a second, independent public dataset maintained by UNSW Canberra: https://research.unsw.edu.au/projects/unsw-nb15-dataset. Its feature schema and class taxonomy differ from CIC-IDS2017 and CyberSentinel's five-class organizer contract. Do not directly feed it to the CIC-trained model or claim a cross-dataset score by coercing labels. A separate schema adapter and independently trained/evaluated experiment are required before reporting UNSW-NB15 results.

## What this does not prove

- It does not reproduce the JAI organizer's official training or evaluation score.
- It does not contain or infer the private hidden replay input.
- It does not prove the Vercel production deployment has model artifacts.
- It does not prove Supabase authentication or two-user RLS isolation.
- It does not prove official submission acceptance.

Official release readiness still requires the organizer's actual packs, local hidden replay, validated three-file submission bundle, live deployment checks, and authenticated browser acceptance.