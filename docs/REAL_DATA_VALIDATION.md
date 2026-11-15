# Real-data validation record

Date: 2026-11-15  
Validated commit: `4a1941c3000cc2ee8bf7ed262068ec7702863a61`  
Execution: clean Vercel sandbox, Python 3.14.4, local FastAPI + SQLite + filesystem workspace  
Raw datasets and derived samples were kept outside Git.

## Scope and result

The complete local data path was exercised with real, research-use network-flow data from two benchmark corpora:

- CIC-IDS2017: import, profile, Random Forest training, held-out evaluation, a second-shard evaluation, detection, and both CSV exports all succeeded.
- UNSW-NB15: import, profile, Random Forest training, and second-shard evaluation all succeeded.
- Public Vercel: actual multipart/JSON POSTs to every workspace write family returned the intended `403` with an explicit message that uploads and training are disabled on the serverless demo.

This is a software integration validation, not a claim that the resulting models are production IDS models.

## CIC-IDS2017

Provider: [Canadian Institute for Cybersecurity, University of New Brunswick](https://www.unb.ca/cic/datasets/ids-2017.html). The provider states that the labeled flow data are available for researchers and requires citation of the original paper. A public Parquet conversion of the corpus was used for this run: [muzom/CIC-IDS2017](https://huggingface.co/datasets/muzom/CIC-IDS2017). The conversion is a mirror, not an official UNB distribution; the original provider terms remain controlling. Do not redistribute the source data.

Original citation: I. Sharafaldin, A. H. Lashkari, and A. A. Ghorbani, “Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization,” ICISSP, 2018, DOI: [10.5220/0006639801080116](https://doi.org/10.5220/0006639801080116).

| Item | Value |
|---|---:|
| Source Parquet shard 0 rows | 793,245 |
| Source Parquet shard 1 rows | 788,520 |
| Training sample | 5,760 rows |
| Held-out same-shard sample | 1,440 rows |
| Second-shard sample | 6,427 rows |
| Features used | 78 numeric flow features |
| Model | Random Forest, 100 trees, max depth 24, seed 20261115 |

The train and same-shard test samples were built by deterministic, stratified sampling (1,800 per class from the four classes in shard 0), then an 80/20 stratified split. The same-shard holdout produced **99.31% accuracy and 0.9931 macro-F1**. This is a smoke/within-shard result only: random splits can overstate generalization when flows share capture conditions or near-duplicate patterns.

The second-shard evaluation intentionally exercised label novelty. It contained 5,000 BENIGN, 1,391 Web Attack – Brute Force, and 36 Infiltration records. Only BENIGN overlapped the four training labels (BENIGN, Bot, DDoS, PortScan); the evaluator correctly surfaced Infiltration and Web Attack – Brute Force as unknown target labels. Overall accuracy was **76.86%** and macro-F1 **0.1449**. These numbers must not be presented as a conventional fully-known-class score; the class-coverage warning is the important result. It demonstrates why high random-holdout accuracy is not enough.

Sample hashes:
- Train CSV SHA-256: `51ad59b187ae26d4791b0683b6719ed75e31740b2aba1c06467b6ac6d576a144`
- Same-shard test CSV SHA-256: `7a2fa3dfd0413706ab31893fd27488401065f8e3de0ed48c95be1d4be0809f20`
- Second-shard CSV SHA-256: `6c0fc294680222dc6a63af2685427ae24e5f3a1d878da76610cf5e1f9f97e43e`
- Source shard 0 SHA-256: `74c1cf554ea140862ce6a727d3e5529b023a441c36bd67bb02e3b832d95b3235`
- Source shard 1 SHA-256: `ac81cbd3cbd4810e2c076505c7ecc825095d31d0a161d23e327de4bbbbb1f79a`

## UNSW-NB15

Provider: [UNSW Research — UNSW-NB15](https://research.unsw.edu.au/projects/unsw-nb15-dataset). The provider grants free use for academic research and requires citation; commercial use requires agreement with the authors. The public Parquet conversion used for this run was [Mouwiya/UNSW-NB15](https://huggingface.co/datasets/Mouwiya/UNSW-NB15), derived from the original UNSW-NB15 files. The mirror's shards are not the provider's canonical train/test split. Obtain the original provider files and follow the provider's terms for formal research or commercial use.

Original citations include N. Moustafa and J. Slay, “UNSW-NB15: a comprehensive data set for network intrusion detection systems,” MilCIS, 2015, and “The evaluation of Network Anomaly Detection Systems,” Information Security Journal, 2016.

| Item | Value |
|---|---:|
| Source shard rows | 1,140,045 each |
| Training sample | 4,320 rows |
| Second-shard evaluation sample | 4,618 rows |
| Classes | 10 (Normal plus nine attack categories) |
| Features used | 8 shared numeric flow features |
| Model | Random Forest, 100 trees, max depth 24, seed 20261115 |

Normal labels were reconstructed from the source's missing `attack_cat` values, whitespace was trimmed, and the singular `Backdoor` spelling was normalized to `Backdoors`. Per-class sampling was capped at 500; the rare Worms class therefore has 32 training examples and 118 evaluation examples. This class imbalance/rarity is retained in the report rather than hidden.

Second-shard evaluation: **66.39% accuracy, 0.6739 macro-F1, 0.6623 weighted-F1**. This is a held-out Parquet-shard experiment, not the provider's official train/test split and not a cross-dataset result.

Sample hashes:
- Train CSV SHA-256: `e7e36b1e5453b9205ece2ed22afb11b6b756cc8c4c99eaf34053544809e205a8`
- Test CSV SHA-256: `0edd316ec2411ddecd5942040f07730ca38e8bc2a574f8e93d3725fba2251cd7`
- Source shard 0 SHA-256: `2aada2a26d061111f4e8fb84e716f5f11264fee71abe04697d42cb89e488d047`
- Source shard 1 SHA-256: `7c6699ae967567977dee9e9193543b515255f4e1671ca79bf9ae65e7866ffef1`

## HTTP acceptance

Against the deployed production host `https://jai-hack-steel.vercel.app`:

| Route | Method | Expected | Observed |
|---|---|---:|---:|
| `/api/health` | GET | 200 | 200 |
| `/api/system/diagnostics` | GET | 200 | 200 |
| `/api/models/status` | GET | 200 | 200 |
| `/api/history` | GET | 200 | 200 |
| `/api/workspace/datasets` | GET | 200 | 200 |
| `/api/workspace/experiments` | GET | 200 | 200 |
| `/api/workspace/datasets/{invalid-id}/profile` | GET | 400 | 400 |
| `/api/workspace/exports/{missing-file}` | GET | 404 | 404 |
| `/api/workspace/datasets` | POST | 403 | 403 |
| `/api/workspace/train` | POST | 403 | 403 |
| `/api/workspace/evaluate` | POST | 403 | 403 |
| `/api/workspace/detect/{id}` | POST | 403 | 403 |
| `/api/workspace/integrations/{zeek,suricata,wazuh,sigma}` | POST | 403 | 403 |

The public POST checks used real HTTP requests with multipart uploads or JSON bodies. They confirmed the deliberate fail-closed serverless boundary. The same routes were exercised locally with real multipart upload, training, evaluation, detection, and downloadable prediction/alert exports.

## Remaining limits

1. CIC-IDS2017 and UNSW-NB15 have now both been exercised end-to-end. ToN-IoT, Bot-IoT, CSE-CIC-IDS2018, and CICIoT2023 still need their own source-specific benchmark runs.
2. These experiments use deterministic samples of public mirror conversions. For publication-grade results, repeat with the original provider archives and official split files; use day/host-separated evaluation and duplicate/leakage audits.
3. The public Vercel deployment is a read-only demo by design. Persistent uploads, model artifacts, and experiment history belong on the local machine or another persistent host. Do not enable write endpoints on Vercel's ephemeral filesystem.
4. The initial broad `ruff check src api scripts tests` surfaced pre-existing lint findings across legacy modules. The existing CI workflows and 180-test suite passed; lint cleanliness is not claimed by this report.
