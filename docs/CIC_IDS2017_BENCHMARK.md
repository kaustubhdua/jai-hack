# CIC-IDS2017 real-data smoke benchmark

**Status:** real-data smoke benchmark completed for the classifier, fusion path, and anomaly detector. This is not a full-corpus or cross-dataset validation.

## Dataset and provenance

- Dataset mirror: `bvsam/cic-ids-2017` on Hugging Face.
- Upstream dataset: Canadian Institute for Cybersecurity (CIC) IDS 2017.
- The mirror's dataset card did not declare a reuse license when checked. Confirm the original UNB/CIC terms before redistribution or commercial use. The source files and prepared rows are deliberately not committed here.
- Deterministic sample: up to 2,500 rows per canonical class, for 12,500 rows total.
- Canonical classes: `BENIGN`, `BRUTE_FORCE`, `DOS`, `DDOS`, `PORT_SCAN`.
- Split: 80% training / 20% held-out evaluation within each class, ordered chronologically within each class after deterministic sampling. Result: 10,000 training rows and 2,500 evaluation rows (500 per class).
- This sample excludes other source families such as Bot, Infiltration, Web Attack XSS/SQL Injection, and Heartbleed. The five-class score must not be represented as coverage of all CIC-IDS2017 attack families.

## Measured results

### Supervised classifier (A1)

| Metric | Held-out result |
|---|---:|
| Accuracy | 82.56% |
| Balanced accuracy | 82.56% |
| Macro-F1 | 78.92% |
| Benign false-positive rate | 0.80% |
| Attack detection rate | 78.45% |

The separate fusion report rounded standalone A1 accuracy to 83.0%.

### Evidence fusion (A3)

| Metric | Held-out result |
|---|---:|
| Flows evaluated | 2,500 |
| Incomplete fusion outputs | 0 |
| A1 accuracy (rounded report) | 83.0% |
| A3 accuracy (rounded report) | 83.0% |
| Predictions overridden | 0 |

On this sample, fusion did not improve the classifier's class predictions. The action policy produced 610 ALLOW, 1,556 REVIEW, and 334 BLOCK decisions. It produced zero false BLOCK decisions on the 500 benign rows and five benign REVIEW decisions. These are simulated policy outputs; the application does not apply firewall rules or block live traffic.

### Anomaly detector (A2)

| Metric | Held-out result |
|---|---:|
| ROC-AUC | 0.8258 |
| Average precision (PR-AUC) | 0.9222 |
| Operational benign FPR | 1.40% |
| Operational attack recall | 3.20% |
| Operational precision | 90.14% |

The operating point is conservative but misses most attacks. Per-class recall was 3.6% for brute force, 4.0% for DoS, 5.2% for DDoS, and 0% for port scan. This is a material limitation, not a successful operational detection result. Threshold changes must be selected using a training/calibration partition and then evaluated once on untouched test data.

### Probability calibration

A separate training-only group-isolated temperature-scaling run did **not** improve calibration on the held-out partition:

| Metric | Uncalibrated | Temperature-scaled |
|---|---:|---:|
| Expected calibration error | 0.1059 | 0.1331 |
| Brier score | 0.1818 | 0.2408 |
| Log loss | 0.3119 | 0.3872 |

Do not describe the temperature-scaled probabilities as an improvement or enable them as a default on the strength of this run.

## Reproducibility and limits

1. Obtain CIC-IDS2017 from an authorized source and record its exact source URL, license, retrieval date, and file hashes.
2. Prepare the same five-class sample and split; keep the original files and generated artifacts outside Git.
3. Run the project training commands, then `python scripts/evaluate_full_system.py` to generate the full report set.
4. Preserve the generated manifests and report metadata with the run; do not combine results from different model artifacts or report timestamps.

The full multi-agent evaluation suite, all attack families, and cross-dataset transfer to licensed UNSW-NB15 / CSE-CIC-IDS2018 / ToN-IoT / Bot-IoT corpora remain separate validation tasks. Synthetic unit tests do not replace these benchmarks. The public Vercel deployment is a stateless demo: upload, training, and official replay operations are intentionally disabled there; run the private workspace locally for persistent datasets and experiments.
