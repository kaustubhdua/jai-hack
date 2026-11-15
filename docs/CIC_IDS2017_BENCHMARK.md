# CIC-IDS2017 real-data benchmark

**Run status:** the complete nine-report multi-agent evaluation finished on 2026-11-15. Twelve PNG/SVG publication artifacts were regenerated successfully after fixing the plot/report schema mismatch. This is a reproducible *five-class sample evaluation*, not a full-corpus benchmark or cross-dataset validation.

## Dataset and provenance

- Dataset mirror used in the prepared workspace: `bvsam/cic-ids-2017` on Hugging Face.
- Upstream dataset: Canadian Institute for Cybersecurity (CIC) IDS 2017.
- The mirror's dataset card did not declare a reuse license when checked. Confirm the original UNB/CIC terms before redistribution or commercial use. Do not redistribute source rows or artifacts until the license is confirmed.
- Canonical classes: `BENIGN`, `BRUTE_FORCE`, `DOS`, `DDOS`, `PORT_SCAN`.
- Prepared evaluation partition: 2,500 flows (500 per class). Prepared training partition: 10,000 flows. The prepared files are not committed to the repository.
- Deterministic sampling/split used seed 42; the evaluation runner validates the five expected classes and records dataset/model hashes.
- Excluded source families include Bot, Infiltration, Web Attack XSS/SQL Injection, Heartbleed, and other CIC-IDS2017 labels not mapped into these five canonical classes. Do not claim coverage of every CIC-IDS2017 attack family.

### Reproducibility identifiers

Full evaluation ran on commit `72689da43095ea6589e45c8286f15f73e2bb525b`, evaluator `2.0.0-cybersentinel-ml-evaluation`, seed `42`, at `2026-11-15T20:40:11Z`. The full runner completed in 511.02 seconds.

| Artifact | SHA-256 |
|---|---|
| `eval_prepared.parquet` | `aa9d3c27c9e743c37e41406156dd0d98cad0e596bc558d89f75c1abc24250c09` |
| `training_prepared.parquet` | `6a58e1d09fcd5146be5336b139f5a0bc0fdcf504f95035d4fb40d71581856f3e` |
| Threat detector model | `3f419b27dcee2250284c65f1014a7b00d953bdd775304e9f7ce6df1981b51bc2` |
| Anomaly detector model | `42c395dad43b4dbdfda961120767ef3e4cca28345913ae756965cf3f2d21db09` |

These hashes identify the prepared files and models used for this run; they do not independently establish the upstream source license or provenance of every raw source file.

## Held-out results

### Agent 1 — supervised classifier

| Metric | Result |
|---|---:|
| Evaluation flows | 2,500 |
| Accuracy | 83.00% |
| Balanced accuracy | 83.00% |
| Macro-F1 | 79.23% |
| Benign false-positive rate | 0.00% |
| Attack detection rate | 79.25% |

Class-level weakness is material: brute-force recall was 15.4%, despite near-perfect recall for DoS, DDoS and port scan. Overall accuracy therefore hides an uneven class profile.

### Agent 3 — evidence fusion

| Metric | Result |
|---|---:|
| Fusion outputs missing/incomplete | 0 |
| A1 accuracy | 83.00% |
| A3 accuracy | 83.00% |
| Class prediction overrides | 0 |

Fusion did not improve the classifier's class predictions on this partition. Its simulated action policy produced 610 ALLOW, 1,556 REVIEW, and 334 BLOCK decisions. It produced zero false BLOCK decisions on the 500 benign flows and five benign REVIEW decisions. These are offline policy-simulation outputs; the application does not apply firewall rules or block live traffic.

### Agent 2 — Isolation Forest anomaly detector

| Metric | Result |
|---|---:|
| ROC-AUC | 0.8310 |
| Average precision | 0.9399 |
| Operational benign FPR | 1.00% |
| Operational attack recall | 16.70% |
| Operational precision | 98.53% |
| Operational F1 | 28.56% |

Per-class anomaly recall: brute force 0%, DoS 38.0%, DDoS 28.8%, port scan 0%. High precision at this operating threshold comes with very low recall. This is not adequate evidence for autonomous blocking or production SOC use. Thresholds need to be selected on a dedicated training/calibration partition and then evaluated once on untouched test data.

### Generalization and leave-one-attack-out

- Exact feature-vector overlap with training was 55/2,500 (2.2%); 2,445/2,500 (97.8%) were unseen exact feature vectors.
- On the unseen-vector subset, classifier accuracy was 82.62%, balanced accuracy 81.92%, and attack detection rate 78.77%. This is not the same as generalization to a new dataset, network, organization, or attack family.
- Four leave-one-attack-out trials reported mean unseen-attack detection of 15.90%, mean anomaly recall of 3.25%, and mean simulated containment of 60.35%. Zero-day generalization remains weak.

### Temporal correlation

- 2,500 flows processed; zero model-prediction errors.
- 1,580 flows were correlated; measured correlated-flow precision was 100% and benign false-correlation rate was 0% on this sample.
- Mean delay across detected contiguous ground-truth label runs was 27 flows.
- Campaign-level precision/recall is **not available**: the partition has no independently verified campaign IDs. The reported flow precision is not campaign precision.

### Agent 5 — adaptive defense simulation

The full five-agent configuration reported 91.35% simulated containment, 0% false blocking, and 100% benign preservation on this held-out sample. These results are policy simulation, not live packet enforcement or a guarantee against real attacks. They should not be used to claim production protection.

### Probability calibration

Training-only temperature scaling did **not** improve held-out calibration:

| Metric | Uncalibrated | Temperature-scaled |
|---|---:|---:|
| Expected calibration error | 0.105939 | 0.133083 |
| Brier score | 0.181757 | 0.240788 |

Do not describe the calibrator as an improvement or enable it as a default based on this run.

## Reports and plots

The full runner writes nine JSON reports: summary, classification, fusion, anomaly, generalization, LOAO, calibration, temporal correlation, and adaptive defense. Publication plotting now supports the actual saved report schemas and successfully generates 12 artifacts (six charts in PNG and SVG): confusion matrix comparison, anomaly ROC/PR curves, calibration reliability diagram, seen/unseen generalization, LOAO comparison, and adaptive-defense comparison.

Run locally with the prepared licensed dataset and trained model artifacts:

```bash
python scripts/evaluate_full_system.py
```

Do not compare reports unless their dataset hashes, model hashes, evaluator version, and run metadata match.

## Remaining validation gates

1. Confirm and record the upstream CIC-IDS2017 license and raw-file hashes before sharing data or claiming reproducible source provenance.
2. Repeat on the complete authorized CIC-IDS2017 corpus, including excluded attack families, with a documented family-to-label mapping.
3. Run independently prepared, licensed UNSW-NB15, CSE-CIC-IDS2018, ToN-IoT and Bot-IoT datasets. Cross-dataset transfer is not yet demonstrated.
4. Revisit the very low brute-force and anomaly/zero-day recall before making any operational security claim.
5. Perform public production URL/API smoke tests after the latest deployment reaches READY. The public Vercel deployment is a stateless demo: uploads, training, and official replay are intentionally disabled there. Use the local API for private persistent datasets and experiments.

Synthetic unit tests are valuable for correctness but do not replace these benchmark and deployment checks.
