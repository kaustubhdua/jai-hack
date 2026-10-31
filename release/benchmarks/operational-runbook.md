# CyberSentinel — Current Presentation and Submission Runbook

**Status:** Use this runbook with the current `main` code and locally prepared organizer data. No model artifacts, challenge rows, completed submission files, or organizer receipt are shipped in Git.

## Submission-contract gate

The supplied Day 2 handout and the later downloaded stage-page templates describe different CSV names and headers. Before creating or uploading a bundle, compare the organizer's current templates with the hashes and headers in [the hidden-input audit](hidden-input-audit.md) and the contract documented in [Level 2 brief](../../docs/level2-brief.md). The repository currently implements the later stage-page templates. If the current organizer/API contract does not match those templates, stop and update the generator and validator to the organizer's confirmed contract. Never mix the two schemas.

## Before the panel

1. Check out the latest `main` and confirm the commit that will be presented.
2. Obtain the authorized training and hidden replay packs from the organizers; do not add them to Git.
3. Prepare the local files and verify the supplied pack hashes:
   ```bash
   python scripts/prepare_challenge_data.py \
     --training-pack cyber-pack.zip \
     --hidden-pack cyber-hidden.zip
   ```
4. Install dependencies and train the models from the authorized training partition:
   ```bash
   python -m pip install -e ".[dev,ml]"
   python scripts/train_models.py --train data/raw/training/flows.parquet
   ```
   The supported workflow uses a training-only holdout for A1 temperature calibration and fits A2 on benign training rows. It does not read hidden labels or tune from the held-out evaluation partition.
5. Generate and validate the complete hidden replay bundle:
   ```bash
   python scripts/generate_submissions.py \
     --input data/processed/hidden_replay_input.csv \
     --output-dir outputs/submission
   python scripts/validate_submissions.py \
     --input data/processed/hidden_replay_input.csv \
     --output-dir outputs/submission
   ```
   A limited replay is a smoke test only. A local pass does not establish organizer acceptance.
6. Start the API and frontend using the current [README setup instructions](../../README.md). Confirm diagnostics report the actual data and model availability before claiming a model-backed demo.

## Five-minute walkthrough

### 00:00–00:40 — Problem and boundaries

Describe CyberSentinel as an offline network-flow replay system. The UI topology is an illustrative architecture view, not live network telemetry. No packet capture, active scanning, exploitation, or real firewall control is performed.

### 00:40–01:30 — Five agents

- **A1:** supervised prediction across BENIGN, BRUTE_FORCE, DOS, DDOS, and PORT_SCAN.
- **A2:** independent anomaly detection trained on benign flows. Its 0–1 anomaly index is not a probability.
- **A3:** evidence fusion with AGREE, CONFLICT, or UNCERTAIN status.
- **A4:** chronological correlation using observed endpoints and replay metadata.
- **A5:** temporary simulated policies with explicit activation and expiry.

The combined trainer temperature-calibrates A1 confidence using a holdout drawn only from training data by default. It is uncalibrated if that calibration is disabled. Do not call the anomaly index a probability.

### 01:30–03:10 — Show a real replay

Use only results produced by the current code and authorized local inputs. Point out that A1/A2 classifications are retained for every record, even when an earlier policy blocks a later record. A newly created policy never blocks its triggering record. If models or data are unavailable, show the explicit unavailable state or a clearly labelled fixture; do not imply it is a real result.

### 03:10–04:20 — Show the submission bundle

Under the currently documented stage-page contract, the files are:

- `classification.csv`: `record_id,predicted_class,anomaly_score,evidence_status`
- `replay.csv`: `record_id,action,active_policy_id`; ALLOW uses `NONE`
- `policies.csv`: `policy_id,activated_after_record_id,scope_type,scope_value,expires_after_record_id`

The hidden replay has 200 unlabelled records. Do not report hidden-set accuracy, macro-F1, attack recall, false-block rate, or containment from it. Report labelled evaluation metrics only from the separate permitted labelled evaluation data, with the documented overlap caveat.

### 04:20–05:00 — Limitations and acceptance

Explain that local validation checks schema and replay semantics; it is not an organizer upload receipt. Claim successful submission only after receiving and retaining the organizer's actual successful response.

## Likely judge questions

**Why classify records that are later blocked?** The organizer requires one classification result for every input record. The replay action is a separate, chronological policy decision.

**Can a new policy block the flow that triggered it?** No. Policies activate after their trigger record and apply only to later matching records within the active window.

**Does the hidden set establish model accuracy?** No. It has no ground-truth labels. It can be used for the prescribed replay and schema validation, not labelled performance claims.

**Are endpoint identities invented from flow features?** No. The Level 2 replay uses only literal observed source/destination endpoints. Missing or invalid endpoints remain unknown and cannot be used to create a matching scope.

**Does CyberSentinel change a real firewall?** No. ALLOW/BLOCK decisions and policies are simulated in the offline application.

**What do the AI agents contribute?** A1 and A2 produce independent learned signals; A3 combines evidence; A4 tracks chronological patterns; A5 manages simulated forward-only policy state. The three deterministic agents are not separately trained ML models.
