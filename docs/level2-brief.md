# CyberSentinel — Level 2 Architecture and Submission Contract

## Organizer input

The Level 2 hidden input contains exactly 200 unlabelled records in organizer order. Each row has a unique `record_id`, 1-based `seq`, literal `source_ip` and `destination_ip`, ports, protocol, `day`, `time_offset`, and 78 numeric flow features. There is no hidden label column. Never infer or add ground-truth labels.

## Five-agent data path

1. **A1 — Threat Detection:** five-class supervised prediction for every hidden record.
2. **A2 — Anomaly Analysis:** BENIGN-only Isolation Forest baseline; emits a bounded anomaly index in [0,1], with higher values meaning more anomalous. It is not a probability.
3. **A3 — Evidence Fusion:** combines A1/A2 outputs into `AGREE`, `CONFLICT`, or `UNCERTAIN` and preserves one classification row per hidden record.
4. **A4 — Temporal Correlation:** consumes only observed source/destination endpoints and organizer `day` + `time_offset`; no fingerprint-derived or synthetic IP identities are permitted.
5. **A5 — Adaptive Defense:** checks already-active policies before A4 correlation/policy updates. It creates forward-only simulated policies from analyzed records; a policy never blocks its own trigger record.

A1/A2 predictions are generated for all records because the organizer requires one classification row per record, including records later blocked. The sequential replay gate then checks A5's active policies. A pre-filtered record is BLOCKed and does not enter A4/A5 state updates. An allowed record proceeds through A3/A4 and may create a policy for later records.

## Submission schema source of truth

The later Day 2 stage-page screenshots and the three downloaded header templates supplied for this replay are the schema used by this implementation. They differ from the earlier Track 1 Day 2 handout, which listed `policy.csv` with a `policy_action` column and described an empty `applied_policy_id` for ALLOW. For this hidden replay, follow the actual stage-page files: `policies.csv` with five columns, `active_policy_id` in `replay.csv`, and the literal `NONE` ALLOW sentinel. Do not mix the two contracts.

## Exact organizer CSV templates

### classification.csv

`record_id,predicted_class,anomaly_score,evidence_status`

- Exactly 200 rows, one per hidden record, in exact `seq` order.
- `predicted_class`: `BENIGN`, `BRUTE_FORCE`, `DOS`, `DDOS`, or `PORT_SCAN`.
- `anomaly_score`: finite numeric value in [0,1], higher means more anomalous; not a probability.
- `evidence_status`: `AGREE`, `CONFLICT`, or `UNCERTAIN`.

### replay.csv

`record_id,action,active_policy_id`

- Exactly 200 rows, one per hidden record, in exact `seq` order.
- `action` is `ALLOW` or `BLOCK`.
- `ALLOW` must use `active_policy_id=NONE` and is invalid if any active policy matches the flow.
- `BLOCK` must reference the lexicographically smallest matching active `policy_id`.

### policies.csv

`policy_id,activated_after_record_id,scope_type,scope_value,expires_after_record_id`

- Zero or more rows; no fixed policy row count.
- `policy_id` values are unique.
- `scope_type` is `SOURCE_IP`, `DESTINATION_IP`, or `SRC_DST_PAIR`.
- Scope values must be exact literal observed endpoint values. Pair format is `source_ip|destination_ip`. No wildcards, CIDR ranges, hashes, or synthetic identities.
- A policy activates on the record after `activated_after_record_id` and remains active through `expires_after_record_id`, inclusive.
- Each policy row represents a simulated BLOCK policy; the organizer template has no `policy_action` column.

## Local workflow

Install the exact supplied packs into ignored local paths and verify the training/evaluation partition hashes:

```bash
python scripts/prepare_challenge_data.py \
  --training-pack cyber-pack.zip \
  --hidden-pack cyber-hidden.zip

pip install -e ".[dev,ml]"

# Train A1 and A2 from the authorized training partition only.
python scripts/train_models.py \
  --train data/raw/training/flows.parquet

# If a separate labelled validation partition is explicitly provided by the organizers,
# pass it with --validation. Do not use the hidden records for training/calibration.
# Do not repurpose the held-out evaluation partition as a tuning set.

python scripts/generate_submissions.py \
  --input data/processed/hidden_replay_input.csv \
  --output-dir outputs/submission

python scripts/validate_submissions.py \
  --input data/processed/hidden_replay_input.csv \
  --output-dir outputs/submission
```

A limited replay is a smoke test only. A successful local validator pass proves contract consistency, not organizer acceptance. Only an actual organizer upload receipt proves acceptance. The system is an offline simulated replay; it does not modify a host firewall or inspect live traffic.
