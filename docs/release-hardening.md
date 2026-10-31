# Release Hardening — Current Contract

## Data and provenance
- Organizer training/evaluation Parquet partitions are installed locally only after byte-count and SHA-256 verification against `cyber-pack.zip/manifest.json`.
- The separate hidden archive supplies 200 unlabelled records with IDs F000001–F000200, exact 1-based `seq`, 78 finite numeric features, literal source/destination IPs, ports, protocol, day and time offset.
- Hidden records are never used for training, calibration, or threshold selection.
- CICIDS2017 training/evaluation feature partitions do not supply native endpoints. The hidden replay's endpoint metadata is separate and is used as observed input. No IP is synthesized from TCP fingerprints.

## Model artifact workflow
- `scripts/train_models.py` trains A1 from all five canonical training classes and A2 from BENIGN training rows only.
- Both artifacts are reloaded after training; feature schema, class set, training provenance and SHA-256 hashes are recorded.
- By default, a deterministic stratified 15% holdout is carved from the authorized training partition for A1 temperature calibration. A2 is fitted on BENIGN rows only and derives its default threshold from benign training scores; label-based threshold tuning requires an explicitly permitted external labelled validation file and an opt-in flag. The held-out evaluation partition and hidden records are never used for fitting or calibration.
- The labelled evaluation partition is reserved for final evaluation and is not used for fitting or calibration.

## Replay and CSV contract
- A1/A2 outputs and A3 evidence are retained for every hidden row because `classification.csv` requires complete coverage.
- Existing A5 policies are checked before an allowed row enters A4 correlation or A5 policy updates. Blocked rows do not update temporal or defense state.
- Policy activation is exclusive; expiry is inclusive. A policy cannot block its trigger record.
- `classification.csv`: `record_id,predicted_class,anomaly_score,evidence_status`.
- `replay.csv`: `record_id,action,active_policy_id`; ALLOW uses `NONE`; BLOCK uses the lexicographically smallest matching active policy ID.
- `policies.csv`: `policy_id,activated_after_record_id,scope_type,scope_value,expires_after_record_id`. The ledger has no `policy_action` column and may have zero or more rows.
- Policy scopes are literal `SOURCE_IP`, `DESTINATION_IP`, or `SRC_DST_PAIR` values from the policy's trigger record. No wildcard, CIDR, hash, or synthetic identity is allowed.

## UI truthfulness
- Flow Inspector has no preloaded synthetic attack records and shows only the actual Agent 2 evidence payload returned by the backend; heuristic feature-impact bars were removed.
- Fusion Studio is explicitly a manual what-if simulator, not a model prediction or observed flow.
- 3D topology and particle animation are explicitly illustrative and not live network telemetry.
- Static/unverified latency claims were removed. Latency is displayed only when measured from a request/replay.

## Verification boundary
- GitHub Actions verifies the Python tests and frontend type-check/build.
- CI does not prove the organizer data can be parsed in a separate local environment, model training has been run on the supplied archives, or the hidden submission has been generated.
- A local CSV validator pass is not organizer acceptance. Only an organizer upload receipt proves acceptance.
- All defense policies and ALLOW/BLOCK actions are simulated offline; no host firewall or live network is modified.
