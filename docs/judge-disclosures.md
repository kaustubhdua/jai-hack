# Judge-facing limitations and honest demo disclosures

## 1. Endpoint provenance

The CICIDS2017 training and labelled evaluation partitions contain numeric flow features, not native Layer-3 endpoint columns. The organizer's separate 200-row Level 2 hidden input is endpoint-enriched and contains literal `source_ip` and `destination_ip` fields. Agent 4 correlation and Agent 5 policy scopes for the official hidden replay use only those observed values.

Missing or invalid endpoint values remain unknown. The implementation does not derive an IP-shaped identity from TCP fingerprints, hashes, or other synthetic data. A policy is not created for a flow that lacks the observed endpoint required by its scope.

## 2. Evaluation overlap

The dataset audit found 8,161 distinct feature vectors shared by training and evaluation, covering 9,795 evaluation rows (8.58% of the evaluation split). This overlap can make repeated-flow results optimistic. The official evaluation split is not modified to remove the overlap. Disclose the caveat alongside any metric.

## 3. Scores are not automatically probabilities

- **Agent 1:** maximum `predict_proba` output is calibrated using the deterministic training-only holdout by default, or an organizer-provided separate labelled validation file when supplied. The manifest records which source was used.
- **Agent 2:** the exported value is a bounded 0–1 anomaly index (higher means more anomalous), not a probability. Its default operating threshold is derived from the BENIGN training-score distribution. Label-based threshold tuning is disabled by default and requires an explicitly permitted separate labelled validation file plus `--calibrate-anomaly-threshold`; the resulting threshold is still applied to the underlying Isolation Forest decision function.

Report the exact model artifact and calibration provenance used for the run.

## 4. Fixed temporal and policy parameters

- Agent 4 has a 150-record sliding-window cap and a configured 300-second age window when usable timestamps exist.
- Agent 5's default policy duration is 150 replay positions, capped to the number of later records remaining in the current replay.

The replay is chronological and causal. A policy is created after its trigger and may affect only later records; it remains active through its expiry record, inclusive. A1/A2 predictions and A3 evidence are retained for every hidden row to satisfy the classification file contract. The active-policy gate determines replay action before Agent 4 correlation and Agent 5 policy updates.

## 5. Exact organizer submission semantics

- `classification.csv` and `replay.csv` each contain exactly one row per hidden record in original `seq` order.
- `policies.csv` has the exact five-column template and can contain zero or more rows.
- `ALLOW` must use `active_policy_id=NONE` and must not have any matching active policy.
- `BLOCK` must reference the lexicographically smallest matching active `policy_id`.
- A policy activates on the record after `activated_after_record_id` and remains active through `expires_after_record_id`, inclusive.
- Scope values are literal observed IPs or `source_ip|destination_ip`; no wildcards, CIDR, synthetic identities, or extra policy action column.

## 6. Dataset and operating scope

- Model validation is based on CICIDS2017 only.
- The system is an offline flow-replay and simulated-defense platform. It does not inspect live sockets, capture packets, or alter operating-system firewalls.
- Generalization to other datasets, network environments, and live deployments is untested.
- A local validator pass is not organizer acceptance. Only an actual organizer upload receipt proves acceptance.

## Suggested 20-second judge explanation

> “CyberSentinel is a causal offline multi-agent flow-replay system. We train the classifier on the authorized labelled training partition and the anomaly detector on benign training flows only. For the hidden replay we use the organizer's observed source and destination endpoints—never synthetic IPs. Existing policies are checked before temporal correlation and policy updates. The three output files follow the exact organizer templates, and every BLOCK is tied to the lexicographically smallest matching policy active after its trigger and through its inclusive expiry. The hidden set is unlabelled, so we do not report attack/benign performance metrics from it. All defense actions are simulated; no live firewall is changed.”
