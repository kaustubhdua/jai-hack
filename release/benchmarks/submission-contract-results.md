# CyberSentinel — Official Level 2 Submission Contract

**Source of truth:** the organizer-provided CSV templates supplied with the hidden replay set. The files are header-only templates; the replay generator must populate them without changing their exact columns or order.

## 1. classification.csv

Exact columns:

`record_id,predicted_class,anomaly_score,evidence_status`

- Exactly one row for every hidden input record, in the same order.
- `predicted_class` must be one of BENIGN, BRUTE_FORCE, DOS, DDOS, PORT_SCAN.
- `anomaly_score` must be finite and within [0,1]; higher means more anomalous. It is a bounded index, not a probability.
- `evidence_status` must be AGREE, CONFLICT, or UNCERTAIN.
- Do not include hidden ground-truth labels.

## 2. replay.csv

Exact columns:

`record_id,action,active_policy_id`

- Exactly one row per hidden input record, in original `seq` order.
- `action` is ALLOW or BLOCK.
- ALLOW must use `active_policy_id=NONE` and must not have a matching active policy.
- BLOCK must reference the lexicographically smallest matching active `policy_id`.

## 3. policies.csv

Exact columns:

`policy_id,activated_after_record_id,scope_type,scope_value,expires_after_record_id`

- Zero or more rows; no fixed policy row count.
- `policy_id` is unique.
- `scope_type` is SOURCE_IP, DESTINATION_IP, or SRC_DST_PAIR.
- `scope_value` must match literal observed endpoint metadata on the policy's activation record. Pair format is `source_ip|destination_ip`.
- A policy becomes active on the record after `activated_after_record_id` and remains active through `expires_after_record_id`, inclusive.
- Each row represents a simulated BLOCK policy. The organizer template has no `policy_action` column.

## 4. Independent validation

The validator checks exact headers, exact record coverage/order, five-class predictions, finite [0,1] anomaly scores, evidence statuses, unique policy IDs, observed endpoint scope values, activation-exclusive/expiry-inclusive windows, ALLOW/NONE behavior, BLOCK references, and the lexicographically smallest matching policy tie-break.

A local validator pass does not prove organizer acceptance. Only an actual successful organizer response or receipt establishes acceptance. The supplied materials do not include API credentials or an upload receipt.
