# Organizer hidden replay input audit

**Audit date:** 31 October 2026  
**Input:** organizer-provided `cyber-hidden.zip`, member `Cyber/hidden/records.csv`  
**Archive SHA-256:** `b59eaca11c6adf147f41b1e955ff380039c5aa21e65a00daf4d151d9adf20857`  
**Member `Cyber/hidden/records.csv` SHA-256:** `5b1fe3d05113c9a3bb04b27e6ae2c8802057830bea60c92923c81408c369be89`

## Verified input facts

| Check | Result |
|---|---:|
| Records | 200 |
| Columns | 87 |
| Numeric flow features | 78 |
| Record IDs | Unique, exactly `F000001` through `F000200` |
| `seq` | Exactly 1 through 200, in file order |
| Ground-truth label column | Absent |
| Missing cells | 0 |
| Non-finite feature values | 0 |
| Source IPs | All valid IPv4/IPv6 literals |
| Destination IPs | All valid IPv4/IPv6 literals |
| Ports | Numeric integers in [0, 65535] |
| `day` + `time_offset` | Valid, monotonically increasing timestamps |

The hidden archive README explicitly says these are 200 unlabelled flows in official replay order and that the same 78 numeric features as the training pack are present. The nine metadata columns are `record_id`, `seq`, `day`, `time_offset`, `source_ip`, `destination_ip`, `source_port`, `destination_port`, and `protocol`.

## Downloaded stage-page templates

The exact downloaded header-only files have these headers:

- `classification.csv`: `record_id,predicted_class,anomaly_score,evidence_status`
  - SHA-256: `03abd1d58c7fb303a3885b83895635409572f6687fcbbb2884c56943a90b5d45`
- `replay.csv`: `record_id,action,active_policy_id`
  - SHA-256: `52b0172f0f52cd2258af528051f4423fc3d0f323d9b26c3dbae708000fec3fe8`
- `policies.csv`: `policy_id,activated_after_record_id,scope_type,scope_value,expires_after_record_id`
  - SHA-256: `126574bd9ad9d92481d486fc5aa504078dfd1150f13605d6ab88783209826de0`

These templates supersede the earlier Day 2 handout's different filename/header wording for this stage-page upload. ALLOW rows in `replay.csv` use the literal `NONE`; policies are a five-column ledger and have no `policy_action` column. Allowed scope types are `SOURCE_IP`, `DESTINATION_IP`, and `SRC_DST_PAIR`; pair values use the exact `source_ip|destination_ip` strings.

## What this audit does not prove

The hidden set has no labels, so it cannot establish classification accuracy, macro-F1, anomaly recall, containment rate, false-block rate, or benign preservation. The three supplied templates are header-only, not completed submissions. This audit does not train either model, run the five-agent replay, prove all 200 CSV rows, or establish organizer acceptance.

The separate organizer training/evaluation archive (`cyber-pack.zip`) and labelled validation file are not present in the supplied files inspected for this audit. Do not train on the hidden set or claim hidden-set performance. Generate the final bundle only after the authorized training data and model artifacts are available, then validate all three populated CSVs against this exact original hidden input.
