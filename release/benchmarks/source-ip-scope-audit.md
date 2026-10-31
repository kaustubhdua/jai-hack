# CyberSentinel — Observed Endpoint Scope Audit

**Current release rule:** Agent 4 and Agent 5 use only literal endpoint values present in the original replay row. Missing or invalid endpoints remain unknown. The system never fabricates an IP address from flow fingerprints.

## Organizer hidden input

The supplied 200-row hidden replay input contains native `source_ip` and `destination_ip` fields, alongside `record_id`, `seq`, protocol, ports, `day`, and `time_offset`. These observed endpoints are available to correlation and policy replay.

The CICIDS2017 training/evaluation feature partitions are feature matrices and do not supply native Layer-3 endpoints. Model training and endpoint-aware hidden replay are separate concerns.

## Scope rules

- `SOURCE_IP`: a normalized literal IP from the current row's `source_ip` field.
- `DESTINATION_IP`: a normalized literal IP from the current row's `destination_ip` field.
- `SRC_DST_PAIR`: the normalized literal source and destination joined as `source|destination`.
- If a required endpoint is absent, malformed, or non-literal, the corresponding scope cannot be created or matched.
- TCP fingerprint fields such as `Init_Win_bytes_forward`, `min_seg_size_forward`, and `Fwd Header Length` are never converted into IP addresses.

## Policy and validator rules

A policy's scope must match the literal endpoint(s) on its activation/trigger record. A policy becomes active on the next record and remains active through its expiry record, inclusive. For each replay record, validators recompute all matching active policies from the original input. A BLOCK must reference the lexicographically smallest matching `policy_id`. An ALLOW must use `active_policy_id=NONE` and is invalid if any active policy matches.

## Limitations

- If a replay input omits native endpoints, endpoint correlation and endpoint-scoped policy generation are unavailable for those records.
- No pseudo-IP, hash-derived identity, or fingerprint-derived endpoint is permitted in the official submission.
- The hidden input is unlabelled, so false-block rates and attack containment cannot be measured from the hidden replay itself.
- ALLOW/BLOCK outcomes are simulated offline replay actions; no live firewall enforcement is performed.
