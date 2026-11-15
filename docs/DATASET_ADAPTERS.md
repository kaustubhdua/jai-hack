# Dataset adapter contracts

The adapter layer in `src/cybersentinel/data/adapters.py` is deliberately
conservative. It normalizes known aliases while retaining source labels and
the immutable original file. Every import manifest includes the source path,
format, dataset family, source SHA-256, row count, source columns, rename map,
and warnings.

## Current dataset families

| Family | Label priority | Common normalized features |
|---|---|---|
| CIC-IDS2017 | `Label` | Flow Duration, Protocol, ports, packet/byte totals and rates |
| CSE-CIC-IDS2018 | `Label` | CIC-compatible flow fields |
| UNSW-NB15 | `attack_cat`, then `label` | `dur`, `proto`, `sport`, `dsport`, `spkts`, `dpkts`, `sbytes`, `dbytes` |
| ToN-IoT | `type`, then `label` | timestamp, endpoints, protocol, ports and byte counters |
| Bot-IoT | `category`, `subcategory`, then `label` | protocol, ports, duration and byte/packet counters |
| CICIoT2023 | `label`, then `attack` | common flow and IoT telemetry fields |
| Generic | `label`, `class`, `attack`, `category`, `target` | numeric columns only unless explicitly selected |

## Unit and category rules

- Canonical `flow_duration` is seconds. CIC-IDS2017/CSE-CIC-IDS2018
  `Flow Duration` values are converted from microseconds to seconds.
- UNSW-NB15 `dur` and generic duration aliases are assumed to be seconds.
  Verify the provider's schema before using a generic adapter.
- `protocol` is converted to standard numeric identifiers for TCP (6), UDP
  (17), ICMP (1), and ICMPv6 (58). Other unrecognized protocol strings become
  missing values; no arbitrary category encoding is performed.
- Port, packet, byte, and rate aliases are coerced to numeric values.
- Labels are trimmed but never rewritten into a shared taxonomy by the adapter.
  Supply an explicit mapping in the experiment configuration.
- IP addresses, timestamps, record identifiers, and label columns are not
  automatically selected as numeric model features.

## Cross-dataset requirements

Identical names do not guarantee identical semantics. Before training for
transfer evaluation, choose an explicit feature allow-list whose meaning and
units match across both datasets. Review missingness and drift diagnostics.
Do not compare results across mismatched label taxonomies or silently drop
classes that exist only in the target dataset.

## Adding another adapter

1. Add a dataset profile with authoritative label-column priority.
2. Add only aliases whose semantics and units are known.
3. Add unit conversion only when the provider schema explicitly documents it.
4. Preserve the original source file and include every conversion in tests.
5. Add small synthetic fixtures; do not commit the original dataset.
6. Record provider URL, licence, retrieval date, and source checksum in the
   dataset manifest or experiment notes.


## Label precedence and leakage protection

For UNSW-NB15, `attack_cat` is the preferred multiclass target when both
`attack_cat` and the binary `label` field are present. The original binary
field is retained as `source_label` for auditability, but it is excluded from
automatic feature selection. Explicit feature allow-lists also reject known
label-like columns to reduce accidental target leakage. If binary classification
is desired instead, prepare/select the intended target explicitly and document
the mapping in the experiment configuration.

Cross-dataset reports distinguish unknown target labels from training classes
that simply do not occur in the target sample. Missing class coverage alone is
not reported as feature-domain shift; feature drift remains a descriptive
distribution diagnostic, not a substitute for labelled performance metrics.
