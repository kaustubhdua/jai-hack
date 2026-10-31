# Agent 3: Evidence Fusion Policy

Agent 3 combines the independent outputs of Agent 1 and Agent 2 and records the evidence state and rationale. It does not read ground-truth labels.

## Evidence states

| Evidence state | Meaning | Fusion handling |
|---|---|---|
| `AGREE` | The valid A1 and A2 outputs support a consistent interpretation. | Record the combined evidence and rationale. |
| `CONFLICT` | A1 and A2 provide materially different signals. | Preserve both signals and route the case for review. |
| `UNCERTAIN` | One or both outputs are missing, invalid, or unusable. | Fail safely to review; do not invent a prediction. |

The configured fusion implementation owns confidence gates and decision thresholds. Do not copy thresholds into the UI or treat the exported anomaly index as a threshold probability. A2's exported index is bounded to [0,1], with higher values meaning more anomalous; it is not a probability. The underlying A2 anomaly flag is based on its Isolation Forest decision score and stored operating threshold.

## Fusion recommendation versus replay action

Fusion evidence is not the same field as the final replay action:

1. A1 and A2 outputs are produced for each hidden record so the classification file covers every input row.
2. The replay engine checks for a previously activated, still-active matching A5 policy.
3. A matching earlier policy makes that record `BLOCK`; it must reference the lexicographically smallest matching policy ID.
4. Without a matching earlier policy, the replay action is `ALLOW`. A policy created after analyzing this record can affect only later records; it cannot block its own trigger.

Thus a flow can have suspicious or conflicting classification evidence while its current replay action remains ALLOW. All actions and policies are offline simulation; no live network or firewall is changed.

## Organizer evidence values

The current Level 2 stage-page contract uses `AGREE`, `CONFLICT`, and `UNCERTAIN`. See [the documented Level 2 contract](level2-brief.md) and [the downloaded-template audit](../release/benchmarks/hidden-input-audit.md). If the organizer supplies a newer template or API schema, verify it before submission and update both the generator and validator together.

Manual fusion workbench inputs are what-if scenarios. Label them as such; they are not observed network records or measured model outputs.
