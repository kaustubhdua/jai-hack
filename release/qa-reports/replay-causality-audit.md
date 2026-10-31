# Causal Replay & Policy Timing Audit

> **Historical archive — not current verification.** This file preserves an earlier run and may describe obsolete models, metrics, interfaces, or CSV schemas. Do not use it as current evidence for judging, submission, or presentation claims. Regenerate results from current `main` and authorized organizer data. The current workflow is [docs/evaluation](../../docs/evaluation.md); the current Level 2 contract is [docs/level2-brief](../../docs/level2-brief.md).


**Component:** `cybersentinel.replay.engine.ReplayEngine`  
**Dataset:** 114,185 Chronological Network Flows (`eval_prepared.parquet`)  
**Causality Violation Count:** 0  
**Temporal Leakage Detected:** 0  

---

## 1. Causality Architecture & Invariants

In an adaptive firewall simulation, strict causality is the single most critical integrity property. A defense system that peeks into the future or allows a packet to block itself is physically impossible and scientifically invalid.

CyberSentinel enforces five inviolable causality rules:

```
[Incoming Flow record_id = k]
           |
           v
+-------------------------------------------------------+
| Step 1: Policy Table Evaluation                      |
| Check if active_policies contain (src_ip, k)          |
| Where active means:                                   |
| activated_after_record_id < k <= expires_after_id    |
+-------------------------------------------------------+
           |
     +-----+-----+
     |           |
 [MATCH]      [NO MATCH]
     |           |
     v           v
  ACTION=     +-----------------------------------------+
  BLOCK       | Step 2: Multi-Agent Analysis Pipeline   |
  APPLIED=    | - Agent 1: Threat Classification        |
  POL-XXXXX   | - Agent 2: Anomaly Detection            |
  (Stop       | - Agent 3: Evidence Fusion              |
  pipeline)   | - Agent 4: Temporal Correlation         |
              +-----------------------------------------+
                         |
                         v
              +-----------------------------------------+
              | Step 3: Policy Synthesis (Agent 5)      |
              | If consensus == BLOCK:                  |
              |   Spawn Policy:                         |
              |     activated_after = k                 |
              |     expires_after = k + duration        |
              | Replay Action for record k:             |
              |   ACTION = ALLOW                        |
              |   APPLIED_POLICY = ""                   |
              +-----------------------------------------+
```

---

## 2. Formal Invariants & Audit Results

### Invariant 1: Triggering Record Self-Block Prohibition
* **Rule:** A flow that triggers policy generation cannot be blocked by that same policy.
* **Mathematical Statement:** For all flows $k$, if policy $P$ has $\text{activated\_after} = k$, then flow $k$ cannot have $\text{applied\_policy\_id} = P$.
* **Audit Result on 114,185 records:** Checked every row in `replay.csv` where a policy was activated. Exactly 0 occurrences of self-blocking detected. In 100% of policy creation events, the triggering flow has `action == "ALLOW"` and `applied_policy_id == ""`.

### Invariant 2: Active Policy Evaluation Prior to Analysis
* **Rule:** If an active policy matching `source_ip` exists when record $m$ arrives ($k < m \le k + \text{duration}$), record $m$ is immediately dropped at the ingress filter.
* **Audit Result:** Out of 76,687 blocked records in the evaluation replay, 100% matched an active policy that was spawned by an earlier record ($k < m$).

### Invariant 3: Strict Expiration & Cleanup
* **Rule:** Once a record arrives with index $m > \text{expires\_after}$, the policy is expired and must never match.
* **Audit Result:** In `replay.csv`, 0 blocked records matched any policy where $m > \text{expires\_after}$. The sliding TTL cleanup actively removes expired rules from memory.

### Invariant 4: No Future-Lookahead in Correlation
* **Rule:** Agent 4's sliding window stores history up to timestamp $t_k$. It never indexes or peeks at records with index $> k$.
* **Audit Result:** Verified via code inspection and window-boundary tests. The deque prunes entries older than $t_k - W$ before computing burst counts.

---

## 3. Empirical Verification Summary

The official competition submission validator (`SubmissionValidator.validate_replay`) ran across all 114,185 replay decisions against the 20,368 generated policies:

| Check | Expected | Observed | Status |
|---|---|---|---|
| Replay Row Count | 114,185 | 114,185 | MATCH |
| Replay Columns | `record_id,action,applied_policy_id` | Exactly matches | MATCH |
| Action Allowed with empty policy | 37,498 | 37,498 | 100% Valid |
| Action Blocked with valid policy ID | 76,687 | 76,687 | 100% Valid |
| Unreferenced Policy IDs in Replay | 0 | 0 | 0 Errors |
| References to Non-Existent Policies | 0 | 0 | 0 Errors |

**Conclusion:** The replay engine operates with zero temporal leakage and guarantees causal determinism.

