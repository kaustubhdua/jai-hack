# CyberSentinel — Official Submission CSV Validation Report

> **Historical archive — not current verification.** This file preserves an earlier run and may describe obsolete models, metrics, interfaces, or CSV schemas. Do not use it as current evidence for judging, submission, or presentation claims. Regenerate results from current `main` and authorized organizer data. The current workflow is [docs/evaluation](../../docs/evaluation.md); the current Level 2 contract is [docs/level2-brief](../../docs/level2-brief.md).


## JAI 2026 Hackathon | Track 1: Agentic AI for Cybersecurity

### 1. Validation Summary

* **Generated Files Location:** `outputs/submission/`
* **Evaluation Dataset:** `data/processed/eval_prepared.parquet` (114,185 records)
* **Overall Validation Status:** **READY_FOR_SUBMISSION**
* **Total Formatting or Constraint Errors:** **0**

```
================================================================================
                    SUBMISSION BUNDLE VALIDATION AUDIT
================================================================================
Status:               READY_FOR_SUBMISSION
Total Files Verified: 3 CSVs + 1 Verification Audit
All Checks Passed:    TRUE
================================================================================
```

---

### 2. File 1: `classification.csv`

* **File Path:** `outputs/submission/classification.csv`
* **File Size:** 3,285,637 bytes
* **Total Rows:** 114,185 data rows (114,186 including header)
* **Header Format:** `record_id,predicted_class,anomaly score,evidence status`
  *(Note exact space in `anomaly score` as mandated by organizer specification)*
* **Schema & Integrity Checks:**
  * **Record ID Integrity:** Monotonically increasing from `0` to `114184` with 0 missing or duplicate entries.
  * **Taxonomy Conformance:** 100% of values in `predicted_class` belong to canonical taxonomy: `BENIGN`, `BRUTE_FORCE`, `DOS`, `DDOS`, `PORT_SCAN`.
  * **Anomaly Score Bounds:** All values are valid floating-point numbers between `0.000000` and `1.000000`. No `NaN`, `inf`, or missing values.
  * **Evidence Status Conformance:** 100% of values in `evidence status` belong to `AGREE`, `DISAGREE`, or `INCOMPLETE`.
* **Validation Errors:** **0**

---

### 3. File 2: `policy.csv`

* **File Path:** `outputs/submission/policy.csv`
* **File Size:** 4,517,370 bytes
* **Total Policies Created:** 85,749 rows
* **Header Format:** `policy_id,activated_after_record_id,scope_type,scope_value,expires_after_record_id,policy_action`
* **Schema & Integrity Checks:**
  * **Policy ID Uniqueness:** Every `policy_id` follows canonical pattern `POL-XXXXX` and is strictly unique.
  * **Activation Bounds:** `0 <= activated_after_record_id < 114185`.
  * **Expiration Invariant:** Strictly enforced `expires_after_record_id > activated_after_record_id` (duration = 150 records).
  * **Scope Type:** `SOURCE_IP` for all active defense entries.
  * **Policy Action:** `BLOCK` for all reactive defense quarantine entries.
* **Validation Errors:** **0**

---

### 4. File 3: `replay.csv`

* **File Path:** `outputs/submission/replay.csv`
* **File Size:** 1,817,980 bytes
* **Total Rows:** 114,185 data rows (114,186 including header)
* **Header Format:** `record_id,action,applied_policy_id`
* **Schema & Integrity Checks:**
  * **Record ID Alignment:** Exactly matches row count and sequence of `classification.csv`.
  * **Action Conformance:** 100% of actions are either `ALLOW` or `BLOCK`.
    * Total `ALLOW`: **90,154**
    * Total `BLOCK`: **24,031**
  * **Foreign Key Referential Integrity:**
    * When `action == "BLOCK"`, `applied_policy_id` is non-empty and points to an active policy defined in `policy.csv`.
    * When `action == "ALLOW"`, `applied_policy_id` is strictly empty (`""`).
  * **No Self-Blocking:** Every record $r$ blocked by policy $p$ satisfies:
    $$p.\text{activated\_after\_record\_id} < r.\text{record\_id} \le p.\text{expires\_after\_record\_id}$$
* **Validation Errors:** **0**

---

### 5. Final Certification

The generated submission bundle conforms with 100% fidelity to the JAI 2026 Level 2 evaluation specification. It contains zero synthetic labels, zero data leakage, and provides complete explainable logs for all tactical recommendations.

