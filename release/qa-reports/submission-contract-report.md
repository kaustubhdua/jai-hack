# Submission Contract & Schema Compliance Report

> **Historical archive — not current verification.** This file preserves an earlier run and may describe obsolete models, metrics, interfaces, or CSV schemas. Do not use it as current evidence for judging, submission, or presentation claims. Regenerate results from current `main` and authorized organizer data. The current workflow is [docs/evaluation](../../docs/evaluation.md); the current Level 2 contract is [docs/level2-brief](../../docs/level2-brief.md).


**Output Directory:** `outputs/submission/`  
**Files Audited:** `classification.csv`, `policy.csv`, `replay.csv`, `summary.json`, `validation_report.json`  
**Validator:** `cybersentinel.replay.submission.SubmissionValidator`  
**Overall Status:** `READY_FOR_SUBMISSION` (100% Schema & Semantic Integrity)  

---

## 1. Specification Compliance Overview

The Day 2 competition rules mandate three specific CSV files with rigid schemas, strict value constraints, and cross-file referential integrity. CyberSentinel produces and validates all three submission deliverables automatically.

---

## 2. File-by-File Audit Breakdown

### 1. `classification.csv`
* **File Size:** ~5.4 MB
* **Total Rows:** 114,185 (excluding header)
* **Required Header:** `record_id,predicted_class,anomaly score,evidence status`
* **Observed Header:** `record_id,predicted_class,anomaly score,evidence status` (EXACT MATCH)
* **Constraints Checked:**
  - `record_id`: Unique non-empty string/integer for every row. (0 duplicates)
  - `predicted_class`: Exactly in `{"BENIGN", "BRUTE_FORCE", "DOS", "DDOS", "PORT_SCAN"}`. (100% match)
  - `anomaly score`: Numeric float strictly within range `[-1.0, 1.0]`. (100% valid floats, bounded)
  - `evidence status`: Exactly in `{"AGREE", "DISAGREE", "INCOMPLETE"}`. (100% valid)
* **Error Count:** 0

### 2. `policy.csv`
* **File Size:** ~1.3 MB
* **Total Rows:** 20,368 policies (excluding header)
* **Required Header:** `policy_id,activated_after_record_id,scope_type,scope_value,expires_after_record_id,policy_action`
* **Observed Header:** `policy_id,activated_after_record_id,scope_type,scope_value,expires_after_record_id,policy_action` (EXACT MATCH)
* **Constraints Checked:**
  - `policy_id`: Unique identifier format `POL-XXXXX`. (0 duplicate IDs)
  - `activated_after_record_id`: Record index triggering rule creation. (All integer-convertible)
  - `scope_type`: Strictly `"SOURCE_IP"`. (100% compliant)
  - `scope_value`: Valid IPv4 address string. (100% compliant)
  - `expires_after_record_id`: strictly greater than `activated_after_record_id`. (100% verified, window = 150)
  - `policy_action`: Strictly `"BLOCK"`. (100% compliant)
* **Error Count:** 0

### 3. `replay.csv`
* **File Size:** ~3.6 MB
* **Total Rows:** 114,185 records (excluding header)
* **Required Header:** `record_id,action,applied_policy_id`
* **Observed Header:** `record_id,action,applied_policy_id` (EXACT MATCH)
* **Constraints Checked:**
  - `record_id`: Aligned one-to-one with input flows. (0 row count mismatch)
  - `action`: Strictly in `{"ALLOW", "BLOCK"}`.
  - `applied_policy_id` Referential Integrity:
    - If `action == "ALLOW"`, `applied_policy_id` must be empty `""`. (Verified: 37,498 rows, 0 non-empty)
    - If `action == "BLOCK"`, `applied_policy_id` must match a valid `policy_id` in `policy.csv`. (Verified: 76,687 rows, 0 orphan IDs)
* **Error Count:** 0

---

## 3. Machine-Generated Validation Summary (`validation_report.json`)

```json
{
  "all_valid": true,
  "status": "READY_FOR_SUBMISSION",
  "classification": {
    "file": "classification.csv",
    "valid": true,
    "row_count": 114185,
    "errors": [],
    "total_errors": 0
  },
  "policy": {
    "file": "policy.csv",
    "valid": true,
    "policy_count": 20368,
    "errors": [],
    "total_errors": 0
  },
  "replay": {
    "file": "replay.csv",
    "valid": true,
    "row_count": 114185,
    "allow_count": 37498,
    "block_count": 76687,
    "errors": [],
    "total_errors": 0
  }
}
```

**Conclusion:** All generated competition artifacts comply strictly with the hackathon submission format and pass automated verification without warnings or exceptions.

