# Day 1 progress questionnaire — current verified status

This working Q&A summarizes what is complete in the repository and what was completed using the organizer files provided locally. It is **not** an official organizer form. Answers below distinguish measured dataset facts from model results that have not yet been produced.

## What data was processed?

### 1. Which files went through preprocessing?

The two Parquet tables supplied for this work: `training/flows.parquet` and `eval/flows.parquet`. Together they contain **570,922 flow records**. These are summaries of network conversations, not raw packet captures or message contents.

### 2. What does one row describe?

One row describes one network flow: measurements such as destination port, duration, packet counts, byte counts, packet timing, and traffic flags, plus the flow's answer in `label`.

### 3. Which columns are used as model input?

There are 78 numeric measurements in the source. The prepared files contain 71 numeric measurements after removing three always-zero columns and four exact duplicate columns. `record_id` is omitted from model input because it gives away label clues. `label` remains in the prepared table as the answer column, not as an input feature.

### 4. What happened to the rows?

No rows were removed. The prepared training file still has 456,737 rows; the prepared eval file still has 114,185 rows, in their original order. Repeated measurement patterns were reported but kept, including those shared between training and eval.

### 5. What values were changed?

The original files had no null or infinite values. A few header-length values were negative, which is impossible for a length. The preprocessor marks those as invalid and fills them using the middle value (median) learned from training. If missing or infinite values appear in a future file, the same code converts them to missing and uses the saved training medians.

### 6. Were training and eval treated the same way?

The training file is used to decide which columns to keep and to calculate fill values and optional scaling settings. Eval receives those exact same decisions and values. Eval is not used to fit preprocessing. All official eval rows are retained; invalid values in them receive the same training-based cleaning as any other row.

### 7. Where are the prepared files?

The generated files are local: `training_prepared.parquet`, `eval_prepared.parquet`, `preprocessing_state.json`, and `dataset_profile.json` under the task's `outputs/prepared/` folder. The code in GitHub writes equivalent generated files to `data/processed/`, which is git-ignored. No challenge rows or fitted values were uploaded.

## Questions and answers

### 1. What is the project and challenge scope?

CyberSentinel is for JAI 2026 Track 1, Agentic AI for Cybersecurity. The prototype is for offline network-flow analysis and replay. It does not perform live attacks, packet sniffing, or real firewall changes; policy actions are simulated.

### 2. What is the assigned workstream covered here?

Member 1 — Data Engineering & Dataset Intelligence: inspect the official files, identify features and labels, assess data quality, imbalance, duplicates and leakage, and provide consistent train-fitted preprocessing for the agents.

### 3. Which files were inspected?

The locally supplied `training/flows.parquet` and `eval/flows.parquet`. The files and prepared records remain local and are not committed to GitHub.

### 4. What is the dataset size and schema?

- Training: 456,737 rows.
- Eval: 114,185 rows.
- Both files: 80 columns — 78 numeric flow measurements, `record_id`, and `label` — in the same order.
- The prepared model matrix contains 71 numeric features plus the string label. `record_id` is excluded from model inputs.

### 5. What labels are used?

The files already use the five benchmark labels: `BENIGN`, `BRUTE_FORCE`, `DOS`, `DDOS`, and `PORT_SCAN`. No attack-name remapping was needed for these files. A stable numeric encoding is recorded in the preprocessing implementation for code that needs one; prepared data keeps the original label strings.

### 6. What data-quality problems were found?

- No null cells or infinite numeric values.
- No duplicate full rows and no duplicate IDs within either split.
- A small number of header-length measurements are negative even though a length cannot be negative: forward length has 37 training and 10 eval cases; backward length has 70 training and 16 eval cases. These occur in BENIGN rows.

The preprocessor treats those negative values as invalid and fills them using medians learned from training. It applies the same training medians to eval.

### 7. Are there repeated feature records?

Yes. Rows with the same measurements can have different IDs. Training has 39,423 rows in repeated-feature groups; eval has 4,066. Across splits, 8,161 distinct feature vectors are shared, covering 9,795 eval rows (8.58%). Shared feature vectors have matching labels. Rows in the official eval file were kept.

### 8. Is the dataset balanced?

No. BENIGN is 52.55% of each split, while BRUTE_FORCE is about 1.21%. The training set has 240,000 BENIGN rows and 5,537 BRUTE_FORCE rows. Report macro-F1 and per-class results so the rare class is visible; do not rebalance the official eval set.

### 9. What leakage risk was identified?

`record_id` is sequential and label frequencies cluster by ID range. A simple ten-range, ID-only diagnostic reached 69.1% eval accuracy and 0.513 macro-F1. This is **not** a trained model or benchmark result; it shows that the ID provides an unintended clue. The preprocessor removes it from model inputs while keeping the original files unchanged for tracing.

### 10. What preprocessing is available?

`src/cybersentinel/data/cleaning.py` validates the schema and labels, marks infinities and invalid negative header lengths as missing, removes constant and exact duplicate feature columns, fills missing values using training medians, and can optionally scale features using training medians and interquartile ranges. It keeps all rows and applies the same fitted rules to eval. The command-line tool reads and writes Parquet.

### 11. What work is complete in the repository?

- Member 1 dataset preprocessing and the aggregate data report were merged in PR #6.
- Member 2 / Agent 1 classifier software was merged in PR #5.
- PyArrow is included in the optional ML dependencies for Parquet support.
- The dataset audit report is `docs/data-intelligence.md`.

### 12. What official model metrics are available?

No official classifier accuracy, macro-F1, confusion matrix, or per-class model scores have been produced in this work. The ID-only diagnostic above is only a leakage check and must not be reported as classifier performance.

### 13. What remains to finish the full team challenge?

- Train and evaluate Agent 1 on the official files. The current Agent 1 training CLI reads CSV; the supplied files are Parquet, so Parquet input support or a conversion step is needed before using that CLI.
- Implement the independent anomaly detector and evidence-fusion agent; both current modules are placeholders.
- Run the complete pipeline on official eval records, report measured metrics and limitations, and complete the organizer API summary submission.

### 14. Has the organizer API submission been made?

No. No benchmark results were submitted. The repository's `/api/analyze` endpoint remains fail-closed until the complete inference pipeline and trained model artifacts are ready.

## Suggested short progress response

“Member 1 inspected the organizer-provided Parquet splits and completed the data audit and train-fitted preprocessing handoff. The files contain 456,737 training rows and 114,185 eval rows across the five canonical classes. The audit found no nulls, infinities, duplicate full rows, or duplicate IDs; it flagged class imbalance, repeated feature vectors across splits, invalid negative header lengths, and `record_id` leakage risk. Preprocessing preserves all rows, excludes the ID from model inputs, and uses training-only fill/scaling values. Agent 1 software is in the repository, but official classifier metrics have not been generated. Agent 2, fusion, full-pipeline evaluation, and API submission remain pending.”
