# Release readiness and reproducibility gates

This document defines the evidence required before CyberSentinel is described as a completed, production-ready product. A green frontend deployment or a successful unit-test run is not, by itself, proof of model-backed operation.

## Current operating boundary

CyberSentinel currently analyzes supplied network-flow records and supports chronological offline replay. Its ALLOW/BLOCK/REVIEW outcomes are simulated application decisions. Unless a separately reviewed live sensor and enforcement adapter is implemented and tested, do not describe the product as live packet monitoring or as changing host/network firewalls.

## Release gates

### 1. Reproducible data and model provenance
- Record the source, license/terms, acquisition date, and SHA-256 digest for each dataset artifact.
- Verify train/evaluation partition membership and document duplicate feature vectors across partitions.
- Fit preprocessing only on training data. Keep final evaluation data out of model selection, threshold selection, calibration selection, and hyperparameter tuning.
- Record model artifact hashes, training code revision, dependency lock, feature schema, class order, and random seeds.
- Train, reload, and predict with both A1 and A2 from a clean checkout.

### 2. Evaluation integrity
- Generate reports from authorized, real benchmark files; never substitute fixture or generated values for benchmark results.
- Keep test fixtures explicitly labeled as fixtures and never publish their metrics as benchmark performance.
- Verify classification metrics, per-class recall, confusion matrix, benign false-positive rate, and attack detection rate.
- Verify A2 score direction, ROC-AUC/PR-AUC, threshold behavior, and incremental value beyond A1.
- Evaluate A3 overrides and ALLOW/REVIEW/BLOCK decisions separately from class accuracy.
- Evaluate A4 with chronological, endpoint-provenance-aware fixtures and report campaign-level precision/recall and detection delay using a documented ground-truth definition.
- Evaluate A5 policy scope, activation order, expiry, benign false-blocks, and replay causality.
- Use group-isolated and independent-dataset tests to assess generalization; CICIDS2017 alone is not evidence of current production generalization.
- Calibration method selection must use training/validation data only; the final evaluation partition must remain untouched until final scoring.

### 3. End-to-end replay and API
- Verify each replay starts with isolated correlation and defense state.
- Verify a policy created by a record cannot block that same record, but may affect later records within its documented scope and lifetime.
- Test malformed inputs, missing model artifacts, inference failures, empty batches, oversized requests, and concurrent replay requests.
- Verify report endpoints return explicit not-generated states rather than placeholder or fabricated metrics.
- Verify output record IDs exactly match the supplied input set and order where required.

### 4. Security and privacy
- Treat model artifacts as trusted executable serialization; never load user-supplied pickle/joblib files.
- Apply authentication/authorization before exposing sensitive analyst or replay data in a hosted deployment.
- Bound upload sizes, row counts, batch sizes, runtime, and memory use.
- Restrict CORS, avoid logging raw sensitive flow payloads, and scan dependencies, secrets, and Python source.
- Review CSV export formula injection and path handling before accepting untrusted input or serving generated files.

### 5. Frontend and usability
- Every metric and status shown in the UI must come from a real API response or be explicitly labeled as an example/empty state.
- Every visible control must perform its advertised action; remove dead controls and pretend-success toasts.
- Verify loading, empty, error, retry, and partial-report states.
- Run responsive, keyboard, screen-reader, and browser end-to-end checks.
- Lazy-load expensive visualizations and paginate or virtualize large flow tables.

### 6. Deployment and operations
- A serverless frontend deployment is not proof that Python models, large replay jobs, or SQLite persistence are available and durable.
- Document which workflows are local/offline and which are hosted.
- For hosted multi-user operation, use durable shared storage, background jobs for long replay, persistent job status, authentication, and model-backed readiness checks.
- Perform a production smoke test using real model artifacts and a known, authorized fixture dataset.

## Clean-machine acceptance test

A person other than the original developer must be able to:
1. Clone the repository and install pinned dependencies.
2. Obtain authorized datasets following the documented instructions and verify their hashes.
3. Prepare data and train A1/A2 without relying on ignored local artifacts.
4. Reload models and run the full evaluation suite.
5. Start the API and frontend from documented commands.
6. Run a chronological replay and validate all generated submission files.
7. Inspect the UI and confirm it reflects the generated reports and real backend responses.

## Release decision

Mark a gate **PASS** only when its command, environment, input artifact hashes, output, and CI/run reference are recorded. Use **BLOCKED** when required datasets, credentials, infrastructure, or independent verification are unavailable. Do not mark a gate complete based only on source-code presence or a planned workflow.
