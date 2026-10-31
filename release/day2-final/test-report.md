# CyberSentinel — Automated Test Verification Report

> **Historical archive — not current verification.** This file preserves an earlier run and may describe obsolete models, metrics, interfaces, or CSV schemas. Do not use it as current evidence for judging, submission, or presentation claims. Regenerate results from current `main` and authorized organizer data. The current workflow is [docs/evaluation](../../docs/evaluation.md); the current Level 2 contract is [docs/level2-brief](../../docs/level2-brief.md).


## 1. Python Pytest Test Suite

* **Total Tests Executed:** 36 passed
* **Failures / Errors:** 0
* **Execution Time:** ~11.5 seconds
* **Command:** `$env:PYTHONPATH="src"; python -m pytest tests -q`

### Test Suite Breakdown:

| Test File | Tests Passed | Covered Functionality |
| :--- | :--- | :--- |
| `tests/test_threat_detection.py` | 5 | Agent 1 model loading, single flow, batch, 5-class predictions, feature validation |
| `tests/test_anomaly_detection.py` | 5 | Agent 2 model loading, isolation thresholding, feature deviation evidence, vectorized scoring |
| `tests/test_fusion.py` | 6 | Agent 3 agreement, disagreement, confidence thresholds, incomplete states, fail-safe fallbacks |
| `tests/test_correlation.py` | 4 | Agent 4 endpoint extraction, port scan sweeps, brute force, DDoS surge correlation |
| `tests/test_adaptive_defense.py` | 3 | Agent 5 initial flow allow, forward policy creation, matching record block, automatic policy expiry |
| `tests/test_replay.py` | 1 | 5-agent causal chronological replay workflow, applied policy attribution, CSV schema check |
| `tests/test_submission_validator.py` | 3 | SubmissionValidator checks, schema & referential integrity, SQLite history DB persistence |
| `tests/test_api.py` | 5 | FastAPI `/health`, `/analyze`, `/analyze/batch`, `/replay/simulate`, dedicated function routes |
| `tests/test_pipeline.py` | 4 | CyberSentinelPipeline fail-closed orchestration, error wrapping, latency measurement |

---

## 2. Frontend TypeScript Build Verification

* **Command:** `npm run build` (`tsc -b && vite build`)
* **Status:** SUCCESS (Built in 8.73s)
* **Modules Transformed:** 1628 modules
* **Output:**
  * `dist/index.html` (0.59 kB)
  * `dist/assets/index-D5PfFz3u.css` (17.90 kB)
  * `dist/assets/index-B2b3wqRW.js` (980.91 kB)
* **TypeScript Errors:** 0

