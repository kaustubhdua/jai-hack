# Release, Current Contract, and QA Archive

## Current entry points

- [Root README](../README.md): project scope, setup, disclosures, and runtime boundaries.
- [Evaluation guide](../docs/evaluation.md): authorized training/evaluation separation and exact local workflow.
- [Level 2 brief](../docs/level2-brief.md): currently implemented hidden replay contract.
- [Hidden-input audit](benchmarks/hidden-input-audit.md): supplied input facts and hashes of downloaded stage-page templates.
- [Submission contract](benchmarks/submission-contract-results.md): current file headers and semantic validation rules.
- [Observed endpoint audit](benchmarks/source-ip-scope-audit.md): current no-synthetic-endpoint rule.
- [Presentation runbook](benchmarks/operational-runbook.md): current rehearsal and submission workflow, including the required schema check.

## Historical reports

Files under `day2-final/` and `qa-reports/` are historical snapshots. Older benchmark and UI reports in `benchmarks/` are also historical unless explicitly listed above as current contract audits or the presentation runbook. Their model metrics, test counts, runtime states, APIs, screenshots, and submission statuses are not current verification. Each historical report is labelled at its top.

Before citing any metric or saying the project is submission-ready:

1. Use the latest `main` revision.
2. Obtain the exact authorized organizer data and the current upload templates.
3. Reproduce training, evaluation, replay, and independent validation with recorded input hashes and code revision.
4. Confirm the current GitHub Actions runs.
5. Claim organizer acceptance only when an actual successful response or receipt is available.

Challenge data, model binaries, and generated submissions remain outside Git unless the organizers explicitly authorize publication.
