# Deployed model artifact provenance

## What is deployed

The checked-in model artifacts are reproducible **public CIC-IDS2017 engineering baselines**. They are not trained on the JAI organizer's private training pack, are not validated against the organizer's hidden replay pack, and must not be described as official challenge models or official JAI scores.

The artifacts are published from GitHub Actions run [43654575456](https://github.com/kaustubhdua/jai-hack/actions/runs/43654575456), which trains and evaluates the models on the pinned public benchmark. The publish workflow verifies the SHA-256 values in the training manifest before copying either model into the runtime paths.

## Evidence and limitations

- Agent 1: Random Forest, trained on the supported five-class subset of CIC-IDS2017.
- Agent 2: Isolation Forest, trained on BENIGN training rows only; its operating threshold is calibrated on a separate training-side holdout.
- The public evaluation partition is untouched by fitting and calibration.
- The training manifest, public evaluation report, and dataset preparation manifest are retained under `models/provenance/`.
- Raw Parquet data is never committed or included in the deployment artifact.
- Agent 2 is supplementary: its public evaluation attack recall is about 31.3% at about 1.76% benign false-positive rate. It is not a strong standalone detector.
- Agent 1's high CIC-IDS2017 score is specific to this group-isolated public benchmark. It is not evidence of cross-dataset generalization or hidden challenge performance.

## Reproducibility

The source dataset and exact preparation procedure are documented in [Open-source benchmark bootstrap](open-source-benchmark.md). Re-run the public benchmark workflow to produce a new model bundle; update the artifact run ID and artifact name in `.github/workflows/publish-public-benchmark-models.yml` only after a successful main-branch benchmark run.

## Production readiness boundary

A model being present means the API can load a baseline model. It does not certify the organizer's official dataset contract, hidden replay outputs, production browser acceptance, or challenge submission. Keep those release gates separate and report them as unverified until the organizer inputs and live end-to-end tests are available.
