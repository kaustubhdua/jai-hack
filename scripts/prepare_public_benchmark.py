#!/usr/bin/env python3
"""Download and prepare a reproducible CIC-IDS2017 public benchmark.

This benchmark is explicitly separate from the JAI organizer's private training,
evaluation, and hidden replay partitions. It is suitable for engineering smoke
tests and public-benchmark evaluation, never as a substitute for organizer data.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import random
import urllib.request
from collections import Counter
from pathlib import Path

import pandas as pd
from sklearn.model_selection import StratifiedGroupKFold

from cybersentinel.agents.threat_detection.model import BENCHMARK_CLASSES, numeric_features

DATASET_REPO = "bvsam/cic-ids-2017"
DATASET_REVISION = "a6628f1c99a39fd23b614a2d926ed679c264dd9b"
FILES = [
    "0000.parquet", "0001.parquet", "0002.parquet", "0003.parquet",
    "0004.parquet", "0005.parquet", "0006.parquet", "0007.parquet",
]
BASE_PATH = "machine_learning/train"
LABEL_COLUMN = "Label"
LABEL_MAP = {
    "benign": "BENIGN",
    "ftp-patator": "BRUTE_FORCE",
    "ssh-patator": "BRUTE_FORCE",
    "dos hulk": "DOS",
    "dos goldeneye": "DOS",
    "dos slowloris": "DOS",
    "dos slowhttptest": "DOS",
    "ddos": "DDOS",
    "portscan": "PORT_SCAN",
}
PAPER_CITATION = (
    "Iman Sharafaldin, Arash Habibi Lashkari, and Ali A. Ghorbani, "
    "Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic "
    "Characterization, ICISSP 2018."
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_label(value: object) -> str | None:
    """Map only documented CIC-IDS2017 labels to CyberSentinel's five classes."""
    if pd.isna(value):
        return None
    return LABEL_MAP.get(str(value).strip().casefold())


def download_file(filename: str, destination: Path, force: bool = False) -> dict:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.is_file() and destination.stat().st_size > 1024 and not force:
        return {"path": str(destination), "bytes": destination.stat().st_size,
                "sha256": sha256_file(destination), "downloaded": False}
    url = (
        f"https://huggingface.co/datasets/{DATASET_REPO}/resolve/"
        f"{DATASET_REVISION}/{BASE_PATH}/{filename}"
    )
    request = urllib.request.Request(url, headers={"User-Agent": "CyberSentinel-public-benchmark/1.0"})
    temporary = destination.with_suffix(destination.suffix + ".download")
    digest = hashlib.sha256()
    size = 0
    try:
        with urllib.request.urlopen(request, timeout=90) as response, temporary.open("wb") as output:  # nosec B310: fixed HTTPS host, pinned dataset revision
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                output.write(chunk)
                digest.update(chunk)
                size += len(chunk)
        if size < 1024:
            raise RuntimeError(f"Downloaded file is unexpectedly small ({size} bytes): {url}")
        temporary.replace(destination)
    finally:
        temporary.unlink(missing_ok=True)
    return {"path": str(destination), "bytes": size, "sha256": digest.hexdigest(),
            "downloaded": True, "source_url": url}


def _label_column(frame: pd.DataFrame) -> str:
    matches = [column for column in frame.columns if str(column).strip().casefold() == "label"]
    if len(matches) != 1:
        raise ValueError(f"Expected exactly one CIC-IDS2017 Label column; found {matches}")
    return matches[0]


def load_public_rows(data_dir: Path, max_per_class: int, seed: int, force_download: bool = False):
    rng = random.Random(seed)
    chunks = []
    download_manifest = []
    excluded_labels: Counter[str] = Counter()
    raw_counts: Counter[str] = Counter()
    for filename in FILES:
        path = data_dir / "downloads" / filename
        download_manifest.append(download_file(filename, path, force_download))
        frame = pd.read_parquet(path)
        label_col = _label_column(frame)
        raw = frame[label_col].astype("string").str.strip()
        mapped = raw.map(lambda item: canonical_label(item))
        for label, count in raw.value_counts(dropna=False).items():
            raw_counts[str(label)] += int(count)
        supported = mapped.notna()
        for label, count in raw.loc[~supported].value_counts(dropna=False).items():
            excluded_labels[str(label)] += int(count)
        frame = frame.loc[supported].copy()
        frame["label"] = mapped.loc[supported].astype(str)
        frame = frame.drop(columns=[label_col], errors="ignore")
        # Reduce memory before concatenating the eight public Parquet partitions.
        for column in frame.columns:
            if column != "label":
                frame[column] = pd.to_numeric(frame[column], errors="coerce").astype("float32")
        # Bound each source shard before combining; final per-class cap is applied below.
        sampled = []
        for label, group in frame.groupby("label", sort=True):
            take = min(len(group), max_per_class)
            sampled.append(group.sample(n=take, random_state=rng.randrange(0, 2**32 - 1)))
        if sampled:
            chunks.append(pd.concat(sampled, ignore_index=True))
        del frame

    if not chunks:
        raise RuntimeError("No supported labelled CIC-IDS2017 rows were found.")
    combined = pd.concat(chunks, ignore_index=True)
    # The final cap is deterministic and keeps the public benchmark tractable.
    balanced = []
    for label in BENCHMARK_CLASSES:
        group = combined.loc[combined["label"] == label]
        if group.empty:
            raise ValueError(f"CIC-IDS2017 did not provide the required benchmark class {label}.")
        balanced.append(group.sample(
            n=min(len(group), max_per_class), random_state=seed
        ))
    selected = pd.concat(balanced, ignore_index=True).sample(frac=1, random_state=seed).reset_index(drop=True)

    features = numeric_features(selected.drop(columns=["label"]))
    # Identical feature vectors with conflicting labels are ambiguous. Remove the
    # entire conflicting group rather than leaking it across train/evaluation.
    groups = pd.util.hash_pandas_object(features, index=False).to_numpy()
    labels_by_group = pd.DataFrame({"group": groups, "label": selected["label"].to_numpy()})
    conflicting = set(labels_by_group.groupby("group")["label"].nunique().loc[lambda x: x > 1].index)
    keep = ~pd.Series(groups).isin(conflicting).to_numpy()
    removed_conflicting_rows = int((~keep).sum())
    selected = selected.loc[keep].reset_index(drop=True)
    features = numeric_features(selected.drop(columns=["label"]))
    groups = pd.util.hash_pandas_object(features, index=False).to_numpy()
    y = selected["label"].astype(str).to_numpy()

    splitter = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=seed)
    split = None
    expected = set(BENCHMARK_CLASSES)
    for train_idx, eval_idx in splitter.split(features, y, groups):
        if set(y[train_idx]) == expected and set(y[eval_idx]) == expected:
            split = train_idx, eval_idx
            break
    if split is None:
        raise RuntimeError("Could not create a group-isolated stratified split containing all five classes.")
    train_idx, eval_idx = split
    if set(groups[train_idx]) & set(groups[eval_idx]):
        raise RuntimeError("Identical feature-vector group leaked between training and evaluation.")
    training = selected.iloc[train_idx].reset_index(drop=True)
    evaluation = selected.iloc[eval_idx].reset_index(drop=True)
    return training, evaluation, {
        "source_repository": f"https://huggingface.co/datasets/{DATASET_REPO}",
        "source_revision": DATASET_REVISION,
        "source_files": download_manifest,
        "paper_citation": PAPER_CITATION,
        "license_note": (
            "The original CIC-IDS2017 publisher describes the CSV dataset as publicly "
            "available for researchers and requests citation. Verify the publisher's "
            "current terms before any commercial use or redistribution."
        ),
        "label_mapping": LABEL_MAP,
        "excluded_raw_label_counts": dict(sorted(excluded_labels.items())),
        "raw_label_counts": dict(sorted(raw_counts.items())),
        "max_rows_per_canonical_class": max_per_class,
        "selected_rows_after_ambiguous_duplicate_removal": int(len(selected)),
        "ambiguous_conflicting_duplicate_rows_removed": removed_conflicting_rows,
        "training_rows": int(len(training)),
        "evaluation_rows": int(len(evaluation)),
        "training_class_counts": training["label"].value_counts().sort_index().to_dict(),
        "evaluation_class_counts": evaluation["label"].value_counts().sort_index().to_dict(),
        "split": "5-fold StratifiedGroupKFold; exact numeric feature vectors kept in one partition",
        "seed": seed,
        "official_challenge_data_used": False,
        "hidden_challenge_data_used": False,
        "benchmark_disclosure": (
            "CIC-IDS2017 is an external public engineering benchmark, not the JAI organizer "
            "dataset. Its class mapping is a documented subset; unsupported attack families "
            "are excluded and listed. Results must not be described as official challenge scores."
        ),
    }


def prepare(output_dir: Path, max_per_class: int, seed: int, force_download: bool = False) -> dict:
    if max_per_class < 100:
        raise ValueError("--max-per-class must be at least 100.")
    downloads_dir = output_dir / "downloads"
    training, evaluation, manifest = load_public_rows(
        downloads_dir, max_per_class=max_per_class, seed=seed, force_download=force_download
    )
    output_dir.mkdir(parents=True, exist_ok=True)
    train_path = output_dir / "training.parquet"
    eval_path = output_dir / "evaluation.parquet"
    training.to_parquet(train_path, index=False)
    evaluation.to_parquet(eval_path, index=False)
    manifest["training_file"] = {"path": str(train_path), "sha256": sha256_file(train_path)}
    manifest["evaluation_file"] = {"path": str(eval_path), "sha256": sha256_file(eval_path)}
    manifest_path = output_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=Path("data/raw/public-benchmark"))
    parser.add_argument("--max-per-class", type=int, default=50000)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--force-download", action="store_true")
    args = parser.parse_args()
    print(json.dumps(prepare(args.output_dir, args.max_per_class, args.seed, args.force_download), indent=2))


if __name__ == "__main__":
    main()
