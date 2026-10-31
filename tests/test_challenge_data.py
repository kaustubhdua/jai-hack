import hashlib
import json
import zipfile

import pandas as pd

from scripts.prepare_challenge_data import prepare


def test_prepare_challenge_data_verifies_manifest_and_hidden_contract(tmp_path):
    training_bytes = b"training parquet placeholder"
    evaluation_bytes = b"evaluation parquet placeholder"
    manifest = {
        "tracks": {"cyber": {"partitions": {
            "training": {"rows": 12, "bytes": len(training_bytes), "sha256": hashlib.sha256(training_bytes).hexdigest()},
            "eval": {"rows": 5, "bytes": len(evaluation_bytes), "sha256": hashlib.sha256(evaluation_bytes).hexdigest()},
        }}}
    }
    training_pack = tmp_path / "cyber-pack.zip"
    with zipfile.ZipFile(training_pack, "w") as archive:
        archive.writestr("manifest.json", json.dumps(manifest))
        archive.writestr("Cyber/training/flows.parquet", training_bytes)
        archive.writestr("Cyber/eval/flows.parquet", evaluation_bytes)

    hidden_rows = []
    for index in range(1, 201):
        row = {
            "record_id": f"F{index:06d}", "seq": index, "day": "2017-07-04",
            "time_offset": f"{index:02d}:00.0", "source_ip": "192.0.2.1",
            "destination_ip": "192.0.2.2", "source_port": 10000 + index,
            "destination_port": 443, "protocol": 6,
        }
        row.update({f"feature_{column:02d}": float(index + column) for column in range(78)})
        hidden_rows.append(row)
    hidden_csv = pd.DataFrame(hidden_rows).to_csv(index=False)
    hidden_pack = tmp_path / "cyber-hidden.zip"
    with zipfile.ZipFile(hidden_pack, "w") as archive:
        archive.writestr("README.md", "There is **no label column** in this hidden input.")
        archive.writestr("Cyber/hidden/records.csv", hidden_csv)

    report = prepare(training_pack, hidden_pack, tmp_path / "data")
    assert report["training"]["rows"] == 12
    assert report["evaluation"]["rows"] == 5
    assert report["hidden"]["rows"] == 200
    assert report["hidden"]["features"] == 78
    assert report["hidden"]["labels_present"] is False
    assert (tmp_path / "data/raw/training/flows.parquet").read_bytes() == training_bytes
    assert (tmp_path / "data/processed/hidden_replay_input.csv").is_file()


def test_prepare_challenge_data_rejects_manifest_hash_mismatch(tmp_path):
    training_pack = tmp_path / "bad-pack.zip"
    hidden_pack = tmp_path / "hidden.zip"
    with zipfile.ZipFile(training_pack, "w") as archive:
        archive.writestr("manifest.json", json.dumps({"tracks": {"cyber": {"partitions": {
            "training": {"rows": 1, "bytes": 3, "sha256": "0" * 64},
            "eval": {"rows": 1, "bytes": 3, "sha256": "0" * 64},
        }}}}))
        archive.writestr("Cyber/training/flows.parquet", b"bad")
        archive.writestr("Cyber/eval/flows.parquet", b"bad")
    with zipfile.ZipFile(hidden_pack, "w") as archive:
        archive.writestr("README.md", "There is **no label column**")
        archive.writestr("Cyber/hidden/records.csv", "record_id,seq\nF000001,1\n")
    try:
        prepare(training_pack, hidden_pack, tmp_path / "data")
    except ValueError as exc:
        assert "SHA-256 verification" in str(exc)
    else:
        raise AssertionError("Invalid training pack must be rejected.")
