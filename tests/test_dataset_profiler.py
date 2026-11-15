from pathlib import Path

import pandas as pd
import pytest

from scripts.profile_dataset import profile_frame, read_dataset


def test_profile_detects_schema_missingness_and_label_distribution():
    frame = pd.DataFrame({
        "Flow Duration": [10, 20, None],
        "Protocol": [6, 6, 17],
        " Label": ["BENIGN", "DoS", "BENIGN"],
    })
    report = profile_frame(frame)
    assert report["rows"] == 3
    assert report["numeric_columns"] == 2
    assert report["label"]["column"] == " Label"
    assert report["label"]["distribution"] == {"BENIGN": 2, "DoS": 1}
    assert report["schema"][0]["missing"] == 1


def test_profile_requires_explicit_existing_label():
    with pytest.raises(ValueError, match="does not exist"):
        profile_frame(pd.DataFrame({"x": [1]}), "missing")


def test_profile_rejects_empty_and_duplicate_columns():
    with pytest.raises(ValueError, match="empty"):
        profile_frame(pd.DataFrame())
    frame = pd.DataFrame([[1, 2]], columns=["x", "x"])
    with pytest.raises(ValueError, match="duplicate"):
        profile_frame(frame)


def test_read_dataset_supports_csv_and_rejects_unknown_format(tmp_path: Path):
    csv_path = tmp_path / "sample.csv"
    csv_path.write_text("feature,label\\n1,BENIGN\\n", encoding="utf-8")
    assert len(read_dataset(csv_path)) == 1
    unknown = tmp_path / "sample.json"
    unknown.write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="Supported formats"):
        read_dataset(unknown)
