"""Automated tests for data preprocessing and cleaning pipeline."""
import numpy as np
import pandas as pd
import pytest

from cybersentinel.data.schema import BENCHMARK_CLASSES, TARGET_COLUMN
from cybersentinel.data.label_mapper import LabelMapper
from cybersentinel.data.cleaner import sanitize_flow_features, impute_missing
from cybersentinel.data.feature_selector import identify_constant_features, identify_duplicate_features
from cybersentinel.data.preprocessing import FlowPreprocessor


def test_label_mapper_strict_and_unknown():
    mapper = LabelMapper()
    # Canonical valid series
    valid_series = pd.Series(["BENIGN", "DOS", "DDOS", "PORT_SCAN", "BRUTE_FORCE"])
    mapped = mapper.map_series(valid_series)
    assert list(mapped) == list(valid_series)

    # Unknown label raises ValueError without silent discard
    with pytest.raises(ValueError, match="invalid benchmark labels"):
        mapper.map_series(pd.Series(["BENIGN", "UNKNOWN_ATTACK"]))

    # Explicit mapping dictionary
    custom_mapper = LabelMapper({"FTP-Patator": "BRUTE_FORCE", "Normal": "BENIGN"})
    custom_series = pd.Series(["FTP-Patator", "Normal"])
    mapped_custom = custom_mapper.map_series(custom_series)
    assert list(mapped_custom) == ["BRUTE_FORCE", "BENIGN"]


def test_cleaner_infinite_and_negative_header_length():
    df = pd.DataFrame({
        "Flow Duration": [100.0, np.inf, 200.0, -np.inf],
        "Fwd Header Length": [20, -10, 40, 20],  # -10 is invalid negative byte length
        "Total Fwd Packets": [1, 2, np.nan, 4],
    })
    cleaned = sanitize_flow_features(df, ["Flow Duration", "Fwd Header Length", "Total Fwd Packets"])

    # Infinities should become NaN
    assert np.isnan(cleaned.loc[1, "Flow Duration"])
    assert np.isnan(cleaned.loc[3, "Flow Duration"])

    # Negative header length should become NaN
    assert np.isnan(cleaned.loc[1, "Fwd Header Length"])
    assert cleaned.loc[0, "Fwd Header Length"] == 20

    # Impute missing with medians
    medians = {"Flow Duration": 150.0, "Fwd Header Length": 20.0, "Total Fwd Packets": 2.0}
    imputed = impute_missing(cleaned, medians)
    assert not imputed.isna().any().any()
    assert imputed.loc[1, "Flow Duration"] == 150.0
    assert imputed.loc[1, "Fwd Header Length"] == 20.0


def test_feature_selector_constants_and_duplicates():
    df = pd.DataFrame({
        "constant_col": [0.0, 0.0, 0.0],
        "varying_col": [1.0, 2.0, 3.0],
        "duplicate_col": [1.0, 2.0, 3.0],
    })
    constants = identify_constant_features(df, list(df.columns))
    assert constants == ["constant_col"]

    duplicates = identify_duplicate_features(df, ["varying_col", "duplicate_col"])
    assert duplicates == {"duplicate_col": "varying_col"}


def test_flow_preprocessor_fit_transform_no_leakage(tmp_path):
    train_df = pd.DataFrame({
        "record_id": [1, 2, 3, 4],
        "feature_1": [10.0, np.nan, 30.0, 40.0],
        "feature_2": [1.0, 1.0, 1.0, 1.0],  # Constant in training
        "label": ["BENIGN", "DOS", "BENIGN", "DOS"],
    })
    eval_df = pd.DataFrame({
        "record_id": [5, 6],
        "feature_1": [100.0, np.nan],
        "feature_2": [1.0, 2.0],  # Not constant in eval, but must be dropped because train-fitted
        "label": ["BENIGN", "DOS"],
    })

    prep = FlowPreprocessor().fit(train_df)
    transformed_train = prep.transform(train_df, include_label=True)
    transformed_eval = prep.transform(eval_df, include_label=True)

    # Constant feature removed from both
    assert "feature_2" not in transformed_train.columns
    assert "feature_2" not in transformed_eval.columns
    # record_id excluded from feature matrix
    assert "record_id" not in transformed_train.columns
    assert "record_id" not in transformed_eval.columns

    # Eval NaN imputed with train median (30.0)
    assert transformed_eval.loc[1, "feature_1"] == 30.0

    # Save and reload preprocessor state
    state_file = tmp_path / "prep_state.json"
    prep.save(state_file)
    restored_prep = FlowPreprocessor.load(state_file)
    assert restored_prep.feature_columns == prep.feature_columns
