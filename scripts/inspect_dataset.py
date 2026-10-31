"""Comprehensive dataset inspection script for CyberSentinel CICIDS2017 dataset."""
import os
import json
import numpy as np
import pandas as pd

train_path = r"C:\Users\Admin\.gemini\antigravity\scratch\jai-hack\data\raw\Cyber\training\flows.parquet"
eval_path = r"C:\Users\Admin\.gemini\antigravity\scratch\jai-hack\data\raw\Cyber\eval\flows.parquet"

print("--- 1. VERIFYING READING THE DATASET ---")
print(f"Training path exists: {os.path.exists(train_path)}")
print(f"Eval path exists: {os.path.exists(eval_path)}")

train_df = pd.read_parquet(train_path)
eval_df = pd.read_parquet(eval_path)

print(f"Training shape: {train_df.shape}")
print(f"Eval shape:     {eval_df.shape}")

print("\n--- 2. COLUMN INSPECTION ---")
print(f"Total columns: {len(train_df.columns)}")
print("Columns list with whitespace stripped check:")
whitespace_issues = [c for c in train_df.columns if c != c.strip()]
print(f"Columns with leading/trailing whitespace: {whitespace_issues}")
print("Sample columns & dtypes:")
for col, dtype in list(train_df.dtypes.items())[:15]:
    print(f"  - {col}: {dtype}")
print(f"  ... and {len(train_df.columns) - 15} more columns.")

print("\n--- 3. LABEL DISTRIBUTION & BENIGN IDENTIFICATION ---")
print("Training class counts:")
train_counts = train_df['label'].value_counts()
print(train_counts)
train_benign_count = (train_df['label'] == 'BENIGN').sum()
print(f"Total BENIGN in Training: {train_benign_count} ({train_benign_count / len(train_df):.2%})")

print("\nEval class counts:")
eval_counts = eval_df['label'].value_counts()
print(eval_counts)
eval_benign_count = (eval_df['label'] == 'BENIGN').sum()
print(f"Total BENIGN in Eval:     {eval_benign_count} ({eval_benign_count / len(eval_df):.2%})")

print("\n--- 4. DATA QUALITY CHECKS (NULLS, INFS, DUPLICATES) ---")
# Check numeric columns
numeric_cols = train_df.select_dtypes(include=[np.number]).columns.tolist()
print(f"Numeric features count: {len(numeric_cols)}")

# Nulls
train_nulls = train_df.isna().sum()
null_cols = train_nulls[train_nulls > 0]
print(f"Columns with NULL in Training: {len(null_cols)}")
if len(null_cols) > 0:
    for c, v in null_cols.items():
        print(f"  - {c}: {v} nulls")

eval_nulls = eval_df.isna().sum()
eval_null_cols = eval_nulls[eval_nulls > 0]
print(f"Columns with NULL in Eval: {len(eval_null_cols)}")
if len(eval_null_cols) > 0:
    for c, v in eval_null_cols.items():
        print(f"  - {c}: {v} nulls")

# Infs
train_infs = {}
for c in numeric_cols:
    inf_count = np.isinf(train_df[c]).sum()
    if inf_count > 0:
        train_infs[c] = int(inf_count)
print(f"Columns with Inf / -Inf in Training: {len(train_infs)}")
for c, v in train_infs.items():
    print(f"  - {c}: {v} inf values")

eval_infs = {}
for c in numeric_cols:
    inf_count = np.isinf(eval_df[c]).sum()
    if inf_count > 0:
        eval_infs[c] = int(inf_count)
print(f"Columns with Inf / -Inf in Eval: {len(eval_infs)}")
for c, v in eval_infs.items():
    print(f"  - {c}: {v} inf values")

# Duplicates
feature_cols = [c for c in train_df.columns if c not in ['record_id', 'label']]
train_dup_features = train_df.duplicated(subset=feature_cols).sum()
eval_dup_features = eval_df.duplicated(subset=feature_cols).sum()
print(f"Duplicate feature rows in Training: {train_dup_features} ({train_dup_features / len(train_df):.2%})")
print(f"Duplicate feature rows in Eval:     {eval_dup_features} ({eval_dup_features / len(eval_df):.2%})")

# Constant features (zero variance)
zero_var_cols = [c for c in numeric_cols if train_df[c].std() == 0]
print(f"\nZero-variance constant columns in Training: {len(zero_var_cols)}")
if zero_var_cols:
    print(f"  Constant columns: {zero_var_cols}")

print("\n--- 5. BENIGN SAMPLE STATISTICS ---")
benign_df = train_df[train_df['label'] == 'BENIGN']
print(f"BENIGN subset shape: {benign_df.shape}")
print("Done inspection!")
