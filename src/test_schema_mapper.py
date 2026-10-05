import os
import pandas as pd

from schema_mapper import (
    detect_column_mapping,
    apply_column_mapping,
    print_mapping_report
)


# ============================================================
# Project Root
# ============================================================

PROJECT_ROOT = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)


# ============================================================
# Dataset Path
# ============================================================

DATA_PATH = os.path.join(
    PROJECT_ROOT,
    "data",
    "raw",
    "cybersecurity.csv"
)


# ============================================================
# Load Dataset
# ============================================================

df = pd.read_csv(
    DATA_PATH
)


print(
    "Original dataset columns:"
)

print(
    df.columns.tolist()
)


# ============================================================
# Detect Column Mapping
# ============================================================

mapping = detect_column_mapping(
    df
)


# ============================================================
# Display Mapping Report
# ============================================================

print_mapping_report(
    df,
    mapping
)


# ============================================================
# Apply Mapping
# ============================================================

mapped_df = apply_column_mapping(
    df,
    mapping
)


# ============================================================
# Display Final Columns
# ============================================================

print(
    "\nFinal standardized columns:"
)

print(
    mapped_df.columns.tolist()
)