import os

from validator import (
    validate_dataset,
    print_validation_report
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
# Validate Dataset
# ============================================================

validation_result = validate_dataset(
    DATA_PATH
)


# ============================================================
# Display Validation Report
# ============================================================

print_validation_report(
    validation_result
)