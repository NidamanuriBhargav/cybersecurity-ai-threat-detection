# ============================================================
# Cybersecurity Dataset Validator
# ============================================================

import os
import pandas as pd


# ============================================================
# Dataset Schema Categories
# ============================================================

CORE_COLUMNS = [
    "timestamp",
    "src_port",
    "dst_port",
    "protocol",
    "bytes_sent",
    "bytes_received"
]


OPTIONAL_COLUMNS = [
    "src_ip",
    "dst_ip",
    "user_agent",
    "url",
    "is_internal_traffic"
]


EVALUATION_COLUMNS = [
    "label",
    "attack_type"
]


# ============================================================
# Validate Dataset File
# ============================================================

def validate_dataset_file(file_path):
    """
    Check whether the dataset exists,
    can be read, and contains data.
    """

    result = {
        "file_exists": False,
        "readable": False,
        "has_data": False,
        "errors": []
    }

    if not os.path.exists(file_path):

        result["errors"].append(
            f"Dataset file not found: {file_path}"
        )

        return result

    result["file_exists"] = True

    try:

        df = pd.read_csv(
            file_path
        )

        result["readable"] = True

    except Exception as error:

        result["errors"].append(
            f"Dataset could not be read: {error}"
        )

        return result

    if df.empty:

        result["errors"].append(
            "Dataset is empty."
        )

        return result

    result["has_data"] = True

    return result


# ============================================================
# Validate Dataset Schema
# ============================================================

def validate_columns(df):
    """
    Classify dataset columns into:
    core, optional, evaluation, and unknown.
    """

    actual_columns = set(
        df.columns
    )

    missing_core = [
        column
        for column in CORE_COLUMNS
        if column not in actual_columns
    ]

    available_optional = [
        column
        for column in OPTIONAL_COLUMNS
        if column in actual_columns
    ]

    available_evaluation = [
        column
        for column in EVALUATION_COLUMNS
        if column in actual_columns
    ]

    unknown_columns = [
        column
        for column in df.columns
        if (
            column not in CORE_COLUMNS
            and column not in OPTIONAL_COLUMNS
            and column not in EVALUATION_COLUMNS
        )
    ]

    return {
        "missing_core": missing_core,
        "available_optional": available_optional,
        "available_evaluation": available_evaluation,
        "unknown_columns": unknown_columns,
        "valid": len(missing_core) == 0
    }


# ============================================================
# Validate Data Quality
# ============================================================

def validate_data_quality(df):
    """
    Check timestamps, numeric fields,
    missing values, protocols, and labels.
    """

    errors = []
    warnings = []

    # --------------------------------------------------------
    # Timestamp validation
    # --------------------------------------------------------

    if "timestamp" in df.columns:

        converted_timestamp = pd.to_datetime(
            df["timestamp"],
            errors="coerce"
        )

        invalid_timestamps = (
            converted_timestamp.isna().sum()
        )

        if invalid_timestamps > 0:

            errors.append(
                f"{invalid_timestamps} invalid "
                "timestamp values found."
            )

    # --------------------------------------------------------
    # Numeric column validation
    # --------------------------------------------------------

    numeric_columns = [
        "src_port",
        "dst_port",
        "bytes_sent",
        "bytes_received"
    ]

    for column in numeric_columns:

        if column not in df.columns:
            continue

        converted_values = pd.to_numeric(
            df[column],
            errors="coerce"
        )

        invalid_values = (
            converted_values.isna().sum()
        )

        if invalid_values > 0:

            errors.append(
                f"{invalid_values} invalid values "
                f"found in '{column}'."
            )

    # --------------------------------------------------------
    # Protocol validation
    # --------------------------------------------------------

    if "protocol" in df.columns:

        missing_protocols = (
            df["protocol"]
            .isna()
            .sum()
        )

        if missing_protocols > 0:

            warnings.append(
                f"{missing_protocols} missing "
                "protocol values found."
            )

    # --------------------------------------------------------
    # Core missing-value checks
    # --------------------------------------------------------

    for column in CORE_COLUMNS:

        if column not in df.columns:
            continue

        missing_count = (
            df[column]
            .isna()
            .sum()
        )

        if missing_count > 0:

            warnings.append(
                f"{missing_count} missing values "
                f"in '{column}'."
            )

    # --------------------------------------------------------
    # Optional missing-value information
    # --------------------------------------------------------

    for column in OPTIONAL_COLUMNS:

        if column not in df.columns:
            continue

        missing_count = (
            df[column]
            .isna()
            .sum()
        )

        if missing_count > 0:

            warnings.append(
                f"{missing_count} missing values "
                f"in optional column '{column}'."
            )

    # --------------------------------------------------------
    # Label validation
    # --------------------------------------------------------

    if "label" in df.columns:

        unique_labels = (
            df["label"]
            .dropna()
            .unique()
            .tolist()
        )

        if not set(unique_labels).issubset(
            {0, 1}
        ):

            warnings.append(
                "The 'label' column contains "
                "values other than 0 and 1."
            )

    return {
        "errors": errors,
        "warnings": warnings,
        "valid": len(errors) == 0
    }


# ============================================================
# Complete Dataset Validation
# ============================================================

def validate_dataset(file_path):
    """
    Perform complete dataset validation.
    """

    file_result = validate_dataset_file(
        file_path
    )

    if file_result["errors"]:

        return {
            "valid": False,
            "file_result": file_result,
            "column_result": None,
            "quality_result": None,
            "data": None
        }

    df = pd.read_csv(
        file_path
    )

    column_result = validate_columns(
        df
    )

    quality_result = validate_data_quality(
        df
    )

    overall_valid = (
        column_result["valid"]
        and quality_result["valid"]
    )

    return {
        "valid": overall_valid,
        "file_result": file_result,
        "column_result": column_result,
        "quality_result": quality_result,
        "data": df
    }


# ============================================================
# Print Validation Report
# ============================================================

def print_validation_report(
    validation_result
):
    """
    Display a readable validation report.
    """

    print("\n" + "=" * 60)
    print("DATASET VALIDATION REPORT")
    print("=" * 60)

    file_result = (
        validation_result["file_result"]
    )

    column_result = (
        validation_result["column_result"]
    )

    quality_result = (
        validation_result["quality_result"]
    )

    # --------------------------------------------------------
    # File Status
    # --------------------------------------------------------

    print("\nFILE STATUS")

    print(
        "File exists:",
        "YES"
        if file_result["file_exists"]
        else "NO"
    )

    print(
        "File readable:",
        "YES"
        if file_result["readable"]
        else "NO"
    )

    print(
        "Contains data:",
        "YES"
        if file_result["has_data"]
        else "NO"
    )

    # --------------------------------------------------------
    # Stop if file validation failed
    # --------------------------------------------------------

    if column_result is None:

        print(
            "\nSTATUS: INVALID DATASET"
        )

        for error in file_result[
            "errors"
        ]:

            print(
                "ERROR:",
                error
            )

        return

    df = validation_result["data"]

    # --------------------------------------------------------
    # Dataset Information
    # --------------------------------------------------------

    print("\nDATASET INFORMATION")

    print(
        "Rows:",
        len(df)
    )

    print(
        "Columns:",
        len(df.columns)
    )

    # --------------------------------------------------------
    # Core Columns
    # --------------------------------------------------------

    print("\nCORE COLUMNS")

    if column_result[
        "missing_core"
    ]:

        print(
            "Missing core columns:"
        )

        for column in column_result[
            "missing_core"
        ]:

            print(
                "  MISSING:",
                column
            )

    else:

        print(
            "All core columns available."
        )

    # --------------------------------------------------------
    # Optional Columns
    # --------------------------------------------------------

    print("\nOPTIONAL COLUMNS")

    if column_result[
        "available_optional"
    ]:

        for column in column_result[
            "available_optional"
        ]:

            print(
                "  AVAILABLE:",
                column
            )

    else:

        print(
            "  None available."
        )

    # --------------------------------------------------------
    # Evaluation Columns
    # --------------------------------------------------------

    print("\nEVALUATION COLUMNS")

    if column_result[
        "available_evaluation"
    ]:

        for column in column_result[
            "available_evaluation"
        ]:

            print(
                "  AVAILABLE:",
                column
            )

    else:

        print(
            "  None available."
        )

        print(
            "  Dataset can still be used "
            "for unsupervised clustering."
        )

    # --------------------------------------------------------
    # Unknown Columns
    # --------------------------------------------------------

    print("\nADDITIONAL DATASET COLUMNS")

    if column_result[
        "unknown_columns"
    ]:

        for column in column_result[
            "unknown_columns"
        ]:

            print(
                "  ",
                column
            )

    else:

        print(
            "  None."
        )

    # --------------------------------------------------------
    # Data Quality
    # --------------------------------------------------------

    print("\nDATA QUALITY")

    if quality_result[
        "errors"
    ]:

        for error in quality_result[
            "errors"
        ]:

            print(
                "ERROR:",
                error
            )

    else:

        print(
            "Critical data-quality checks: PASSED"
        )

    if quality_result[
        "warnings"
    ]:

        print(
            "\nWARNINGS:"
        )

        for warning in quality_result[
            "warnings"
        ]:

            print(
                "  WARNING:",
                warning
            )

    # --------------------------------------------------------
    # Final Status
    # --------------------------------------------------------

    print("\n" + "-" * 60)

    if validation_result["valid"]:

        print(
            "STATUS: DATASET IS COMPATIBLE"
        )

    else:

        print(
            "STATUS: DATASET IS NOT COMPATIBLE"
        )

    print("-" * 60)