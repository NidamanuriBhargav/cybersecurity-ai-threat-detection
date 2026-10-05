import pandas as pd

from schema_mapper import (
    detect_column_mapping,
    apply_column_mapping,
    print_mapping_report
)


# ============================================================
# Create a Temporary Dataset with Different Column Names
# ============================================================

test_data = pd.DataFrame({
    "Time": [
        "2025-10-01 10:00:00",
        "2025-10-01 11:00:00"
    ],

    "Source_IP": [
        "192.168.1.10",
        "192.168.1.20"
    ],

    "Destination_IP": [
        "10.0.0.5",
        "10.0.0.10"
    ],

    "Source_Port": [
        45000,
        45001
    ],

    "Destination_Port": [
        443,
        22
    ],

    "Protocol_Type": [
        "TCP",
        "TCP"
    ],

    "Sent_Bytes": [
        1200,
        2500
    ],

    "Received_Bytes": [
        3500,
        5000
    ],

    "UserAgent": [
        "Mozilla/5.0",
        "Chrome"
    ],

    "Request_URL": [
        "https://example.com/login",
        "https://example.com/admin"
    ],

    "Internal": [
        True,
        False
    ],

    "Attack_Label": [
        0,
        1
    ],

    "Attack_Category": [
        "benign",
        "brute-force"
    ]
})


# ============================================================
# Display Original Columns
# ============================================================

print(
    "\nOriginal temporary dataset columns:"
)

print(
    test_data.columns.tolist()
)


# ============================================================
# Detect Column Mapping
# ============================================================

mapping = detect_column_mapping(
    test_data
)


# ============================================================
# Display Mapping Report
# ============================================================

print_mapping_report(
    test_data,
    mapping
)


# ============================================================
# Apply Column Mapping
# ============================================================

mapped_df = apply_column_mapping(
    test_data,
    mapping
)


# ============================================================
# Display Standardized Columns
# ============================================================

print(
    "\nStandardized dataset columns:"
)

print(
    mapped_df.columns.tolist()
)


# ============================================================
# Display Standardized Dataset
# ============================================================

print(
    "\nStandardized dataset:"
)

print(
    mapped_df
)