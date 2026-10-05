# ============================================================
# Cybersecurity Dataset Schema Mapper
# ============================================================

import pandas as pd


# ============================================================
# Standard Column Names
# ============================================================

STANDARD_COLUMNS = [
    "timestamp",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
    "bytes_sent",
    "bytes_received",
    "user_agent",
    "url",
    "is_internal_traffic",
    "label",
    "attack_type"
]


# ============================================================
# Possible Dataset Column Names
# ============================================================

COLUMN_ALIASES = {

    "timestamp": [
        "timestamp",
        "time",
        "datetime",
        "date_time",
        "event_time",
        "event_timestamp"
    ],

    "src_ip": [
        "src_ip",
        "source_ip",
        "sourceip",
        "src_address",
        "source_address",
        "src_addr"
    ],

    "dst_ip": [
        "dst_ip",
        "destination_ip",
        "destinationip",
        "dst_address",
        "destination_address",
        "dst_addr"
    ],

    "src_port": [
        "src_port",
        "source_port",
        "sourceport",
        "src_port_number"
    ],

    "dst_port": [
        "dst_port",
        "destination_port",
        "destinationport",
        "dest_port",
        "dst_port_number"
    ],

    "protocol": [
        "protocol",
        "network_protocol",
        "protocol_type"
    ],

    "bytes_sent": [
        "bytes_sent",
        "sent_bytes",
        "bytes_out",
        "outgoing_bytes",
        "upload_bytes"
    ],

    "bytes_received": [
        "bytes_received",
        "received_bytes",
        "bytes_in",
        "incoming_bytes",
        "download_bytes"
    ],

    "user_agent": [
        "user_agent",
        "useragent",
        "http_user_agent",
        "browser"
    ],

    "url": [
        "url",
        "uri",
        "request_url",
        "request_uri",
        "http_url",
        "web_url"
    ],

    "is_internal_traffic": [
        "is_internal_traffic",
        "internal_traffic",
        "is_internal",
        "internal",
        "internal_flag"
    ],

    "label": [
        "label",
        "target",
        "class",
        "attack_label",
        "is_attack"
    ],

    "attack_type": [
        "attack_type",
        "attack",
        "attack_category",
        "attack_class",
        "threat_type"
    ]
}


# ============================================================
# Normalize Column Name
# ============================================================

def normalize_column_name(column_name):
    """
    Convert a column name into a standard
    comparison format.
    """

    return (
        str(column_name)
        .strip()
        .lower()
        .replace(" ", "_")
        .replace("-", "_")
    )


# ============================================================
# Build Alias Lookup
# ============================================================

def build_alias_lookup():
    """
    Create a lookup table where every known
    alias points to its standard column name.
    """

    alias_lookup = {}

    for standard_name, aliases in COLUMN_ALIASES.items():

        for alias in aliases:

            normalized_alias = (
                normalize_column_name(alias)
            )

            alias_lookup[
                normalized_alias
            ] = standard_name

    return alias_lookup


# ============================================================
# Detect Column Mapping
# ============================================================

def detect_column_mapping(df):
    """
    Detect which dataset columns correspond
    to the project's standard column names.
    """

    alias_lookup = build_alias_lookup()

    mapping = {}

    for column in df.columns:

        normalized_column = (
            normalize_column_name(column)
        )

        if normalized_column in alias_lookup:

            standard_name = (
                alias_lookup[
                    normalized_column
                ]
            )

            mapping[column] = standard_name

    return mapping


# ============================================================
# Check Mapping Conflicts
# ============================================================

def find_mapping_conflicts(mapping):
    """
    Detect cases where multiple source columns
    map to the same standard column.
    """

    reverse_mapping = {}

    for source_column, standard_column in mapping.items():

        reverse_mapping.setdefault(
            standard_column,
            []
        ).append(source_column)

    conflicts = {
        standard_column: source_columns
        for standard_column, source_columns
        in reverse_mapping.items()
        if len(source_columns) > 1
    }

    return conflicts


# ============================================================
# Apply Column Mapping
# ============================================================

def apply_column_mapping(df, mapping):
    """
    Rename detected columns to the project's
    standard schema.
    """

    conflicts = find_mapping_conflicts(
        mapping
    )

    if conflicts:

        raise ValueError(
            "Column mapping conflict detected: "
            f"{conflicts}"
        )

    renamed_df = df.rename(
        columns=mapping
    )

    return renamed_df


# ============================================================
# Get Mapping Summary
# ============================================================

def get_mapping_summary(
    df,
    mapping
):
    """
    Create a summary showing mapped and
    unmapped columns.
    """

    mapped_columns = list(
        mapping.keys()
    )

    unmapped_columns = [
        column
        for column in df.columns
        if column not in mapped_columns
    ]

    detected_standard_columns = list(
        mapping.values()
    )

    missing_standard_columns = [
        column
        for column in STANDARD_COLUMNS
        if column not in detected_standard_columns
    ]

    return {
        "mapped_columns": mapped_columns,
        "unmapped_columns": unmapped_columns,
        "missing_standard_columns":
            missing_standard_columns
    }


# ============================================================
# Print Mapping Report
# ============================================================

def print_mapping_report(
    df,
    mapping
):
    """
    Display a readable schema mapping report.
    """

    summary = get_mapping_summary(
        df,
        mapping
    )

    print("\n" + "=" * 60)
    print("DATASET COLUMN MAPPING REPORT")
    print("=" * 60)

    print("\nDETECTED COLUMN MAPPINGS")

    if mapping:

        for source, standard in mapping.items():

            if source == standard:

                print(
                    f"  {source} -> {standard}"
                )

            else:

                print(
                    f"  {source} -> {standard}"
                )

    else:

        print(
            "  No recognized columns found."
        )

    print("\nUNMAPPED DATASET COLUMNS")

    if summary["unmapped_columns"]:

        for column in summary[
            "unmapped_columns"
        ]:

            print(
                f"  {column}"
            )

    else:

        print(
            "  None"
        )

    print(
        "\nSTANDARD COLUMNS NOT FOUND"
    )

    if summary[
        "missing_standard_columns"
    ]:

        for column in summary[
            "missing_standard_columns"
        ]:

            print(
                f"  MISSING: {column}"
            )

    else:

        print(
            "  None"
        )

    print("\n" + "-" * 60)

    if not summary[
        "missing_standard_columns"
    ]:

        print(
            "STATUS: FULL STANDARD SCHEMA DETECTED"
        )

    else:

        print(
            "STATUS: PARTIAL STANDARD SCHEMA"
        )

    print("-" * 60)