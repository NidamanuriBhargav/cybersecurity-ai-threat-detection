# ============================================================
# Cybersecurity Threat Detection Pipeline
# ============================================================

import os
import pandas as pd


from validator import (
    validate_dataset,
    print_validation_report
)


from schema_mapper import (
    detect_column_mapping,
    find_mapping_conflicts,
    apply_column_mapping,
    print_mapping_report
)


from preprocessing import (
    engineer_features
)


from clustering import (
    prepare_clustering_features,
    scale_features,
    apply_dbscan
)


from analysis import (
    add_month_column,
    create_monthly_attack_table,
    calculate_recurrence,
    identify_recurring_patterns,
    create_threat_pattern_library,
    create_behavior_profile,
    create_url_behavior_profile,
    create_behavior_summary,
    create_detailed_threat_report
)


# ============================================================
# 1. PROJECT PATHS
# ============================================================

PROJECT_ROOT = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)


DATA_PATH = os.path.join(
    PROJECT_ROOT,
    "data",
    "raw",
    "cybersecurity.csv"
)


OUTPUT_PATH = os.path.join(
    PROJECT_ROOT,
    "outputs",
    "reports"
)


PROCESSED_PATH = os.path.join(
    PROJECT_ROOT,
    "data",
    "processed"
)


os.makedirs(
    OUTPUT_PATH,
    exist_ok=True
)


os.makedirs(
    PROCESSED_PATH,
    exist_ok=True
)


# ============================================================
# 2. START PIPELINE
# ============================================================

print("\n" + "=" * 60)
print("CYBERSECURITY THREAT DETECTION PIPELINE")
print("=" * 60)


# ============================================================
# 3. LOAD RAW DATASET
# ============================================================

print("\nLoading raw dataset...")


try:

    raw_df = pd.read_csv(
        DATA_PATH
    )

except Exception as error:

    print("\nERROR: Could not load dataset.")
    print(error)

    raise SystemExit(1)


print(
    f"Raw dataset loaded: "
    f"{len(raw_df)} rows, "
    f"{len(raw_df.columns)} columns"
)


# ============================================================
# 4. SCHEMA DETECTION
# ============================================================

print("\n" + "-" * 60)
print("STEP 1: SCHEMA DETECTION")
print("-" * 60)


mapping = detect_column_mapping(
    raw_df
)


print_mapping_report(
    raw_df,
    mapping
)


# ============================================================
# 5. CHECK SCHEMA MAPPING CONFLICTS
# ============================================================

conflicts = find_mapping_conflicts(
    mapping
)


if conflicts:

    print(
        "\nERROR: Schema mapping conflicts detected."
    )

    for conflict in conflicts:

        print(
            "  ",
            conflict
        )

    raise SystemExit(1)


# ============================================================
# 6. APPLY STANDARD COLUMN NAMES
# ============================================================

standardized_df = apply_column_mapping(
    raw_df,
    mapping
)


print(
    "\nStandardized dataset columns:"
)


print(
    standardized_df.columns.tolist()
)


# ============================================================
# 7. SAVE STANDARDIZED TEMPORARY DATASET
# ============================================================

temporary_validation_path = os.path.join(
    PROCESSED_PATH,
    "_standardized_validation_dataset.csv"
)


standardized_df.to_csv(
    temporary_validation_path,
    index=False
)


# ============================================================
# 8. DATASET VALIDATION
# ============================================================

print("\n" + "-" * 60)
print("STEP 2: DATASET VALIDATION")
print("-" * 60)


validation_result = validate_dataset(
    temporary_validation_path
)


print_validation_report(
    validation_result
)


if not validation_result["valid"]:

    print(
        "\nPipeline stopped because "
        "dataset validation failed."
    )

    raise SystemExit(1)


df = validation_result["data"]


# ============================================================
# 9. FEATURE ENGINEERING
# ============================================================

print("\n" + "-" * 60)
print("STEP 3: FEATURE ENGINEERING")
print("-" * 60)


df_processed = engineer_features(
    df
)


print(
    f"Processed dataset: "
    f"{len(df_processed)} rows, "
    f"{len(df_processed.columns)} columns"
)


# ============================================================
# 10. PREPARE CLUSTERING FEATURES
# ============================================================

print("\n" + "-" * 60)
print("STEP 4: CLUSTERING FEATURE PREPARATION")
print("-" * 60)


X = prepare_clustering_features(
    df_processed
)


print(
    f"Clustering matrix: "
    f"{X.shape[0]} rows × "
    f"{X.shape[1]} features"
)


print(
    "\nClustering features:"
)


print(
    X.columns.tolist()
)


# ============================================================
# 11. FEATURE SCALING
# ============================================================

print("\n" + "-" * 60)
print("STEP 5: FEATURE SCALING")
print("-" * 60)


X_scaled, scaler = scale_features(
    X
)


print(
    f"Scaled feature matrix: "
    f"{X_scaled.shape}"
)


# ============================================================
# 12. DBSCAN CLUSTERING
# ============================================================

print("\n" + "-" * 60)
print("STEP 6: DBSCAN CLUSTERING")
print("-" * 60)


cluster_labels, dbscan_model = apply_dbscan(
    X_scaled,
    eps=2.1,
    min_samples=10
)


df_processed["final_cluster"] = (
    cluster_labels
)


number_of_clusters = len(
    set(cluster_labels) - {-1}
)


noise_count = (
    cluster_labels == -1
).sum()


print(
    f"Clusters discovered: "
    f"{number_of_clusters}"
)


print(
    f"Noise points: "
    f"{noise_count}"
)


# ============================================================
# 13. ADD MONTH INFORMATION
# ============================================================

df_processed = add_month_column(
    df_processed
)


# ============================================================
# 14. THREAT PATTERN ANALYSIS
# ============================================================

print("\n" + "-" * 60)
print("STEP 7: THREAT PATTERN ANALYSIS")
print("-" * 60)


monthly_attack_table = (
    create_monthly_attack_table(
        df_processed
    )
)


recurrence = calculate_recurrence(
    monthly_attack_table
)


recurring_patterns = (
    identify_recurring_patterns(
        df_processed,
        minimum_attacks=3,
        minimum_months=2
    )
)


# ============================================================
# 15. CREATE THREAT PATTERN LIBRARY
# ============================================================

threat_pattern_library = (
    create_threat_pattern_library(
        recurring_patterns
    )
)


# ============================================================
# 16. DETERMINE RECURRING CLUSTERS
# ============================================================

if not threat_pattern_library.empty:

    recurring_clusters = (
        threat_pattern_library[
            "final_cluster"
        ].tolist()
    )

else:

    recurring_clusters = []


print(
    f"Recurring clusters: "
    f"{len(recurring_clusters)}"
)


# ============================================================
# 17. BEHAVIORAL ANALYSIS
# ============================================================

behavior_profile = (
    create_behavior_profile(
        df_processed,
        recurring_clusters
    )
)


url_behavior_profile = (
    create_url_behavior_profile(
        df_processed,
        recurring_clusters
    )
)


behavior_summary = (
    create_behavior_summary(
        behavior_profile,
        url_behavior_profile
    )
)


# ============================================================
# 18. CREATE FINAL THREAT PATTERN LIBRARY
# ============================================================

print(
    "\nCreating final threat pattern library..."
)


if not threat_pattern_library.empty:

    # --------------------------------------------------------
    # Calculate behavioral metrics directly from the
    # processed attack records.
    #
    # We do this here instead of depending on specific column
    # names returned by create_behavior_profile().
    # --------------------------------------------------------

    if (
        "label" in df_processed.columns
        and "attack_type" in df_processed.columns
    ):

        behavior_data = df_processed[
            df_processed["final_cluster"].isin(
                recurring_clusters
            )
            &
            (df_processed["label"] == 1)
        ].copy()

    else:

        behavior_data = df_processed[
            df_processed["final_cluster"].isin(
                recurring_clusters
            )
        ].copy()


    if not behavior_data.empty:

        behavior_metrics = (
            behavior_data
            .groupby("final_cluster")
            .agg(
                attack_records=(
                    "final_cluster",
                    "size"
                ),

                avg_bytes_sent=(
                    "bytes_sent",
                    "mean"
                ),

                avg_bytes_received=(
                    "bytes_received",
                    "mean"
                ),

                avg_bytes_ratio=(
                    "bytes_ratio",
                    "mean"
                ),

                internal_traffic_rate=(
                    "internal_code",
                    "mean"
                ),

                sensitive_url_rate=(
                    "has_sensitive_keyword",
                    "mean"
                ),

                browser_rate=(
                    "is_browser",
                    "mean"
                ),

                query_parameter_rate=(
                    "has_query_params",
                    "mean"
                )
            )
            .reset_index()
        )

    else:

        behavior_metrics = pd.DataFrame(
            columns=[
                "final_cluster",
                "attack_records",
                "avg_bytes_sent",
                "avg_bytes_received",
                "avg_bytes_ratio",
                "internal_traffic_rate",
                "sensitive_url_rate",
                "browser_rate",
                "query_parameter_rate"
            ]
        )


    # --------------------------------------------------------
    # Create human-readable behavioral indicators.
    # --------------------------------------------------------

    indicators_list = []


    if not behavior_metrics.empty:

        median_sent = (
            behavior_metrics[
                "avg_bytes_sent"
            ].median()
        )


        median_received = (
            behavior_metrics[
                "avg_bytes_received"
            ].median()
        )


        for _, row in behavior_metrics.iterrows():

            indicators = []


            if (
                row["sensitive_url_rate"]
                >= 0.75
            ):

                indicators.append(
                    "High sensitive-URL activity"
                )


            if (
                row["query_parameter_rate"]
                >= 0.75
            ):

                indicators.append(
                    "High query-parameter activity"
                )


            if (
                row["browser_rate"]
                >= 0.75
            ):

                indicators.append(
                    "Browser-based traffic"
                )


            if (
                row["internal_traffic_rate"]
                >= 0.75
            ):

                indicators.append(
                    "Internal traffic"
                )


            if (
                row["internal_traffic_rate"]
                <= 0.25
            ):

                indicators.append(
                    "External traffic"
                )


            if (
                row["avg_bytes_received"]
                > median_received
            ):

                indicators.append(
                    "Higher received traffic"
                )


            if (
                row["avg_bytes_sent"]
                > median_sent
            ):

                indicators.append(
                    "Higher sent traffic"
                )


            indicators_list.append(
                {
                    "final_cluster":
                        row["final_cluster"],

                    "indicators":
                        ", ".join(indicators)
                }
            )


    indicators_df = pd.DataFrame(
        indicators_list
    )


    # --------------------------------------------------------
    # Human-readable names for the recurring patterns.
    # --------------------------------------------------------

    pattern_names = {

        2:
            "Recurring Multi-Type External Browser Threat",

        3:
            "Recurring High-Volume External Threat",

        0:
            "External Web Request Attack Pattern",

        9:
            "External Non-Browser Web Attack Pattern",

        5:
            "Recurring High-Volume Browser Threat",

        4:
            "Internal Browser Threat Pattern",

        15:
            "Internal High-Volume Threat Pattern",

        10:
            "External Browser Web Threat Pattern",

        1:
            "Recurring External Network Threat",

        7:
            "Internal Browser Web Attack Pattern"
    }


    pattern_name_df = pd.DataFrame(
        [
            {
                "final_cluster": cluster_id,
                "pattern_name": pattern_names.get(
                    cluster_id,
                    "Recurring Threat Pattern"
                )
            }

            for cluster_id
            in recurring_clusters
        ]
    )


    # --------------------------------------------------------
    # Combine the recurrence information with behavioral
    # metrics, indicators and human-readable names.
    # --------------------------------------------------------

    final_threat_pattern_library = (
        threat_pattern_library.copy()
    )


    final_threat_pattern_library = (
        final_threat_pattern_library
        .merge(
            pattern_name_df,
            on="final_cluster",
            how="left"
        )
    )


    if not behavior_metrics.empty:

        final_threat_pattern_library = (
            final_threat_pattern_library
            .merge(
                behavior_metrics[
                    [
                        "final_cluster",
                        "attack_records",
                        "avg_bytes_sent",
                        "avg_bytes_received",
                        "avg_bytes_ratio",
                        "internal_traffic_rate",
                        "sensitive_url_rate",
                        "browser_rate",
                        "query_parameter_rate"
                    ]
                ],
                on="final_cluster",
                how="left"
            )
        )


    if not indicators_df.empty:

        final_threat_pattern_library = (
            final_threat_pattern_library
            .merge(
                indicators_df,
                on="final_cluster",
                how="left"
            )
        )


    # --------------------------------------------------------
    # Reorder columns for a clean final report.
    # --------------------------------------------------------

    preferred_columns = [

        "final_cluster",

        "pattern_name",

        "recurring_attack_types",

        "total_recurring_attacks",

        "recurring_pattern_count",

        "max_months_present",

        "indicators",

        "attack_records",

        "avg_bytes_sent",

        "avg_bytes_received",

        "avg_bytes_ratio",

        "internal_traffic_rate",

        "sensitive_url_rate",

        "browser_rate",

        "query_parameter_rate"
    ]


    available_columns = [
        column
        for column in preferred_columns
        if column in final_threat_pattern_library.columns
    ]


    final_threat_pattern_library = (
        final_threat_pattern_library[
            available_columns
        ]
        .sort_values(
            "total_recurring_attacks",
            ascending=False
        )
        .reset_index(drop=True)
    )


else:

    final_threat_pattern_library = (
        threat_pattern_library.copy()
    )


# ============================================================
# 19. DETAILED THREAT REPORT
# ============================================================

detailed_report = (
    create_detailed_threat_report(
        threat_pattern_library,
        behavior_summary
    )
)


# ============================================================
# 20. SAVE OUTPUTS
# ============================================================

print("\n" + "-" * 60)
print("STEP 8: SAVING OUTPUTS")
print("-" * 60)


# ------------------------------------------------------------
# Original threat pattern library
# ------------------------------------------------------------

threat_pattern_library.to_csv(
    os.path.join(
        OUTPUT_PATH,
        "threat_pattern_library.csv"
    ),
    index=False
)


# ------------------------------------------------------------
# Final enriched threat pattern library
# ------------------------------------------------------------

final_threat_pattern_library.to_csv(
    os.path.join(
        OUTPUT_PATH,
        "final_threat_pattern_library.csv"
    ),
    index=False
)


# ------------------------------------------------------------
# Detailed threat report
# ------------------------------------------------------------

detailed_report.to_csv(
    os.path.join(
        OUTPUT_PATH,
        "detailed_threat_pattern_report.csv"
    ),
    index=False
)


# ------------------------------------------------------------
# Monthly recurrence
# ------------------------------------------------------------

recurrence.to_csv(
    os.path.join(
        OUTPUT_PATH,
        "monthly_recurrence.csv"
    ),
    index=False
)


# ------------------------------------------------------------
# Monthly attack table
# ------------------------------------------------------------

monthly_attack_table.reset_index().to_csv(
    os.path.join(
        OUTPUT_PATH,
        "monthly_attack_table.csv"
    ),
    index=False
)

# ============================================================
# 20A. MONTHLY ATTACK PROFILE
# ============================================================

if (
    "label" in df_processed.columns
    and
    "attack_type" in df_processed.columns
):

    monthly_attack_profile = (
        df_processed[
            df_processed["label"] == 1
        ]
        .groupby(
            ["month", "attack_type"]
        )
        .size()
        .reset_index(
            name="attack_count"
        )
    )

    monthly_totals = (
        monthly_attack_profile
        .groupby("month")["attack_count"]
        .sum()
        .reset_index(
            name="total_month_attacks"
        )
    )

    monthly_attack_profile = (
        monthly_attack_profile
        .merge(
            monthly_totals,
            on="month",
            how="left"
        )
    )

    monthly_attack_profile[
        "attack_share_pct"
    ] = (
        monthly_attack_profile[
            "attack_count"
        ]
        /
        monthly_attack_profile[
            "total_month_attacks"
        ]
        * 100
    ).round(2)

    monthly_attack_profile = (
        monthly_attack_profile
        .sort_values(
            [
                "month",
                "attack_count"
            ],
            ascending=[
                True,
                False
            ]
        )
        .reset_index(
            drop=True
        )
    )

    monthly_attack_profile.to_csv(
        os.path.join(
            OUTPUT_PATH,
            "monthly_attack_profile.csv"
        ),
        index=False
    )


# ============================================================
# 21. PROJECT SUMMARY
# ============================================================

summary_data = {

    "total_logs":
        len(df_processed),

    "total_clusters":
        number_of_clusters,

    "noise_points":
        noise_count,

    "recurring_clusters":
        len(recurring_clusters),

    "clustering_features":
        X.shape[1]
}


# ============================================================
# 22. ADD LABEL-BASED INFORMATION IF AVAILABLE
# ============================================================

if (
    "label" in df_processed.columns
    and
    "attack_type" in df_processed.columns
):

    summary_data["total_attacks"] = int(
        (
            df_processed["label"] == 1
        ).sum()
    )


    summary_data["total_benign"] = int(
        (
            df_processed["label"] == 0
        ).sum()
    )


    summary_data[
        "recurring_attack_patterns"
    ] = len(
        recurring_patterns
    )


    summary_data[
        "recurring_attack_types"
    ] = (
        recurring_patterns[
            "attack_type"
        ].nunique()
    )


# ============================================================
# 23. SAVE PROJECT SUMMARY
# ============================================================

project_summary = pd.DataFrame(
    [summary_data]
)


project_summary.to_csv(
    os.path.join(
        OUTPUT_PATH,
        "project_summary.csv"
    ),
    index=False
)


# ============================================================
# 24. SAVE PROCESSED DATASET
# ============================================================

processed_dataset_path = os.path.join(
    PROCESSED_PATH,
    "cybersecurity_processed.csv"
)


df_processed.to_csv(
    processed_dataset_path,
    index=False
)


# ============================================================
# 25. FINAL SUMMARY
# ============================================================

print("\n" + "=" * 60)
print("PIPELINE COMPLETED SUCCESSFULLY")
print("=" * 60)


print(
    f"Total logs: "
    f"{len(df_processed)}"
)


print(
    f"Clusters discovered: "
    f"{number_of_clusters}"
)


print(
    f"Noise points: "
    f"{noise_count}"
)


print(
    f"Recurring clusters: "
    f"{len(recurring_clusters)}"
)


if (
    "label" in df_processed.columns
    and
    "attack_type" in df_processed.columns
):

    print(
        f"Recurring attack patterns: "
        f"{len(recurring_patterns)}"
    )


    print(
        f"Recurring attack types: "
        f"{recurring_patterns['attack_type'].nunique()}"
    )

else:

    print(
        "Evaluation labels: "
        "Not available"
    )


print(
    "\nReports saved to:"
)


print(
    OUTPUT_PATH
)


print(
    "\nProcessed dataset saved to:"
)


print(
    processed_dataset_path
)


print(
    "\nFinal threat pattern library saved to:"
)


print(
    os.path.join(
        OUTPUT_PATH,
        "final_threat_pattern_library.csv"
    )
)


print("=" * 60)