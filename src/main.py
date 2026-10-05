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


# detect_column_mapping() expects the complete DataFrame.

mapping = detect_column_mapping(
    raw_df
)


# print_mapping_report() expects the DataFrame
# and the detected mapping.

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
# 18. DETAILED THREAT REPORT
# ============================================================

detailed_report = (
    create_detailed_threat_report(
        threat_pattern_library,
        behavior_summary
    )
)


# ============================================================
# 19. SAVE OUTPUTS
# ============================================================

print("\n" + "-" * 60)
print("STEP 8: SAVING OUTPUTS")
print("-" * 60)


threat_pattern_library.to_csv(
    os.path.join(
        OUTPUT_PATH,
        "threat_pattern_library.csv"
    ),
    index=False
)


detailed_report.to_csv(
    os.path.join(
        OUTPUT_PATH,
        "detailed_threat_pattern_report.csv"
    ),
    index=False
)


recurrence.to_csv(
    os.path.join(
        OUTPUT_PATH,
        "monthly_recurrence.csv"
    )
)


monthly_attack_table.to_csv(
    os.path.join(
        OUTPUT_PATH,
        "monthly_attack_table.csv"
    )
)


# ============================================================
# 20. PROJECT SUMMARY
# ============================================================

summary_data = {
    "total_logs": len(df_processed),
    "total_clusters": number_of_clusters,
    "noise_points": noise_count,
    "recurring_clusters": len(recurring_clusters),
    "clustering_features": X.shape[1]
}


# ============================================================
# 21. ADD LABEL-BASED INFORMATION IF AVAILABLE
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
# 22. SAVE PROJECT SUMMARY
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
# 23. SAVE PROCESSED DATASET
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
# 24. FINAL SUMMARY
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

print("=" * 60)