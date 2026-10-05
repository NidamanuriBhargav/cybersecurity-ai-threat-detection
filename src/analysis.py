# ============================================================
# Cybersecurity Threat Pattern Analysis
# ============================================================

import pandas as pd


# ------------------------------------------------------------
# 1. Add month column
# ------------------------------------------------------------

def add_month_column(df):
    """
    Add a month column based on the timestamp.

    Example:
    2025-10-15 → 2025-10
    """

    df = df.copy()

    df["month"] = df["timestamp"].dt.to_period("M")

    return df


# ------------------------------------------------------------
# 2. Check whether evaluation columns are available
# ------------------------------------------------------------

def has_evaluation_columns(df):
    """
    Check whether the dataset contains both:
    - label
    - attack_type

    These columns are optional because the project
    uses unsupervised clustering.
    """

    return (
        "label" in df.columns
        and "attack_type" in df.columns
    )


# ------------------------------------------------------------
# 3. Create monthly attack table
# ------------------------------------------------------------

def create_monthly_attack_table(df):
    """
    Create a monthly attack table.

    If label and attack_type are unavailable,
    return an empty DataFrame instead of failing.
    """

    if not has_evaluation_columns(df):
        return pd.DataFrame()

    if "final_cluster" not in df.columns:
        return pd.DataFrame()

    monthly_attack_types = pd.crosstab(
        [df["month"], df["final_cluster"]],
        df["attack_type"]
    )

    return monthly_attack_types


# ------------------------------------------------------------
# 4. Calculate recurrence
# ------------------------------------------------------------

def calculate_recurrence(monthly_attack_types):
    """
    Calculate how many months each cluster
    shows attack activity.
    """

    if monthly_attack_types.empty:
        return pd.DataFrame()

    attack_only_monthly = monthly_attack_types.drop(
        columns="benign",
        errors="ignore"
    )

    monthly_presence = attack_only_monthly.gt(0)

    recurrence = monthly_presence.groupby(
        level="final_cluster"
    ).sum()

    return recurrence


# ------------------------------------------------------------
# 5. Identify recurring attack patterns
# ------------------------------------------------------------

def identify_recurring_patterns(
    df,
    minimum_attacks=3,
    minimum_months=2
):
    """
    Identify attack types that repeatedly appear
    in the same cluster across multiple months.

    This analysis is available only when
    label and attack_type are present.
    """

    if not has_evaluation_columns(df):
        return pd.DataFrame(
            columns=[
                "final_cluster",
                "attack_type",
                "total_attacks",
                "months_present"
            ]
        )

    if "final_cluster" not in df.columns:
        return pd.DataFrame(
            columns=[
                "final_cluster",
                "attack_type",
                "total_attacks",
                "months_present"
            ]
        )

    attack_data = df[
        (df["label"] == 1)
        & (df["final_cluster"] != -1)
    ].copy()

    if attack_data.empty:
        return pd.DataFrame(
            columns=[
                "final_cluster",
                "attack_type",
                "total_attacks",
                "months_present"
            ]
        )

    # Total attacks by cluster and attack type
    attack_counts = (
        attack_data
        .groupby(
            ["final_cluster", "attack_type"]
        )
        .size()
        .reset_index(name="total_attacks")
    )

    # Monthly attack counts
    monthly_counts = (
        attack_data
        .groupby(
            [
                "final_cluster",
                "attack_type",
                "month"
            ]
        )
        .size()
        .reset_index(name="monthly_attacks")
    )

    # Number of months in which the pattern appeared
    months_present = (
        monthly_counts
        .groupby(
            [
                "final_cluster",
                "attack_type"
            ]
        )
        .size()
        .reset_index(name="months_present")
    )

    recurring_patterns = attack_counts.merge(
        months_present,
        on=[
            "final_cluster",
            "attack_type"
        ],
        how="left"
    )

    recurring_patterns = recurring_patterns[
        (recurring_patterns["total_attacks"] >= minimum_attacks)
        &
        (recurring_patterns["months_present"] >= minimum_months)
    ]

    return recurring_patterns


# ------------------------------------------------------------
# 6. Create threat pattern library
# ------------------------------------------------------------

def create_threat_pattern_library(recurring_patterns):
    """
    Convert recurring attack patterns into a compact
    threat pattern library.
    """

    if recurring_patterns.empty:
        return pd.DataFrame(
            columns=[
                "final_cluster",
                "recurring_attack_types",
                "total_recurring_attacks",
                "recurring_pattern_count",
                "max_months_present"
            ]
        )

    threat_pattern_library = (
        recurring_patterns
        .groupby("final_cluster")
        .agg(
            recurring_attack_types=(
                "attack_type",
                lambda x: ", ".join(x)
            ),
            total_recurring_attacks=(
                "total_attacks",
                "sum"
            ),
            recurring_pattern_count=(
                "attack_type",
                "count"
            ),
            max_months_present=(
                "months_present",
                "max"
            )
        )
        .reset_index()
        .sort_values(
            "total_recurring_attacks",
            ascending=False
        )
    )

    return threat_pattern_library


# ------------------------------------------------------------
# 7. Create behavioral profile
# ------------------------------------------------------------

def create_behavior_profile(
    df,
    recurring_clusters
):
    """
    Calculate average behavioral characteristics
    for recurring clusters.

    This function does not require label or attack_type.
    """

    behavior_features = [
        "src_port",
        "dst_port",
        "bytes_sent",
        "bytes_received",
        "bytes_ratio",
        "internal_code",
        "url_length",
        "has_sensitive_keyword",
        "is_browser",
        "hour",
        "day_of_week"
    ]

    available_features = [
        feature
        for feature in behavior_features
        if feature in df.columns
    ]

    if (
        "final_cluster" not in df.columns
        or not recurring_clusters
        or not available_features
    ):
        return pd.DataFrame()

    behavior_profile = (
        df[
            df["final_cluster"].isin(
                recurring_clusters
            )
        ]
        .groupby("final_cluster")[
            available_features
        ]
        .mean()
    )

    return behavior_profile


# ------------------------------------------------------------
# 8. Create URL behavior profile
# ------------------------------------------------------------

def create_url_behavior_profile(
    df,
    recurring_clusters
):
    """
    Analyze URL-related behavior.

    If URL-derived features are unavailable,
    return an empty DataFrame.
    """

    required_features = [
        "url_length",
        "has_sensitive_keyword",
        "is_browser",
        "has_query_params"
    ]

    if "final_cluster" not in df.columns:
        return pd.DataFrame()

    if not all(
        feature in df.columns
        for feature in required_features
    ):
        return pd.DataFrame()

    if not recurring_clusters:
        return pd.DataFrame()

    url_behavior_profile = (
        df[
            df["final_cluster"].isin(
                recurring_clusters
            )
        ]
        .groupby("final_cluster")
        .agg(
            avg_url_length=(
                "url_length",
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
            records_with_query_params=(
                "has_query_params",
                "mean"
            )
        )
    )

    return url_behavior_profile


# ------------------------------------------------------------
# 9. Combine behavioral profiles
# ------------------------------------------------------------

def create_behavior_summary(
    behavior_profile,
    url_behavior_profile
):
    """
    Combine network behavior and URL behavior
    into one summary table.
    """

    if behavior_profile.empty:
        if url_behavior_profile.empty:
            return pd.DataFrame()

        return url_behavior_profile.reset_index()

    if url_behavior_profile.empty:
        return behavior_profile.reset_index()

    behavior_summary = behavior_profile.join(
        url_behavior_profile,
        how="left"
    ).reset_index()

    return behavior_summary


# ------------------------------------------------------------
# 10. Create detailed threat report
# ------------------------------------------------------------

def create_detailed_threat_report(
    threat_pattern_library,
    behavior_summary
):
    """
    Combine the threat pattern library with
    behavioral characteristics.
    """

    if threat_pattern_library.empty:
        return pd.DataFrame()

    if behavior_summary.empty:
        return threat_pattern_library.copy()

    detailed_report = threat_pattern_library.merge(
        behavior_summary,
        on="final_cluster",
        how="left"
    )

    return detailed_report