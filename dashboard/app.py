# ============================================================
# CYBERSECURITY & AI-DRIVEN THREAT DETECTION
# PROFESSIONAL SOC THREAT INTELLIGENCE CENTER
# ============================================================

from pathlib import Path

import pandas as pd
import streamlit as st
import plotly.express as px


# ============================================================
# 1. PROJECT PATHS
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

REPORTS_DIR = PROJECT_ROOT / "outputs" / "reports"
FIGURES_DIR = PROJECT_ROOT / "outputs" / "figures"


# ============================================================
# 2. PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="Cyber Threat Intelligence Center",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)


# ============================================================
# 3. PROFESSIONAL DARK SOC THEME
# ============================================================

st.markdown(
    """
<style>

.stApp {
    background-color: #070b10;
    color: #e6edf3;
}

[data-testid="stHeader"] {
    background-color: #070b10;
}

[data-testid="stToolbar"] {
    background-color: #070b10;
}

.block-container {
    padding-top: 1.5rem;
    padding-bottom: 3rem;
    max-width: 1500px;
}

[data-testid="stMetric"] {
    background:
        linear-gradient(
            145deg,
            #0d151e,
            #111c27
        );

    border: 1px solid #263544;
    border-radius: 12px;
    padding: 18px;

    box-shadow:
        0 6px 20px rgba(0, 0, 0, 0.18);
}

[data-testid="stMetricLabel"] {
    color: #8b9aaa !important;
    font-size: 0.75rem !important;
    text-transform: uppercase;
    letter-spacing: 0.7px;
}

[data-testid="stMetricValue"] {
    color: #f0f6fc !important;
    font-weight: 800;
}

[data-testid="stMetricDelta"] {
    color: #56d364 !important;
}

div[data-baseweb="select"] > div {
    background-color: #0d151e;
    border-color: #263544;
}

[data-testid="stDataFrame"] {
    border: 1px solid #263544;
    border-radius: 10px;
    overflow: hidden;
}

hr {
    border-color: #1d2935;
}

</style>
""",
    unsafe_allow_html=True
)


# ============================================================
# 4. LOAD CSV REPORTS
# ============================================================

@st.cache_data
def load_report(filename):

    file_path = REPORTS_DIR / filename

    if not file_path.exists():
        return None

    return pd.read_csv(file_path)


project_summary = load_report(
    "project_summary.csv"
)

monthly_attack_profile = load_report(
    "monthly_attack_profile.csv"
)

final_patterns = load_report(
    "final_threat_pattern_library.csv"
)

detailed_patterns = load_report(
    "detailed_threat_pattern_report.csv"
)


# ============================================================
# 5. CHECK REQUIRED REPORTS
# ============================================================

required_reports = {
    "project_summary.csv": project_summary,
    "monthly_attack_profile.csv": monthly_attack_profile,
    "final_threat_pattern_library.csv": final_patterns,
    "detailed_threat_pattern_report.csv": detailed_patterns
}

missing_reports = [
    filename
    for filename, dataframe in required_reports.items()
    if dataframe is None
]

if missing_reports:

    st.error(
        "Required project reports are missing."
    )

    for filename in missing_reports:

        st.write(
            f"- {filename}"
        )

    st.stop()


# ============================================================
# 6. READ PROJECT SUMMARY
# ============================================================

# Read project summary values
summary_row = project_summary.iloc[0]

total_logs = int(summary_row["total_logs"])
total_attacks = int(summary_row["total_attacks"])
total_benign = int(summary_row["total_benign"])
total_clusters = int(summary_row["total_clusters"])
noise_points = int(summary_row["noise_points"])
recurring_clusters = int(summary_row["recurring_clusters"])
recurring_attack_types = int(summary_row["recurring_attack_types"])

recurring_attack_patterns = len(final_patterns)
clustering_features = int(summary_row["clustering_features"])


# ============================================================
# 7. DERIVED PROJECT INFORMATION
# ============================================================

attack_rate = (
    total_attacks
    /
    total_logs
    *
    100
)


recurring_attack_patterns = len(
    final_patterns
)


# Your final clustering matrix contains 16 features.
clustering_features = 16


# ============================================================
# 8. MONTHLY SUMMARY
# ============================================================

monthly_summary = (
    monthly_attack_profile
    .groupby("month")
    .agg(
        total_attacks=(
            "attack_count",
            "sum"
        )
    )
    .reset_index()
    .sort_values("month")
)


# ============================================================
# 9. ATTACK TYPE TOTALS
# ============================================================

attack_totals = (
    monthly_attack_profile
    .groupby("attack_type")[
        "attack_count"
    ]
    .sum()
    .sort_values(
        ascending=False
    )
)


# ============================================================
# 10. MAIN HEADER
# ============================================================

st.title(
    "🛡️ CYBERSECURITY THREAT INTELLIGENCE CENTER"
)

st.caption(
    "Network Threat Monitoring  •  Behavioral Detection  •  "
    "Recurring Attack Analysis"
)


status1, status2, status3, status4 = st.columns(4)


with status1:

    st.success(
        "● ANALYSIS ENGINE ONLINE"
    )


with status2:

    st.info(
        "DBSCAN THREAT DETECTION"
    )


with status3:

    st.info(
        "HISTORICAL INTELLIGENCE"
    )


with status4:

    st.warning(
        "DATASET: OCT–DEC 2025"
    )


# ============================================================
# 11. EXECUTIVE KPI OVERVIEW
# ============================================================

st.divider()

st.subheader(
    "THREAT OPERATIONS OVERVIEW"
)


kpi1, kpi2, kpi3, kpi4 = st.columns(4)


with kpi1:

    st.metric(
        "Security Logs",
        f"{total_logs:,}"
    )


with kpi2:

    st.metric(
        "Attack Records",
        f"{total_attacks:,}",
        f"{attack_rate:.1f}% of logs"
    )


with kpi3:

    st.metric(
        "DBSCAN Clusters",
        total_clusters
    )


with kpi4:

    st.metric(
        "Recurring Threat Patterns",
        recurring_clusters
    )


# ============================================================
# 12. SECONDARY KPI ROW
# ============================================================

kpi5, kpi6, kpi7, kpi8 = st.columns(4)


with kpi5:

    st.metric(
        "Benign Records",
        f"{total_benign:,}"
    )


with kpi6:

    st.metric(
        "Noise / Outliers",
        f"{noise_points:,}"
    )


with kpi7:

    st.metric(
        "Recurring Attack Types",
        recurring_attack_types
    )


with kpi8:

    st.metric(
        "Detection Features",
        clustering_features
    )


# ============================================================
# 13. THREAT ACTIVITY TIMELINE
# ============================================================

st.divider()

st.subheader(
    "THREAT ACTIVITY TIMELINE"
)

st.caption(
    "Observed labeled attack activity during the analyzed period."
)


fig_monthly = px.bar(
    monthly_summary,
    x="month",
    y="total_attacks",
    text="total_attacks",
    labels={
        "month": "Month",
        "total_attacks": "Attack Records"
    }
)


fig_monthly.update_traces(
    marker_color="#e5534b",
    textposition="outside"
)


fig_monthly.update_layout(
    height=330,

    paper_bgcolor="#0d151e",

    plot_bgcolor="#0d151e",

    font_color="#e6edf3",

    margin=dict(
        l=30,
        r=30,
        t=30,
        b=30
    ),

    xaxis=dict(
        gridcolor="#263544"
    ),

    yaxis=dict(
        gridcolor="#263544"
    )
)


st.plotly_chart(
    fig_monthly,
    use_container_width=True
)


# ============================================================
# 14. MONTHLY KPI CARDS
# ============================================================

month_columns = st.columns(
    len(monthly_summary)
)


for column, (_, row) in zip(
    month_columns,
    monthly_summary.iterrows()
):

    with column:

        month_name = row[
            "month"
        ]

        attack_count = int(
            row["total_attacks"]
        )

        st.metric(
            month_name,
            f"{attack_count} attacks"
        )


# ============================================================
# 15. ATTACK TYPE + MONTHLY PROFILE
# ============================================================

st.divider()


left_column, right_column = st.columns(
    2
)


# ============================================================
# 15A. ATTACK TYPE ANALYSIS
# ============================================================

with left_column:

    st.subheader(
        "ATTACK TYPE ANALYSIS"
    )

    st.caption(
        "Overall attack concentration across all three months."
    )


    attack_chart_data = (
        attack_totals
        .head(7)
        .sort_values()
        .reset_index()
    )


    attack_chart_data.columns = [
        "attack_type",
        "attack_count"
    ]


    fig_attack = px.bar(
        attack_chart_data,

        x="attack_count",

        y="attack_type",

        orientation="h",

        text="attack_count",

        labels={
            "attack_count": "Attack Count",
            "attack_type": "Attack Type"
        }
    )


    fig_attack.update_traces(
        marker_color="#58a6ff",
        textposition="outside"
    )


    fig_attack.update_layout(
        height=400,

        paper_bgcolor="#0d151e",

        plot_bgcolor="#0d151e",

        font_color="#e6edf3",

        margin=dict(
            l=20,
            r=30,
            t=30,
            b=30
        ),

        xaxis=dict(
            gridcolor="#263544"
        ),

        yaxis=dict(
            gridcolor="#263544"
        )
    )


    st.plotly_chart(
        fig_attack,
        use_container_width=True
    )


# ============================================================
# 15B. MONTHLY THREAT PROFILE
# ============================================================

with right_column:

    st.subheader(
        "MONTHLY THREAT PROFILE"
    )

    st.caption(
        "Attack types with the highest historical share for a selected month."
    )


    selected_month = st.selectbox(
        "Select month",
        monthly_summary[
            "month"
        ].tolist()
    )


    selected_month_data = (
        monthly_attack_profile[
            monthly_attack_profile[
                "month"
            ] == selected_month
        ]
        .sort_values(
            "attack_count",
            ascending=False
        )
        .head(5)
        .copy()
    )


    for _, row in selected_month_data.iterrows():

        attack_type = row[
            "attack_type"
        ]

        attack_count = int(
            row["attack_count"]
        )

        attack_share = float(
            row["attack_share_pct"]
        )


        st.write(
            f"**{attack_type}**"
        )


        st.progress(
            min(
                attack_share / 100,
                1.0
            )
        )


        st.caption(
            f"{attack_count} attacks  •  "
            f"{attack_share:.2f}% historical share"
        )


# ============================================================
# 16. MONTHLY ATTACK-TYPE HEATMAP
# ============================================================

st.divider()

st.subheader(
    "MONTHLY ATTACK-TYPE INTELLIGENCE"
)

st.caption(
    "Historical share of each attack type within each month."
)


monthly_pivot = (
    monthly_attack_profile
    .pivot(
        index="attack_type",
        columns="month",
        values="attack_share_pct"
    )
    .fillna(0)
)


fig_heatmap = px.imshow(
    monthly_pivot,

    text_auto=".1f",

    aspect="auto",

    labels={
        "x": "Month",
        "y": "Attack Type",
        "color": "Historical Share %"
    }
)


fig_heatmap.update_layout(
    height=430,

    paper_bgcolor="#0d151e",

    plot_bgcolor="#0d151e",

    font_color="#e6edf3",

    margin=dict(
        l=20,
        r=20,
        t=30,
        b=30
    )
)


st.plotly_chart(
    fig_heatmap,
    use_container_width=True
)


# ============================================================
# 17. HIGH-PRIORITY RECURRING THREATS
# ============================================================

st.divider()

st.subheader(
    "🔴 HIGH-PRIORITY RECURRING THREATS"
)

st.caption(
    "Recurring behavioral patterns ranked by recurring attack activity."
)


priority_patterns = (
    final_patterns
    .sort_values(
        "total_recurring_attacks",
        ascending=False
    )
    .head(5)
)


priority_table = priority_patterns[
    [
        "final_cluster",
        "pattern_name",
        "total_recurring_attacks",
        "max_months_present"
    ]
].copy()


priority_table.columns = [
    "Cluster",
    "Threat Pattern",
    "Recurring Attacks",
    "Months Present"
]


st.dataframe(
    priority_table,

    use_container_width=True,

    hide_index=True
)


# ============================================================
# 18. THREAT PATTERN EXPLORER
# ============================================================

st.divider()

st.subheader(
    "🔎 THREAT PATTERN EXPLORER"
)

st.caption(
    "Investigate the behavioral characteristics of a recurring threat."
)


pattern_names = (
    final_patterns[
        "pattern_name"
    ]
    .tolist()
)


selected_pattern = st.selectbox(
    "Select Threat Pattern",
    pattern_names
)


selected_row = (
    final_patterns[
        final_patterns[
            "pattern_name"
        ] == selected_pattern
    ]
    .iloc[0]
)


selected_cluster = int(
    selected_row[
        "final_cluster"
    ]
)


st.markdown(
    f"### Cluster {selected_cluster} — {selected_pattern}"
)


# ============================================================
# 19. SELECTED PATTERN METRICS
# ============================================================

pattern_col1, pattern_col2, pattern_col3, pattern_col4 = (
    st.columns(4)
)


with pattern_col1:

    st.metric(
        "Recurring Attacks",
        int(
            selected_row[
                "total_recurring_attacks"
            ]
        )
    )


with pattern_col2:

    st.metric(
        "Recurring Months",
        int(
            selected_row[
                "max_months_present"
            ]
        )
    )


# Get corresponding detailed cluster information

detail_rows = (
    detailed_patterns[
        detailed_patterns[
            "final_cluster"
        ] == selected_cluster
    ]
)


if not detail_rows.empty:

    detail = detail_rows.iloc[0]


    browser_rate = (
        float(
            detail[
                "browser_rate"
            ]
        )
        * 100
    )


    internal_rate = (
        float(
            detail[
                "internal_code"
            ]
        )
        * 100
    )


    with pattern_col3:

        st.metric(
            "Browser Rate",
            f"{browser_rate:.1f}%"
        )


    with pattern_col4:

        st.metric(
            "Internal Traffic",
            f"{internal_rate:.1f}%"
        )


# ============================================================
# 20. ASSOCIATED ATTACK TYPES
# ============================================================

st.subheader(
    "Associated Attack Types"
)


st.info(
    str(
        selected_row[
            "recurring_attack_types"
        ]
    )
)


# ============================================================
# 21. BEHAVIORAL INDICATORS
# ============================================================

if not detail_rows.empty:

    detail = detail_rows.iloc[0]


    sensitive_rate = (
        float(
            detail[
                "sensitive_url_rate"
            ]
        )
        * 100
    )


    query_rate = (
        float(
            detail[
                "records_with_query_params"
            ]
        )
        * 100
    )


    avg_bytes_sent = float(
        detail[
            "bytes_sent"
        ]
    )


    avg_bytes_received = float(
        detail[
            "bytes_received"
        ]
    )


    st.subheader(
        "Behavioral Indicators"
    )


    indicator1, indicator2, indicator3, indicator4 = (
        st.columns(4)
    )


    with indicator1:

        st.metric(
            "Sensitive URL Rate",
            f"{sensitive_rate:.1f}%"
        )


    with indicator2:

        st.metric(
            "Query Parameter Rate",
            f"{query_rate:.1f}%"
        )


    with indicator3:

        st.metric(
            "Avg Bytes Sent",
            f"{avg_bytes_sent:,.0f}"
        )


    with indicator4:

        st.metric(
            "Avg Bytes Received",
            f"{avg_bytes_received:,.0f}"
        )


# ============================================================
# 22. CLUSTER VISUALIZATION
# ============================================================

st.divider()

st.subheader(
    "📊 THREAT CLUSTER VISUALIZATION"
)


pca_file = (
    FIGURES_DIR /
    "dbscan_clusters_pca.png"
)


heatmap_file = (
    FIGURES_DIR /
    "recurring_threat_cluster_month_heatmap.png"
)


visual_col1, visual_col2 = st.columns(2)


with visual_col1:

    if pca_file.exists():

        st.image(
            str(pca_file),
            use_container_width=True
        )

        st.caption(
            "DBSCAN clusters visualized using PCA."
        )


with visual_col2:

    if heatmap_file.exists():

        st.image(
            str(heatmap_file),
            use_container_width=True
        )

        st.caption(
            "Recurring threat activity by cluster and month."
        )


# ============================================================
# 23. SYSTEM INFORMATION
# ============================================================

st.divider()

st.subheader(
    "SYSTEM INFORMATION"
)


info1, info2, info3, info4 = st.columns(4)


with info1:

    st.metric(
        "DBSCAN Clusters",
        total_clusters
    )


with info2:

    st.metric(
        "Noise Points",
        noise_points
    )


with info3:

    st.metric(
        "Recurring Patterns",
        recurring_attack_patterns
    )


with info4:

    st.metric(
        "Recurring Attack Types",
        recurring_attack_types
    )


# ============================================================
# 24. ANALYTICAL NOTE
# ============================================================

st.warning(
    """
    Analytical note: Monthly attack percentages represent historical
    activity within the analyzed security logs. They should not be
    interpreted as guaranteed future attack probabilities. The current
    dataset contains three months of observations.
    """
)


# ============================================================
# 25. FOOTER
# ============================================================

st.divider()

st.caption(
    "Cybersecurity & AI-Driven Threat Detection  •  "
    "DBSCAN Behavioral Clustering  •  "
    "Recurring Threat Intelligence"
)