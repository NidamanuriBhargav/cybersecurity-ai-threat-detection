# ============================================================
# Cybersecurity Data Preprocessing
# ============================================================

import pandas as pd
import numpy as np


# ============================================================
# Load Dataset
# ============================================================

def load_data(file_path):
    """
    Load the cybersecurity dataset from a CSV file.
    """

    df = pd.read_csv(
        file_path
    )

    return df


# ============================================================
# Prepare Optional Columns
# ============================================================

def prepare_optional_columns(df):
    """
    Create missing optional columns with safe default values.

    This allows the pipeline to process datasets that do not
    contain URL, user-agent, or internal-traffic information.
    """

    df = df.copy()

    # --------------------------------------------------------
    # URL
    # --------------------------------------------------------

    if "url" not in df.columns:

        df["url"] = ""

    else:

        df["url"] = (
            df["url"]
            .fillna("")
            .astype(str)
        )

    # --------------------------------------------------------
    # User Agent
    # --------------------------------------------------------

    if "user_agent" not in df.columns:

        df["user_agent"] = ""

    else:

        df["user_agent"] = (
            df["user_agent"]
            .fillna("")
            .astype(str)
        )

    # --------------------------------------------------------
    # Internal Traffic
    # --------------------------------------------------------

    if "is_internal_traffic" not in df.columns:

        df["is_internal_traffic"] = False

    else:

        df["is_internal_traffic"] = (
            df["is_internal_traffic"]
            .fillna(False)
            .astype(bool)
        )

    return df


# ============================================================
# Feature Engineering
# ============================================================

def engineer_features(df):
    """
    Perform feature engineering for cybersecurity
    behavioral analysis.
    """

    df = df.copy()

    # --------------------------------------------------------
    # Prepare optional columns
    # --------------------------------------------------------

    df = prepare_optional_columns(
        df
    )

    # --------------------------------------------------------
    # Timestamp
    # --------------------------------------------------------

    df["timestamp"] = pd.to_datetime(
        df["timestamp"]
    )

    # --------------------------------------------------------
    # Time Features
    # --------------------------------------------------------

    df["hour"] = (
        df["timestamp"].dt.hour
    )

    df["day_of_week"] = (
        df["timestamp"].dt.dayofweek
    )

    # --------------------------------------------------------
    # Traffic Volume
    # --------------------------------------------------------

    df["total_bytes"] = (
        df["bytes_sent"]
        + df["bytes_received"]
    )

    # --------------------------------------------------------
    # Bytes Ratio
    # --------------------------------------------------------

    df["bytes_ratio"] = (
        df["bytes_sent"]
        / (
            df["bytes_received"]
            + 1
        )
    )

    # --------------------------------------------------------
    # Traffic Imbalance
    # --------------------------------------------------------

    df["traffic_imbalance"] = (
        (
            df["bytes_sent"]
            - df["bytes_received"]
        )
        / (
            df["total_bytes"]
            + 1
        )
    )

    # --------------------------------------------------------
    # Protocol Encoding
    # --------------------------------------------------------

    df["protocol_code"] = (
        df["protocol"].map({
            "TCP": 0,
            "UDP": 1,
            "ICMP": 2
        })
    )

    # --------------------------------------------------------
    # Internal Traffic Encoding
    # --------------------------------------------------------

    df["internal_code"] = (
        df["is_internal_traffic"]
        .astype(int)
    )

    # --------------------------------------------------------
    # Common Destination Ports
    # --------------------------------------------------------

    common_ports = [
        21,
        22,
        25,
        53,
        80,
        443,
        445,
        1433,
        3306,
        3389
    ]

    df["common_dst_port"] = (
        df["dst_port"]
        .isin(common_ports)
        .astype(int)
    )

    # --------------------------------------------------------
    # URL Length
    # --------------------------------------------------------

    df["url_length"] = (
        df["url"]
        .str.len()
    )

    # --------------------------------------------------------
    # Query Parameters
    # --------------------------------------------------------

    df["has_query_params"] = (
        df["url"]
        .str.contains(
            r"\?",
            regex=True
        )
        .astype(int)
    )

    # --------------------------------------------------------
    # Sensitive URL Keywords
    # --------------------------------------------------------

    sensitive_keywords = (
        r"login|admin|phpmyadmin|config|auth"
    )

    df["has_sensitive_keyword"] = (
        df["url"]
        .str.lower()
        .str.contains(
            sensitive_keywords,
            regex=True
        )
        .astype(int)
    )

    # --------------------------------------------------------
    # URL Path Depth
    # --------------------------------------------------------

    df["url_path_depth"] = (
        df["url"]
        .str.split("/")
        .str.len()
    )

    # --------------------------------------------------------
    # Browser Detection
    # --------------------------------------------------------

    df["is_browser"] = (
        df["user_agent"]
        .str.contains(
            r"Mozilla|Chrome|Firefox|Safari|Edge",
            case=False,
            regex=True
        )
        .astype(int)
    )

    # --------------------------------------------------------
    # Cyclical Hour Encoding
    # --------------------------------------------------------

    df["hour_sin"] = np.sin(
        2
        * np.pi
        * df["hour"]
        / 24
    )

    df["hour_cos"] = np.cos(
        2
        * np.pi
        * df["hour"]
        / 24
    )

    # --------------------------------------------------------
    # Cyclical Day Encoding
    # --------------------------------------------------------

    df["day_sin"] = np.sin(
        2
        * np.pi
        * df["day_of_week"]
        / 7
    )

    df["day_cos"] = np.cos(
        2
        * np.pi
        * df["day_of_week"]
        / 7
    )

    return df