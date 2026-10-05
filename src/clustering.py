# ============================================================
# Cybersecurity Clustering Module
# ============================================================

import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import DBSCAN


def prepare_clustering_features(df):
    """
    Prepare features for unsupervised clustering.

    Source and destination ports are included because they
    contributed to stronger cluster separation in the current
    dataset and baseline evaluation.
    """

    clustering_features = [
        "src_port",
        "dst_port",
        "bytes_sent",
        "bytes_received",
        "bytes_ratio",
        "internal_code",
        "url_length",
        "has_sensitive_keyword",
        "is_browser",
        "hour_sin",
        "hour_cos",
        "day_sin",
        "day_cos"
    ]

    # Convert protocol into one-hot encoded features.
    # This represents protocol as categorical information
    # instead of treating TCP, UDP and ICMP as ordered numbers.
    protocol_encoded = pd.get_dummies(
        df["protocol"],
        prefix="protocol",
        dtype=int
    )

    # Combine numerical/behavioral features with
    # one-hot encoded protocol features.
    X = pd.concat(
        [
            df[clustering_features],
            protocol_encoded
        ],
        axis=1
    )

    return X


def scale_features(X):
    """
    Standardize clustering features so that features with
    larger numerical ranges do not dominate the clustering.
    """

    scaler = StandardScaler()

    X_scaled = scaler.fit_transform(X)

    return X_scaled, scaler


def apply_dbscan(X_scaled, eps=2.1, min_samples=10):
    """
    Apply DBSCAN clustering to the scaled feature matrix.
    """

    dbscan = DBSCAN(
        eps=eps,
        min_samples=min_samples
    )

    cluster_labels = dbscan.fit_predict(X_scaled)

    return cluster_labels, dbscan