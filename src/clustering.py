# Required Libraries
import pandas as pd

from sklearn.preprocessing import StandardScaler
from sklearn.cluster import DBSCAN


# Prepare features for clustering
def prepare_clustering_features(df):
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

    # One-hot encode protocol
    protocol_encoded = pd.get_dummies(
        df["protocol"],
        prefix="protocol",
        dtype=int
    )

    # Combine behavioral features with protocol features
    X = pd.concat(
        [
            df[clustering_features],
            protocol_encoded
        ],
        axis=1
    )

    return X


# Scale clustering features
def scale_features(X):
    scaler = StandardScaler()

    X_scaled = scaler.fit_transform(X)

    return X_scaled, scaler


# Apply DBSCAN clustering
def apply_dbscan(X_scaled, eps=2.1, min_samples=10):
    dbscan = DBSCAN(
        eps=eps,
        min_samples=min_samples
    )

    cluster_labels = dbscan.fit_predict(X_scaled)

    return cluster_labels, dbscan