import pandas as pd
from sklearn.cluster import DBSCAN

def detect_outliers(df, numeric_cols, eps=0.5, min_samples=5, whitelist=None):
    db = DBSCAN(eps=eps, min_samples=min_samples)
    df['cluster'] = db.fit_predict(df[numeric_cols])

    # Identify small clusters
    cluster_counts = df['cluster'].value_counts()
    small_clusters = cluster_counts[cluster_counts < 10].index.tolist()

    # Identify outliers
    df['is_anomaly'] = 0
    df.loc[df['cluster'].isin(small_clusters), 'is_anomaly'] = 1

    # Apply whitelist rules
    if whitelist:
        # Source IP whitelist
        if 'srcip' in whitelist and len(whitelist['srcip']) > 0:
            mask = df['srcip'].isin(whitelist['srcip'])
            df.loc[mask, 'is_anomaly'] = 0
            df.loc[mask, 'cluster'] = -2

        # Destination IP whitelist
        if 'dstip' in whitelist and len(whitelist['dstip']) > 0:
            mask = df['dstip'].isin(whitelist['dstip'])
            df.loc[mask, 'is_anomaly'] = 0
            df.loc[mask, 'cluster'] = -2

        # Protocol whitelist
        if 'proto' in whitelist and len(whitelist['proto']) > 0:
            col = 'proto_raw' if 'proto_raw' in df.columns else 'proto'
            mask = df[col].astype(str).str.lower().isin([p.lower() for p in whitelist['proto']])
            df.loc[mask, 'is_anomaly'] = 0
            df.loc[mask, 'cluster'] = -2

        # Service whitelist
        if 'service' in whitelist and len(whitelist['service']) > 0:
            col = 'service_raw' if 'service_raw' in df.columns else 'service'
            mask = df[col].astype(str).str.lower().isin([s.lower() for s in whitelist['service']])
            df.loc[mask, 'is_anomaly'] = 0
            df.loc[mask, 'cluster'] = -2

        # State whitelist
        if 'state' in whitelist and len(whitelist['state']) > 0:
            col = 'state_raw' if 'state_raw' in df.columns else 'state'
            mask = df[col].astype(str).str.lower().isin([st.lower() for st in whitelist['state']])
            df.loc[mask, 'is_anomaly'] = 0
            df.loc[mask, 'cluster'] = -2

    return df
