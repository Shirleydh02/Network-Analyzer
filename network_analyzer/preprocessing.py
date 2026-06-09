import pandas as pd
from sklearn.preprocessing import LabelEncoder, StandardScaler

def parse_standard_log(df, format_type="default"):
    format_type = str(format_type).lower().strip()
    df_new = pd.DataFrame()

    if format_type == 'aws':
        # AWS VPC Flow Log mapping
        mapping = {
            'srcaddr': 'srcip',
            'dstaddr': 'dstip',
            'packets': 'spkts',
            'bytes': 'sbytes'
        }
        for src, dest in mapping.items():
            if src in df.columns:
                df_new[dest] = df[src]
            else:
                df_new[dest] = 0 if dest in ['spkts', 'sbytes'] else '-'

        # Protocol mapping (number to standard name)
        if 'protocol' in df.columns:
            proto_map = {6: 'tcp', 17: 'udp', 1: 'icmp'}
            df_new['proto'] = df['protocol'].map(proto_map).fillna(df['protocol'].astype(str))
        else:
            df_new['proto'] = 'tcp'

        df_new['dpkts'] = 0
        df_new['dbytes'] = 0
        df_new['service'] = '-'
        df_new['state'] = '-'
        df_new['dur'] = 0.0

        mapped_sources = ['srcaddr', 'dstaddr', 'packets', 'bytes', 'protocol']

    elif format_type == 'zeek':
        # Zeek Conn Log mapping
        mapping = {
            'id.orig_h': 'srcip', 'id_orig_h': 'srcip',
            'id.resp_h': 'dstip', 'id_resp_h': 'dstip',
            'proto': 'proto',
            'service': 'service',
            'conn_state': 'state', 'conn_state_': 'state',
            'orig_pkts': 'spkts',
            'resp_pkts': 'dpkts',
            'orig_bytes': 'sbytes',
            'resp_bytes': 'dbytes',
            'duration': 'dur'
        }
        for src, dest in mapping.items():
            if src in df.columns:
                df_new[dest] = df[src]

        required_cols = {
            'srcip': '-', 'dstip': '-', 'proto': 'tcp',
            'service': '-', 'state': '-', 'spkts': 0, 'dpkts': 0,
            'sbytes': 0, 'dbytes': 0, 'dur': 0.0
        }
        for col, default in required_cols.items():
            if col not in df_new.columns:
                df_new[col] = default

        mapped_sources = list(mapping.keys())
    else:
        df_new = df.copy()
        mapped_sources = []

    # Copy other unmapped columns (e.g. label, attack_cat)
    for col in df.columns:
        if col not in mapped_sources and col not in df_new.columns:
            df_new[col] = df[col]

    # Ensure all required standard fields exist
    standard_cols = ['srcip', 'dstip', 'proto', 'service', 'state', 'spkts', 'dpkts', 'sbytes', 'dbytes', 'dur']
    for col in standard_cols:
        if col not in df_new.columns:
            if col in ['spkts', 'dpkts', 'sbytes', 'dbytes', 'dur']:
                df_new[col] = 0.0 if col == 'dur' else 0
            else:
                df_new[col] = '-'

    return df_new

def preprocess_dataset(csv_path="unsw_clean.csv", format_type="default"):
    df = pd.read_csv(csv_path)

    # Apply log format parser
    df = parse_standard_log(df, format_type)

    # Encode categorical columns if they exist
    cat_cols = ['proto', 'service', 'state']
    le = LabelEncoder()
    for col in cat_cols:
        if col in df.columns:
            df[col] = df[col].astype(str).fillna('-')
            # Save raw string version for whitelisting and UI display
            df[col + '_raw'] = df[col]
            df[col] = le.fit_transform(df[col])

    # Scale numeric features (excluding ID/IP columns and label/anomaly tags)
    exclude_cols = ['label', 'is_anomaly', 'cluster', 'srcip', 'dstip', 'attack_cat', 'pca1', 'pca2', 'anomaly_reason']
    num_cols = df.select_dtypes(include=['int64', 'float64']).columns
    num_cols = [c for c in num_cols if c not in exclude_cols]

    if len(num_cols) > 0:
        # Fill numeric NaNs with 0 before scaling
        df[num_cols] = df[num_cols].fillna(0)
        scaler = StandardScaler()
        df[num_cols] = scaler.fit_transform(df[num_cols])

    return df, list(num_cols)
