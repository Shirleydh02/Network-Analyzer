import pandas as pd
from sklearn.decomposition import PCA
import matplotlib
matplotlib.use('Agg')  # Non-interactive backend
import matplotlib.pyplot as plt
import os

def explain_anomalies(df, numeric_cols):
    df['anomaly_reason'] = "Normal"
    
    # Separate normal traffic
    normal_df = df[df['is_anomaly'] == 0]
    if len(normal_df) == 0:
        normal_df = df
        
    stats = {}
    for col in numeric_cols:
        mean_val = normal_df[col].mean()
        std_val = normal_df[col].std()
        if pd.isna(std_val) or std_val == 0:
            std_val = 1e-5
        stats[col] = (mean_val, std_val)
        
    for idx, row in df.iterrows():
        if row['is_anomaly'] == 1:
            feat_reasons = []
            for col in numeric_cols:
                mean_val, std_val = stats[col]
                val = row[col]
                z = (val - mean_val) / std_val
                if abs(z) > 2.0:
                    direction = "high" if z > 0 else "low"
                    feat_reasons.append(f"{col} is unusually {direction} ({abs(z):.1f} std dev)")
            if len(feat_reasons) > 0:
                df.at[idx, 'anomaly_reason'] = ", ".join(feat_reasons)
            else:
                df.at[idx, 'anomaly_reason'] = "Multi-dimensional outlier (minor deviation across multiple features)"
        else:
            df.at[idx, 'anomaly_reason'] = "Normal"
            
    return df

def analyze_outliers(df, numeric_cols):
    # Run PCA for visualization
    pca = PCA(n_components=2)
    components = pca.fit_transform(df[numeric_cols].fillna(0))
    df['pca1'] = components[:, 0]
    df['pca2'] = components[:, 1]

    # Save plot for reference
    plt.figure(figsize=(10, 6))
    plt.scatter(df['pca1'], df['pca2'], c=df['is_anomaly'], cmap='coolwarm', alpha=0.6)
    plt.title("Outlier Visualization using PCA")
    plt.xlabel("PCA Component 1")
    plt.ylabel("PCA Component 2")
    os.makedirs('static/results', exist_ok=True)
    plt.savefig('static/results/outliers_plot.png')
    plt.close()

    # Generate anomaly reasons
    df = explain_anomalies(df, numeric_cols)

    return df
