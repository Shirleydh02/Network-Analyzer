from flask import Flask, render_template, request, jsonify, redirect, url_for, send_file
import os
import json
import pandas as pd
import threading
import requests

try:
    from preprocessing import preprocess_dataset
    from outlier_detection import detect_outliers
    from outlier_analysis import analyze_outliers
except ImportError as e:
    raise ImportError("Ensure preprocessing.py, outlier_detection.py, outlier_analysis.py exist in the network_analyzer folder.") from e

app = Flask(__name__, static_folder='static', template_folder='templates')
UPLOAD_DIR = os.path.join(os.getcwd(), 'uploads')
RESULTS_DIR = os.path.join('static', 'results')
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(RESULTS_DIR, exist_ok=True)

WHITELIST_FILE = os.path.join(os.getcwd(), 'whitelist.json')

def load_whitelist():
    if not os.path.exists(WHITELIST_FILE):
        default = {
            "srcip": [],
            "dstip": [],
            "proto": [],
            "service": [],
            "state": []
        }
        with open(WHITELIST_FILE, 'w') as f:
            json.dump(default, f, indent=4)
        return default
    try:
        with open(WHITELIST_FILE, 'r') as f:
            return json.load(f)
    except Exception:
        return {"srcip": [], "dstip": [], "proto": [], "service": [], "state": []}

def save_whitelist(whitelist):
    try:
        with open(WHITELIST_FILE, 'w') as f:
            json.dump(whitelist, f, indent=4)
        return True
    except Exception:
        return False

# Initialize whitelist on startup
load_whitelist()

def send_webhook(webhook_url, summary_data):
    def run():
        try:
            payload = {
                "text": (
                    f"🚨 *NetAnalyzr Alert*: Suspicious traffic detected!\n"
                    f"• *Total records*: {summary_data['total']}\n"
                    f"• *Anomalies detected*: {summary_data['anomalies']} ({summary_data['percent']}%)\n"
                    f"• *Download CSV Results*: {summary_data['csv_url']}\n"
                )
            }
            requests.post(webhook_url, json=payload, timeout=5)
        except Exception as e:
            print(f"Webhook notification failed: {e}")
            
    threading.Thread(target=run).start()

def get_scatter_points(df, max_normal=1000):
    normal_points = df[df['is_anomaly'] == 0]
    anomaly_points = df[df['is_anomaly'] == 1]
    
    if len(normal_points) > max_normal:
        normal_points = normal_points.sample(n=max_normal, random_state=42)
        
    combined = pd.concat([normal_points, anomaly_points])
    
    proto_col = 'proto_raw' if 'proto_raw' in combined.columns else 'proto'
    service_col = 'service_raw' if 'service_raw' in combined.columns else 'service'
    state_col = 'state_raw' if 'state_raw' in combined.columns else 'state'
    
    points = []
    for _, row in combined.iterrows():
        points.append({
            'pca1': float(row['pca1']) if 'pca1' in row else 0.0,
            'pca2': float(row['pca2']) if 'pca2' in row else 0.0,
            'is_anomaly': int(row['is_anomaly']),
            'srcip': str(row['srcip']),
            'dstip': str(row['dstip']),
            'proto': str(row[proto_col]),
            'service': str(row[service_col]),
            'state': str(row[state_col])
        })
    return points

def get_cluster_sizes(df):
    counts = df[~df['cluster'].isin([-1, -2])]['cluster'].value_counts()
    return {f"Cluster {int(cluster_id)}": int(count) for cluster_id, count in counts.items()}

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/analyze', methods=['GET', 'POST'])
def analyze():
    if request.method == 'POST':
        f = request.files.get('file')
        format_type = request.form.get('format', 'default')
        webhook_url = request.form.get('webhook_url', '')

        # Fallback to internal dataset if no file uploaded
        if f and f.filename != '':
            filepath = os.path.join(UPLOAD_DIR, f.filename)
            f.save(filepath)
            source = filepath
        else:
            internal = os.path.join(os.getcwd(), 'unsw_clean.csv')
            if os.path.exists(internal):
                source = internal
            else:
                return jsonify({"success": False, "error": "No file uploaded and no default dataset found."}), 400

        try:
            whitelist = load_whitelist()
            df, numeric_cols = preprocess_dataset(source, format_type)
            df = detect_outliers(df, numeric_cols, whitelist=whitelist)
            df = analyze_outliers(df, numeric_cols)
        except Exception as exc:
            return jsonify({"success": False, "error": f"Processing error: {exc}"}), 500

        csv_path = os.path.join(RESULTS_DIR, 'analyzed_results.csv')
        df.to_csv(csv_path, index=False)

        # Summary metrics
        total = len(df)
        anomalies = int(df['is_anomaly'].sum()) if 'is_anomaly' in df.columns else 0
        percent = round((anomalies / total * 100), 2) if total else 0.0

        # Extract list of anomalies to display in table
        anomaly_df = df[df['is_anomaly'] == 1]
        anomalies_list = []
        proto_col = 'proto_raw' if 'proto_raw' in anomaly_df.columns else 'proto'
        service_col = 'service_raw' if 'service_raw' in anomaly_df.columns else 'service'
        state_col = 'state_raw' if 'state_raw' in anomaly_df.columns else 'state'
        
        for _, row in anomaly_df.iterrows():
            anomalies_list.append({
                'srcip': str(row['srcip']),
                'dstip': str(row['dstip']),
                'proto': str(row[proto_col]),
                'service': str(row[service_col]),
                'state': str(row[state_col]),
                'spkts': int(row['spkts']) if 'spkts' in row else 0,
                'dpkts': int(row['dpkts']) if 'dpkts' in row else 0,
                'sbytes': int(row['sbytes']) if 'sbytes' in row else 0,
                'dbytes': int(row['dbytes']) if 'dbytes' in row else 0,
                'anomaly_reason': str(row['anomaly_reason']) if 'anomaly_reason' in row else 'N/A'
            })

        plot_path = os.path.join('static', 'results', 'outliers_plot.png')
        if not os.path.exists(plot_path):
            plot_path = None

        summary_data = {
            "total": total,
            "anomalies": anomalies,
            "percent": percent,
            "csv_url": url_for('static', filename='results/analyzed_results.csv'),
            "plot_url": url_for('static', filename='results/outliers_plot.png') if plot_path else None
        }

        # Send Webhook Alert if configured
        if webhook_url:
            # Complete URL for webhook summary download
            csv_full_url = request.url_root.rstrip('/') + summary_data['csv_url']
            send_webhook(webhook_url, {**summary_data, 'csv_url': csv_full_url})

        # Return structured JSON for UI rendering
        return jsonify({
            "success": True,
            "summary": summary_data,
            "anomalies_list": anomalies_list,
            "scatter_points": get_scatter_points(df),
            "cluster_sizes": get_cluster_sizes(df)
        })

    return render_template('analysis.html', results=False)

# REST API Endpoint for programmatic integrations
@app.route('/api/analyze', methods=['POST'])
def api_analyze():
    f = request.files.get('file')
    format_type = request.form.get('format', 'default')
    webhook_url = request.form.get('webhook_url', '')

    if not f or f.filename == '':
        return jsonify({"success": False, "error": "No file uploaded."}), 400

    filepath = os.path.join(UPLOAD_DIR, f.filename)
    f.save(filepath)

    try:
        whitelist = load_whitelist()
        df, numeric_cols = preprocess_dataset(filepath, format_type)
        df = detect_outliers(df, numeric_cols, whitelist=whitelist)
        df = analyze_outliers(df, numeric_cols)
    except Exception as exc:
        return jsonify({"success": False, "error": f"Processing error: {exc}"}), 500

    csv_path = os.path.join(RESULTS_DIR, 'analyzed_results.csv')
    df.to_csv(csv_path, index=False)

    total = len(df)
    anomalies = int(df['is_anomaly'].sum()) if 'is_anomaly' in df.columns else 0
    percent = round((anomalies / total * 100), 2) if total else 0.0

    anomaly_df = df[df['is_anomaly'] == 1]
    anomalies_list = []
    proto_col = 'proto_raw' if 'proto_raw' in anomaly_df.columns else 'proto'
    service_col = 'service_raw' if 'service_raw' in anomaly_df.columns else 'service'
    state_col = 'state_raw' if 'state_raw' in anomaly_df.columns else 'state'

    for _, row in anomaly_df.iterrows():
        anomalies_list.append({
            'srcip': str(row['srcip']),
            'dstip': str(row['dstip']),
            'proto': str(row[proto_col]),
            'service': str(row[service_col]),
            'state': str(row[state_col]),
            'spkts': int(row['spkts']) if 'spkts' in row else 0,
            'dpkts': int(row['dpkts']) if 'dpkts' in row else 0,
            'sbytes': int(row['sbytes']) if 'sbytes' in row else 0,
            'dbytes': int(row['dbytes']) if 'dbytes' in row else 0,
            'anomaly_reason': str(row['anomaly_reason']) if 'anomaly_reason' in row else 'N/A'
        })

    summary_data = {
        "total": total,
        "anomalies": anomalies,
        "percent": percent,
        "csv_url": request.url_root.rstrip('/') + url_for('static', filename='results/analyzed_results.csv')
    }

    if webhook_url:
        send_webhook(webhook_url, summary_data)

    return jsonify({
        "success": True,
        "summary": summary_data,
        "anomalies": anomalies_list
    })

# API Endpoints to Manage Whitelists
@app.route('/api/whitelist', methods=['GET', 'POST'])
def api_whitelist():
    whitelist = load_whitelist()
    if request.method == 'POST':
        data = request.json or {}
        col = data.get('type')  # e.g., 'srcip', 'dstip', 'proto', 'service', 'state'
        value = data.get('value')

        if not col or not value:
            return jsonify({"success": False, "error": "Type and value are required."}), 400

        if col in whitelist:
            if value not in whitelist[col]:
                whitelist[col].append(value)
                save_whitelist(whitelist)
                return jsonify({"success": True, "whitelist": whitelist})
            return jsonify({"success": True, "message": "Already whitelisted.", "whitelist": whitelist})
        return jsonify({"success": False, "error": "Invalid whitelist field type."}), 400

    return jsonify({"success": True, "whitelist": whitelist})

@app.route('/download-sample')
def download_sample():
    sample = os.path.join('static', 'sample.csv')
    if os.path.exists(sample):
        return send_file(sample, as_attachment=True)
    return redirect(url_for('analyze'))

if __name__ == '__main__':
    app.run(debug=True)
