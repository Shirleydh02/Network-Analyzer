# Network Analyzer

Network Analyzer is a Flask web application for detecting and explaining anomalies in network traffic data. It preprocesses uploaded CSV logs, clusters the records with DBSCAN, highlights suspicious traffic, and generates a PCA-based visualization plus a CSV report of the analyzed results.

## Features

- Upload a CSV file and analyze it from the web UI.
- Use a built-in sample download to test the app quickly.
- Detect anomalies with DBSCAN-based clustering.
- Apply whitelist rules for trusted source IPs, destination IPs, protocols, services, and states.
- Generate anomaly explanations from feature deviations.
- Export analyzed results to CSV.
- Visualize normal and anomalous points with a PCA scatter plot.
- Send an optional webhook alert after analysis.
- Access a JSON API for programmatic integrations.

## Project Structure

```text
network_analyzer/
	app.py
	preprocessing.py
	outlier_detection.py
	outlier_analysis.py
	whitelist.json
	static/
		css/
		js/
		sample.csv
		results/
	templates/
	uploads/
```

## Requirements

- Python 3.10 or newer is recommended.
- pip
- A modern browser

Python packages used by the app:

- Flask
- pandas
- scikit-learn
- matplotlib
- requests

## Installation

1. Clone or download the repository.
2. Open a terminal in the `network_analyzer` folder.
3. Create a virtual environment:

```bash
python -m venv .venv
```

4. Activate the virtual environment:

```bash
\.venv\Scripts\activate
```

5. Install the dependencies:

```bash
pip install -r requirements.txt
```

## Running the App

From the `network_analyzer` folder, run:

```bash
python app.py
```

By default, Flask starts the development server at `http://127.0.0.1:5000/`.

## How to Use

1. Open the app in your browser.
2. Upload a CSV file containing network traffic data.
3. Choose the input format if needed.
4. Run the analysis.
5. Review the anomaly summary, the list of suspicious records, and the PCA plot.
6. Download the analyzed CSV if you want to inspect the full output.

If no file is uploaded, the app looks for a local `unsw_clean.csv` file in the `network_analyzer` folder. If that file is not present, you must upload a CSV manually.

## Sample Download

The app provides a sample CSV download from the UI. This is useful for testing the workflow before uploading your own dataset.

## Whitelist

The app maintains `whitelist.json` in the project folder. You can use the whitelist API to mark trusted values so they are not treated as anomalies.

## API Endpoints

### `POST /api/analyze`

Uploads a file and returns JSON containing:

- `summary`
- `anomalies`

Supported form fields:

- `file`
- `format`
- `webhook_url`

### `GET /api/whitelist`

Returns the current whitelist.

### `POST /api/whitelist`

Adds a value to the whitelist.

Request JSON example:

```json
{
	"type": "srcip",
	"value": "192.168.1.10"
}
```

### `GET /download-sample`

Downloads the bundled sample CSV.

## Output Files

When analysis runs, the app writes its generated artifacts to runtime folders such as:

- `uploads/`
- `static/results/`

These files are created automatically and do not need to be committed to version control.

## Notes

- Run the app from inside the `network_analyzer` directory so relative paths resolve correctly.
- If you change the code, restart the Flask server to pick up the updates.
- The included analysis logic is intended for detecting unusual patterns, not for replacing a full security monitoring platform.
