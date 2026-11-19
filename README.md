# Autonomous Threat Hunting System

An AI-powered, autonomous threat hunting platform that ingests raw security
logs (SSH/auth, web server, firewall, Windows event logs) and automatically
detects, classifies, correlates, explains, and reports on security threats —
combining rule-based detection, machine learning, statistical anomaly
detection, threat intelligence, and a local LLM for human-readable summaries.

## Features

- **Multi-format log parsing** — SSH/auth logs, Apache/Nginx access logs,
  firewall/port-scan logs, Windows Security Event log lines, and generic
  syslog/application logs.
- **Rule-based detection engine** — brute force, port scanning, SQL
  injection, web reconnaissance, and data exfiltration signatures.
- **Machine learning ensemble** — a supervised `RandomForestClassifier`,
  an unsupervised `IsolationForest`, and an `Autoencoder` (deep learning via
  TensorFlow/Keras if installed, with an automatic PCA-based fallback if not).
- **Statistical anomaly detection** — per-batch z-score baselining.
- **Threat intelligence** — local IOC feed (malicious IPs/domains/user-agents)
  and MITRE ATT&CK technique mapping.
- **Attack chain correlation** — groups related findings per source IP into
  a kill-chain narrative (recon → brute force → exfiltration, etc.).
- **LLM-powered summaries** — natural-language threat explanations via a
  local [Ollama](https://ollama.com) model, with a deterministic template
  fallback if Ollama isn't running.
- **PDF reporting** — generate polished incident reports with ReportLab.
- **Email alerting** — SMTP-based alerts gated by severity threshold.
- **Web dashboard** — Flask + Bootstrap 5 + Chart.js, with login/auth,
  log upload, threat triage, and report generation.

## Project Structure

```
Autonomous-Threat-Hunting-System/
├── app.py                    # Main Flask application
├── config.py                 # Central configuration (reads .env)
├── requirements.txt
├── .env                      # Environment variables (edit before running)
├── sample_logs.txt           # Example log file to test the pipeline
│
├── Authentication/           # Flask-Login based auth blueprint
├── Backend_support/          # File handling, validation, security helpers, API responses
├── Database/                 # SQLAlchemy models + init script
├── Log_Processing/           # Parsing, normalization, feature extraction
├── Threat_Detection/         # Rule engine, classifier, detection orchestrator
├── Machine_learning/         # RandomForest / IsolationForest / Autoencoder + training
│   └── models/                   # Saved .pkl / .keras model artifacts
├── Anomaly_Detection/         # Statistical baseline + z-score anomaly detector
├── LLMs/                      # Ollama client, prompt templates, LLM manager
├── Threat_Intelligence/       # IOC manager, MITRE ATT&CK mapper
├── Attack_Correlation/        # Multi-stage attack chain correlation
├── PDF_Generation/            # ReportLab PDF report builder
├── Email_Alerts/              # SMTP email alerting
├── templates/                 # Jinja2 HTML templates (Bootstrap 5)
├── static/                    # CSS + JS for the dashboard
├── uploads/                   # Uploaded log files land here
└── reports/                   # Generated PDF reports land here
```

## Setup

### 1. Install dependencies

```bash
python -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

> TensorFlow is commented out in `requirements.txt` by default. Uncomment it
> if you want the "real" deep-learning autoencoder; otherwise the system
> automatically uses a PCA-based reconstruction-error fallback.

### 2. Configure environment

Edit `.env` and set at minimum:
- `SECRET_KEY` — a random secret string
- `ADMIN_USERNAME` / `ADMIN_PASSWORD` / `ADMIN_EMAIL` — seeded admin account
- SMTP settings if you want email alerts (`EMAIL_ALERTS_ENABLED=True`)
- `OLLAMA_HOST` / `OLLAMA_MODEL` if you're running a local LLM

### 3. Initialize the database

```bash
python -m Database.init_db
```

This creates the SQLite database and seeds the admin account defined in `.env`.

### 4. Train the ML models

```bash
python -m Machine_learning.train_model
```

This generates synthetic (but realistic) training data matching the feature
schema used by the live detection pipeline, and saves trained models to
`Machine_learning/models/`. **Replace this with real labeled historical data
for production use.**

### 5. (Optional) Run a local LLM via Ollama

```bash
ollama pull llama3
ollama serve
```

If Ollama isn't running, the system automatically falls back to
template-based threat summaries — nothing breaks.

### 6. Run the application

```bash
python app.py
```

Visit `http://localhost:5000`, log in with your admin credentials, and
upload `sample_logs.txt` from the Upload Logs page to see the full detection
pipeline in action.

## How Detection Works

1. **Parse & normalize** raw log lines into a consistent schema.
2. **Extract per-source-IP feature vectors** (failed logins, unique ports,
   HTTP errors, request volume, night-time activity ratio, etc.).
3. **Run the rule engine** for high-confidence, explainable signature matches.
4. **Score with the ML ensemble** (RandomForest + IsolationForest + Autoencoder)
   to catch patterns rules don't cover.
5. **Run statistical anomaly detection** against the batch's own baseline.
6. **Cross-reference threat intelligence** (known-malicious IPs, suspicious
   user agents).
7. **Deduplicate & classify** all findings by severity/confidence.
8. **Correlate into attack chains** per source IP.
9. **Generate an LLM-written summary** for each finding and chain.
10. **Persist to the database**, fire email alerts for high-severity findings,
    and display everything in the dashboard.

## Notes

- The bundled `Machine_learning/models/*.pkl` files are trained on synthetic
  data purely so the app works out of the box. Retrain on real labeled data
  before using this in a production security context.
- The IOC feed (`Threat_Intelligence/ioc_feed.json`, auto-created on first
  run) ships with a handful of illustrative example indicators — wire it up
  to a real feed (AbuseIPDB, MISP, AlienVault OTX, etc.) for real coverage.
- This project is intended as an educational/demonstration scaffold for
  building an ML + LLM-assisted threat hunting pipeline, not a
  drop-in replacement for a commercial SIEM/XDR product.

## License

Provided as-is for educational and internal tooling purposes.
