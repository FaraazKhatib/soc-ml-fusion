# SOC ML Brute Force Detector
**IITB Trust Lab — Summer of Code 2026**

Real-time ML-based brute force detection engine for mail authentication logs.
Uses IsolationForest to learn normal login failure patterns and flags anomalies as they happen.

---

## What it detects

| Attack Type | How |
|---|---|
| Brute force (single IP) | High failed attempts in short window |
| Distributed brute force | Same username attacked from multiple IPs |
| Password spraying | One IP targeting many different usernames |
| Automated attacks | Sub-second retry speed, burst patterns |
| Slow and low attacks | Long-window 60 min failure accumulation |
| Persistent attacks | Attack duration tracking |

---

## Quick Start

### 1. Clone the repo

    git clone https://github.com/FaraazKhatib/soc-ml-fusion.git
    cd soc-ml-fusion

### 2. Set your log file path

Open ml_fusion.py and change line 20:

    # CHANGE THIS to your actual log file path
    AUTH_LOG_FILE = "/var/log/soc_output/mail_auth.json"

That is the only change you need to make.

### 3. Run

    chmod +x run.sh
    ./run.sh

---

## Recommended — Run in an isolated environment

If you are on a shared server or don't have sudo access, use a Python virtual environment:

    python3 -m venv freshenv
    source freshenv/bin/activate
    chmod +x run.sh
    ./run.sh

This installs all dependencies in isolation without touching system packages.
To exit the virtual environment when done:

    deactivate

---

## Manual setup

    pip3 install -r requirements.txt
    python3 -u ml_fusion.py

---

## Requirements

- Python 3.8 or higher
- Log file in newline-delimited JSON format (one JSON object per line)

---

## Expected log format

    {
      "@timestamp": "2026-05-29T10:03:31Z",
      "event": {
        "original": "May 29 10:03:31 mail sshd[1234]: Failed password for root from 10.8.0.30"
      },
      "user": { "name": "root" },
      "observer": { "source_host": "mail" },
      "source": { "ip": "10.8.0.30" }
    }

---

## Output format

    [2026-05-29 10:03:31 UTC] [AUTOMATED_BRUTE_FORCE] severity=CRITICAL user=root
    source_ip=10.8.0.30 target_host=mail risk=100
    reasons=['burst_attack', 'ml_anomaly_detected'] features={...}

---

## Project structure

    soc-ml-fusion/
    ├── ml_fusion.py          — main detection engine
    ├── run.sh                — setup and run script
    ├── requirements.txt      — Python dependencies
    ├── core/                 — shared core modules
    ├── plugins/              — per-service detection plugins
    ├── config/               — configuration files
    └── README.md

---

## Part of the IITB SOC Pipeline

    Sources → Kafka → FOSS SOC Engine → Logstash → [THIS DETECTOR] → Alerts → Kibana

---

## Authors

IITB Trust Lab — SOC ML Team, Summer of Code 2026
