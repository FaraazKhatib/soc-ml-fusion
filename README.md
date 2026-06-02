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
| Valid account targeting | Higher risk if targeted account actually exists |
| Compromised account | Successful login detected after brute force activity |

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

If you are on a shared server or do not have sudo access, use a Python virtual environment:

    python3 -m venv freshenv
    source freshenv/bin/activate
    chmod +x run.sh
    ./run.sh

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

### Brute force alert

    [2026-05-29 10:03:31 UTC] [AUTOMATED_BRUTE_FORCE] severity=CRITICAL user=root
    source_ip=10.8.0.30 target_host=mail risk=100
    reasons=['burst_attack', 'valid_account_targeted', 'ml_anomaly_detected']
    features={...}

### Compromised account alert

    [2026-05-29 10:15:44 UTC] [COMPROMISED_ACCOUNT] severity=CRITICAL user=root
    source_ip=10.8.0.30 target_host=mail risk=100 previous_risk=85
    failed_attempts=12 reason=successful_login_after_bruteforce

---

## Feature set (9 features fed into the ML model)

| Feature | What it measures |
|---|---|
| failed_attempts | Max failures across pair, user, and IP in last 5 min |
| long_failed_attempts | Max failures across pair, user, and IP in last 60 min |
| seconds_since_last_attempt | Time since last attempt from this IP and user |
| source_attempt_rate | Attempts per minute from this IP |
| source_burst_attempts | Attempts from this IP within last 1 second |
| unique_users_targeted | Distinct usernames tried from this IP in 5 min |
| persistence_minutes | How long this attack has been running |
| account_risk | root=5, admin=4, mysql/postgres=3, others=1 |
| user_validity | 1 if account exists, 0 if invalid user |

---

## New in this version

### Valid vs Invalid user classification

When a log contains "invalid user" it means the attacker is guessing usernames that do not exist.
When the username actually exists on the system ("failed password"), the risk score increases significantly
because the attacker has found a real target.

    invalid user attempt  → risk reduced  (just scanning, not targeted)
    valid user, few fails → small boost
    valid user, 10+ fails → +15 points
    valid user, 20+ fails → +25 points

### Successful login after brute force detection

When a successful authentication is detected from an IP that was previously flagged for brute force
activity against the same user within the last hour, a COMPROMISED_ACCOUNT alert fires immediately
with severity CRITICAL regardless of anything else.

This is the most dangerous scenario — the attack succeeded.

---

## How the detection pipeline works

    New log arrives
         |
    is_auth_success? --> YES --> was this user under attack in last hour?
         |                              |
         |                    YES --> COMPROMISED_ACCOUNT alert
         |
    is_auth_failure? --> NO --> skip
         |
    extract 9 features
         |
    IsolationForest predict --> normal or anomaly?
         |
    calculate_risk_score() --> 0 to 100 + reasons list
         |
    if ML anomaly and 3+ failures --> risk += 20
         |
    classify severity
         |
    detect automation --> MANUAL or AUTOMATED
         |
    print alert

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
