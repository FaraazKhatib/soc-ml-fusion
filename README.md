# SOC ML Brute Force Detector
**IITB Trust Lab — Summer of Code 2026**

Real-time ML-based brute force detection engine for mail authentication logs.
Uses two IsolationForest models (IP-level + User-level) to detect attacks that
a single model cannot catch individually.

---

## What it detects

| Attack Type | How |
|---|---|
| Brute force (single IP) | High failed attempts in short window |
| Password spray | One IP targeting many different usernames |
| Credential stuffing | One IP, many users, automated tool |
| Distributed attack | Multiple IPs coordinating against same user |
| Automated botnet | 5+ IPs targeting same user simultaneously |
| Successful compromise | Login after brute force activity |
| Slow and low attacks | Long-window 60 min failure accumulation |

---

## Quick Start

### 1. Clone the repo

    git clone https://github.com/FaraazKhatib/soc-ml-fusion.git
    cd soc-ml-fusion

### 2. Set your log file path

Open ml_fusion.py and change line 20:

    AUTH_LOG_FILE = "/your/path/to/auth_logs.json"

That is the only change you need to make.

### 3. Run

    chmod +x run.sh
    ./run.sh

---

## Recommended — Run in an isolated environment

    python3 -m venv freshenv
    source freshenv/bin/activate
    chmod +x run.sh
    ./run.sh

To exit:

    deactivate

---

## Manual setup

    pip3 install -r requirements.txt
    python3 -u ml_fusion.py

---

## How it works

Two IsolationForest models run in parallel:

    IP Model   — learns normal behavior per source IP
                 catches brute force, spray, credential stuffing

    User Model — learns normal behavior per target user
                 catches distributed attacks where each IP
                 looks innocent individually but the combined
                 pressure on one user is anomalous

Final score = max(ip_score, user_score)
The worst-case perspective always wins.

---

## Alert format

    [2026-06-04 06:04:08 UTC] [CRITICAL] [AUTOMATED]
      Who:    10.8.10.20 -> root on mail
      What:   5 different IPs are all targeting the 'root' account.
              Each IP makes only a few attempts to stay under the radar,
              but together they have made 12 failed login attempts.
              This looks like a coordinated botnet.
      Score:  0.87/1.00  (ip model: 0.61, user model: 0.87)
      Tags:   automated_distributed
      All IPs targeting 'root': 10.8.10.10, 10.8.10.20, 10.8.10.30

---

## Identity key logic

Each alert is deduplicated by an identity key:

    3+ IPs targeting same user  ->  DISTRIBUTED:{user}  (consolidated)
    Single IP attack            ->  {source_ip}         (per IP)

This means a 10-IP botnet fires ONE alert, not 10 noisy ones.

---

## Automation detection — 3 paths

    CV consistency    — same IP fires at perfectly regular intervals
                        works for Hydra --wait N regardless of speed

    Speed signals     — sub-second gaps, high rate, or burst in 1 second
                        catches fast single-IP tools

    Distributed botnet — 5+ IPs coordinating against same user
                         catches botnets where no single IP looks fast

---

## Requirements

- Python 3.8 or higher
- Log file in newline-delimited JSON format

---

## Expected log format

    {
      "@timestamp": "2026-06-04T06:04:08Z",
      "event": {
        "original": "2026-06-04T06:04:08+00:00 mail sshd[477802]: Invalid user root from 10.8.10.10 port 45812"
      },
      "user": { "name": "root" },
      "observer": { "source_host": "mail" },
      "source": { "ip": "10.8.10.10" }
    }

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

    Sources -> Kafka -> FOSS SOC Engine -> Logstash -> [THIS DETECTOR] -> Alerts -> Kibana

---

## Authors

IITB Trust Lab — SOC ML Team, Summer of Code 2026
