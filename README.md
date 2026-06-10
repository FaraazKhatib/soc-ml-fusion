# SOC ML Brute Force Detector
**IITB Trust Lab — Summer of Code 2026**

Real-time ML-based brute force detection engine for mail authentication logs.
Uses two IsolationForest models (IP-level and User-level) running in parallel
to catch attacks that a single model cannot detect on its own.

---

## What it detects

| Attack Type | How |
|---|---|
| Brute force (single IP) | High failed attempts against one user from one IP |
| Password spray | One IP trying many usernames with few attempts each |
| Credential stuffing | Automated spray using leaked password lists |
| Distributed attack | 3+ different IPs coordinating against same user |
| Automated botnet | 5+ IPs simultaneously targeting same user |
| Successful compromise | Login detected after prior brute force activity |
| Slow and low attacks | 60-minute window catches attackers who pace slowly |

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

If you are on a shared server or do not have sudo access:

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

## How the dual model works

Two IsolationForest models run on every event:

    IP Model (model_ip)
    Trained on per-source-IP features.
    Catches: brute force, spray, credential stuffing, fast automated attacks.
    Features: failed attempts, attempt rate, burst, CV interval, persistence, etc.

    User Model (model_user)
    Trained on per-target-user features.
    Catches: distributed attacks where each IP looks innocent individually
    but the combined pressure on one account is anomalous.
    Features: unique IPs targeting user, rate of new IPs joining, mean attempts per IP.

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
              Detected as automated because: distributed_botnet(5_ips_targeting_same_user).
      Score:  0.87/1.00  (ip model: 0.61, user model: 0.87)
      Tags:   automated_distributed
      All IPs targeting 'root': 10.8.10.10, 10.8.10.20, 10.8.10.30, 10.8.10.40, 10.8.10.50

    [2026-06-04 06:10:22 UTC] [CRITICAL] [COMPROMISED ACCOUNT]
      Who:    10.8.10.10 -> root on mail
      What:   After 8 failed attempts, this IP just logged in successfully.
              The attacker likely guessed the correct password.
      Action: Reset root's password immediately and check for suspicious activity.
      Prior score: 0.91 (CRITICAL)

---

## Identity key and alert deduplication

Each alert is tracked by an identity key so the same attack does not spam the terminal:

    3+ IPs targeting same user  ->  key = DISTRIBUTED:{user}   (one consolidated alert)
    Single IP attack            ->  key = {source_ip}          (one alert per IP)

Escalation still fires: a LOW alert re-fires as CRITICAL when the score crosses 0.5.
A MANUAL alert re-fires as AUTOMATED when automation is confirmed.

---

## Automation detection — 3 independent paths

    CV consistency     CV = std_dev / mean of inter-attempt gaps.
                       CV near 0 means perfectly regular timing = tool.
                       Works for Hydra --wait N regardless of speed.

    Speed signals      Sub-0.5s gaps, rate > 4/min, or 3+ attempts in 1 second.
                       Requires 2 signals to avoid false positives.

    Distributed botnet 5+ coordinated IPs against same user.
                       A human cannot operate 5 machines simultaneously.

---

## Event detection

Uses structured event fields (event_action, event_outcome) when available,
with raw message text as fallback. Only processes login events — cron jobs,
session opens, and privilege escalations are ignored.

---

## Requirements

- Python 3.8 or higher
- Log file in newline-delimited JSON format (one JSON object per line)

---

## Expected log format

    {
      "@timestamp": "2026-06-04T06:04:08Z",
      "event": {
        "original": "2026-06-04T06:04:08+00:00 mail sshd[477802]: Invalid user root from 10.8.10.10",
        "action": "login",
        "outcome": "failure"
      },
      "user": { "name": "root" },
      "observer": { "source_host": "mail" },
      "source": { "ip": "10.8.10.10" }
    }

---

## Project structure

    soc-ml-fusion/
    ├── ml_fusion.py          — main detection engine (dual model)
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
