# SOC ML Brute Force Detector
**IITB Trust Lab — Summer of Code 2026**

Real-time ML-based brute force detection engine for mail authentication logs.
Uses two IsolationForest models (IP-level and User-level) running in parallel.
Alerts print to terminal and are also written as structured JSON for Elasticsearch ingestion.

---

## What it detects

| Attack Type | How |
|---|---|
| Brute force (single IP) | High failed attempts against one user from one IP |
| Password spray | One IP trying many usernames with few attempts each |
| Credential stuffing | Automated spray using leaked password lists |
| Distributed attack | 3+ different IPs coordinating against same user |
| Automated botnet | 5+ IPs simultaneously targeting same user |
| Successful compromise | Login detected within 2 minutes of prior brute force |
| Slow and low attacks | 60-minute window catches attackers who pace slowly |

---

## Quick Start

### 1. Clone the repo

    git clone https://github.com/FaraazKhatib/soc-ml-fusion.git
    cd soc-ml-fusion

### 2. Set your paths

Open ml_fusion.py and change lines 20-21:

    AUTH_LOG_FILE  = "/your/path/to/auth_logs.json"
    ALERTS_FILE    = "/your/path/to/bruteforce_alerts.json"

Those are the only changes you need to make.

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

## Output — Two channels

Every alert goes to both places simultaneously:

    Terminal     Human-readable multi-line format for live monitoring.

    ALERTS_FILE  One JSON object per line, ECS-compatible structure,
                 ready to be ingested into Elasticsearch and visualised on Kibana.

---

## Terminal alert format

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

## JSON alert format (bruteforce_alerts.json)

Each line in ALERTS_FILE is a JSON object structured for ECS compatibility:

    {
      "@timestamp": "2026-06-04 06:04:08 UTC",
      "event": {
        "module":   "bruteforce_detector",
        "category": "authentication",
        "kind":     "alert",
        "type":     ["indicator"],
        "severity": "CRITICAL",
        "action":   "blocked",
        "reason":   "automated_distributed"
      },
      "source":   { "ip": "10.8.10.20" },
      "user":     { "name": "root" },
      "host":     { "name": "mail" },
      "observer": { "name": "ml_fusion_faraaz" },
      "tlsoc": {
        "automated":                 true,
        "auto_signals":              ["distributed_botnet(5_ips_targeting_same_user)"],
        "score":                     0.87,
        "score_ip":                  0.61,
        "score_user":                0.87,
        "failed_attempts":           12,
        "source_attempt_rate":       2.4,
        "unique_ips_targeting_user": 5,
        "pattern":                   "automated_distributed",
        ...
      }
    }

This file can be shipped to Elasticsearch via Filebeat or Logstash for Kibana dashboards.

---

## How the dual model works

    IP Model (model_ip)
    Trained on 11 per-source-IP features.
    Catches: brute force, spray, credential stuffing, fast automated attacks.

    User Model (model_user)
    Trained on 7 per-target-user features.
    Catches: distributed attacks where each individual IP looks innocent
    but the combined pressure on one account is anomalous.

    Final score = max(ip_score, user_score)
    The worst-case perspective always wins.

---

## Automation detection — 3 independent paths

    CV consistency     CV = std_dev / mean of inter-attempt gaps.
                       CV near 0 means perfectly regular timing = tool.
                       Catches Hydra --wait N regardless of speed.

    Speed signals      Sub-0.5s gaps, rate > 4/min, or 3+ attempts in 1s.
                       Requires 2 of 3 signals to avoid false positives.

    Distributed botnet 5+ coordinated IPs against same user.
                       Requires user_failed_attempts >= 5 as confirmation.

Once an IP or user key is confirmed automated it is locked in memory for 1 hour.

---

## Alert deduplication

Each attack is tracked by an identity key:

    3+ IPs targeting same user  ->  DISTRIBUTED:{user}  (one consolidated alert)
    Single IP attack            ->  {source_ip}         (one alert per IP)

Escalation paths that re-fire:
    LOW  -> CRITICAL when score crosses 0.5
    MANUAL -> AUTOMATED when automation is later confirmed

---

## Compromised account detection

A COMPROMISED ACCOUNT alert fires when:
    1. A successful login is detected from an IP
    2. That same IP attacked that same user in the last 2 minutes
    3. The prior attack had at least 3 failed attempts

The 2-minute window is tight by design to avoid false positives from
legitimate users who failed their own password multiple times.

---

## Event filtering

Only processes events where event_action == "login".
CRON jobs, session opens, PAM events, and privilege escalations are ignored.
Events with no source IP are skipped.

---

## Requirements

- Python 3.8 or higher
- Log file in newline-delimited JSON format (one JSON object per line)
- Write access to ALERTS_FILE directory

---

## Expected log format

    {
      "@timestamp": "2026-06-04T06:04:08Z",
      "event": {
        "original": "2026-06-04T06:04:08+00:00 mail sshd[477802]: Invalid user root from 10.8.10.10",
        "action":   "login",
        "outcome":  "failure"
      },
      "user":     { "name": "root" },
      "observer": { "source_host": "mail" },
      "source":   { "ip": "10.8.10.10" }
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

    Sources -> Kafka -> FOSS SOC Engine -> Logstash -> [THIS DETECTOR] -> bruteforce_alerts.json -> Elasticsearch -> Kibana

---

## Authors

IITB Trust Lab — SOC ML Team, Summer of Code 2026
