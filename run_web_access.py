#!/usr/bin/env python3

import os
import sys
import time
import yaml
import pandas as pd
import signal
import atexit

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

from core.reader import JSONFileTailer
from core.state import load_state, save_state
from plugins.web_access.signals import extract_features
from plugins.web_access.detect import detect

# ================= CONFIG =================
with open(os.path.join(BASE_DIR, "config/ml.yaml")) as f:
    cfg = yaml.safe_load(f)

DEBUG = cfg.get("debug", False)
LOG_FILES = ["web_apache_access.json", "mail_apache_access.json", "waf-nginx-access.json"]

# State now stores the DATAFRAME of history, not a dict of users
STATE_FILE = f"state/web_global_history_{cfg['org']}_{cfg['dept']}.pkl"
ALERT_FILE = "alerts/web_global_alerts.json"

os.makedirs("alerts", exist_ok=True)
os.makedirs("state", exist_ok=True)

print("=" * 60)
print(" TLSOC-ML :: Global Web Traffic Analyzer")
print(" Strategy: Time-Series Anomaly Detection (No IP Profiling)")
print("=" * 60)

# ================= STATE =================
history = load_state(STATE_FILE)
if history is None or not isinstance(history, pd.DataFrame):
    history = pd.DataFrame(columns=[
        "total_reqs", "unique_ips", "unique_paths", "error_count", "bytes_sent"
    ])
    print("[INFO] New Global History started")
else:
    print(f"[INFO] Loaded {len(history)} historical batch samples")

# ================= HANDLERS =================
def shutdown_handler(signum=None, frame=None):
    print("\n[SHUTDOWN] Saving history state...")
    save_state(history, STATE_FILE)
    sys.exit(0)

signal.signal(signal.SIGINT, shutdown_handler)
signal.signal(signal.SIGTERM, shutdown_handler)

tailers = [JSONFileTailer(os.path.join(cfg["input"]["directory"], f)) for f in LOG_FILES if os.path.exists(os.path.join(cfg["input"]["directory"], f))]

# ================= LOOP =================
while True:
    try:
        all_lines = []
        for tailer in tailers:
            all_lines.extend(tailer.read_new_lines())

        if DEBUG:
            print(f"[DEBUG] Batch processing: {len(all_lines)} log lines")

        # 1. Extract ONE row of stats for this batch
        current_batch_df = extract_features(all_lines)

        # 2. Detect & Update History
        # We pass the full history + current batch to the model
        anomalies, history = detect(history, current_batch_df)

        if not anomalies.empty:
            with open(ALERT_FILE, "a") as f:
                anomalies.to_json(f, orient="records", lines=True)

        # Auto-save occasionally
        if len(history) % 10 == 0: # Save every 10 batches roughly
            save_state(history, STATE_FILE)

        time.sleep(cfg["processing"]["batch_seconds"])

    except Exception as e:
        print(f"[ERROR] {e}")
        time.sleep(5)
