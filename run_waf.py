#!/usr/bin/env python3

import os
import sys
import time
import yaml
import pandas as pd

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

from core.reader import JSONFileTailer
from core.state import load_state, save_state
from plugins.waf.signals import extract_events, update_profiles
from plugins.waf.detect import detect

# Load Config
with open(os.path.join(BASE_DIR, "config/ml.yaml")) as f:
    cfg = yaml.safe_load(f)

# Note: We are reading modsec_audit_log.json
INPUT_FILE = os.path.join(cfg["input"]["directory"], "modsec_audit_log.json")
STATE_FILE = f"state/waf_{cfg['org']}_{cfg['dept']}.pkl"
ALERT_FILE = "alerts/waf_alerts.json"

os.makedirs("alerts", exist_ok=True)
os.makedirs("state", exist_ok=True)

print("=" * 60)
print(" TLSOC-ML :: WAF Threat Detection Engine")
print(f" Input : {INPUT_FILE}")
print("=" * 60)

# Init State
profiles = load_state(STATE_FILE)
if profiles is None:
    profiles = pd.DataFrame(columns=[
        "total_alerts", "accumulated_risk", "unique_rules", "targeted_uris"
    ])
    print("[INFO] New WAF baseline started")

tailer = JSONFileTailer(INPUT_FILE)
last_state_save = time.time()

while True:
    try:
        lines = tailer.read_new_lines()
        
        # 1. Extract
        events = extract_events(lines)
        
        # 2. Update State
        profiles = update_profiles(profiles, events)

        # 3. Detect
        anomalies = detect(profiles)
        
        if not anomalies.empty:
            # Flatten sets for JSON serialization
            out_df = anomalies.copy()
            out_df["unique_rules"] = out_df["unique_rules"].apply(list)
            out_df["targeted_uris"] = out_df["targeted_uris"].apply(list)
            
            # Append to alerts file
            with open(ALERT_FILE, "a") as f:
                out_df.to_json(f, orient="records", lines=True)

        # 4. Save State periodically
        if time.time() - last_state_save > cfg["processing"]["state_save_seconds"]:
            save_state(profiles, STATE_FILE)
            last_state_save = time.time()
            # print(f"[DEBUG] WAF State Saved. Tracking {len(profiles)} IPs.")

        time.sleep(cfg["processing"]["batch_seconds"])

    except KeyboardInterrupt:
        break
    except Exception as e:
        print(f"[ERROR] {e}")
        time.sleep(5)
