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
from plugins.roundcube.signals import extract_events, update_profiles
from plugins.roundcube.detect import detect


with open(os.path.join(BASE_DIR, "config/ml.yaml")) as f:
    cfg = yaml.safe_load(f)

INPUT_FILE = os.path.join(cfg["input"]["directory"], "roundcube_login.json")
STATE_FILE = f"state/roundcube_{cfg['org']}_{cfg['dept']}.pkl"
ALERT_FILE = "alerts/roundcube_alerts.json"
BASELINE_FILE = f"baselines/roundcube_live_profiles_{cfg['org']}_{cfg['dept']}.json"

os.makedirs("alerts", exist_ok=True)
os.makedirs("state", exist_ok=True)
os.makedirs("baselines", exist_ok=True)

print("=" * 60)
print(" TLSOC-ML :: Roundcube UEBA Engine")
print(f" Input : {INPUT_FILE}")
print("=" * 60)


profiles = load_state(STATE_FILE)
if profiles is None:
    profiles = pd.DataFrame(
        columns=["total", "success", "failure", "unique_ips"]
    )
    print("[INFO] New Roundcube baseline started")


tailer = JSONFileTailer(INPUT_FILE)
last_state_save = time.time()


while True:
    lines = tailer.read_new_lines()

    events = extract_events(lines)
    profiles = update_profiles(profiles, events)

    anomalies = detect(profiles)
    if not anomalies.empty:
        anomalies.to_json(ALERT_FILE, orient="records", lines=True)

    if time.time() - last_state_save > cfg["processing"]["state_save_seconds"]:
        save_state(profiles, STATE_FILE)
        profiles.to_json(BASELINE_FILE, orient="index", indent=2)
        last_state_save = time.time()

    time.sleep(cfg["processing"]["batch_seconds"])
