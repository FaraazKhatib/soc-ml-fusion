#!/usr/bin/env python3

import os
import sys
import time
import yaml
import signal
import atexit
import pandas as pd

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

from core.reader import JSONFileTailer
from core.state import load_state, save_state
from plugins.postfix.signals import extract_events, update_profiles
from plugins.postfix.detect import detect


# ================= LOAD CONFIG =================
with open(os.path.join(BASE_DIR, "config/ml.yaml")) as f:
    cfg = yaml.safe_load(f)

DEBUG = cfg.get("debug", False)

INPUT_FILE = os.path.join(cfg["input"]["directory"], "postfix.json")
STATE_FILE = f"state/postfix_{cfg['org']}_{cfg['dept']}.pkl"
ALERT_FILE = "alerts/postfix_alerts.json"
BASELINE_FILE = f"baselines/postfix_live_profiles_{cfg['org']}_{cfg['dept']}.json"

os.makedirs("alerts", exist_ok=True)
os.makedirs("state", exist_ok=True)
os.makedirs("baselines", exist_ok=True)


print("=" * 60)
print(" TLSOC-ML :: Postfix UEBA Engine (DEBUG MODE)")
print(f" Input : {INPUT_FILE}")
print("=" * 60)


# ================= BASELINE WRITER =================
def write_live_baseline():
    global profiles
    if profiles.empty:
        return

    df = profiles.copy()

    df["unique_recipients"] = df["unique_recipients"].apply(
        lambda x: list(x) if isinstance(x, set) else []
    )

    df["avg_send_hour"] = df["sending_hours"].apply(
        lambda x: round(sum(x) / len(x), 2)
        if isinstance(x, list) and len(x) > 0 else 0
    )

    df.drop(columns=["sending_hours"], errors="ignore", inplace=True)
    df.to_json(BASELINE_FILE, orient="index", indent=2)

    if DEBUG:
        print(f"[DEBUG] Baseline written → {BASELINE_FILE}")


# ================= SAFE SHUTDOWN =================
def shutdown_handler(signum=None, frame=None):
    print("\n[SHUTDOWN] Saving baseline and ML state...")
    write_live_baseline()
    save_state(profiles, STATE_FILE)
    print("[SHUTDOWN] Done")
    sys.exit(0)


signal.signal(signal.SIGINT, shutdown_handler)
signal.signal(signal.SIGTERM, shutdown_handler)
atexit.register(shutdown_handler)


# ================= LOAD STATE =================
profiles = load_state(STATE_FILE)
if profiles is None:
    profiles = pd.DataFrame(columns=[
        "total_sent",
        "unique_recipients",
        "bounces",
        "sending_hours"
    ])
    print("[INFO] New Postfix baseline started")
else:
    print("[INFO] Loaded existing Postfix baseline")


# ================= TAILER =================
tailer = JSONFileTailer(INPUT_FILE)
last_state_save = time.time()


# ================= MAIN LOOP =================
while True:
    try:
        lines = tailer.read_new_lines()

        if DEBUG:
            print(f"[DEBUG] Lines read: {len(lines)}")

        events = extract_events(lines)

        if DEBUG:
            print(f"[DEBUG] Events extracted: {len(events)}")

        if not events.empty:
            profiles = update_profiles(profiles, events)

            if DEBUG:
                print(
                    f"[DEBUG] Baseline updated | "
                    f"users={len(profiles)} | "
                    f"total_sent={profiles['total_sent'].sum()}"
                )

            write_live_baseline()

        if DEBUG:
            print(
                f"[DEBUG] ML warm-up check | "
                f"users={len(profiles)} | "
                f"events={profiles['total_sent'].sum()}"
            )

        anomalies = detect(profiles)

        if DEBUG:
            print(f"[DEBUG] ML anomalies found: {len(anomalies)}")

        if not anomalies.empty:
            anomalies.to_json(ALERT_FILE, orient="records", lines=True)
            print(f"[ALERT] {len(anomalies)} anomalous mail senders")

        if time.time() - last_state_save > cfg["processing"]["state_save_seconds"]:
            save_state(profiles, STATE_FILE)
            if DEBUG:
                print("[DEBUG] ML state autosaved")
            last_state_save = time.time()

        time.sleep(cfg["processing"]["batch_seconds"])

    except Exception as e:
        print(f"[ERROR] {e}")
        shutdown_handler()
