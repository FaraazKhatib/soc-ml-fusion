#!/usr/bin/env python3

import subprocess
import sys
import time
import signal

ML_SCRIPTS = {
    "1": ("Postfix UEBA", "run_postfix.py"),
    "2": ("Roundcube UEBA", "run.py"),
    # future
    "3": ("Waf Threat Detect", "run_waf.py"),
    "4": ("Web Access Analytics", "run_web_access.py")
}

running_processes = []


def print_menu():
    print("\n================ TLSOC-ML Launcher ================")
    for k, v in ML_SCRIPTS.items():
        print(f"{k}. {v[0]}")
    print("===================================================")
    print("Select ML engines to start (comma separated)")
    print("Example: 1,2,3\n")


def start_engines(selection):
    for key in selection:
        if key not in ML_SCRIPTS:
            print(f"[WARN] Invalid selection: {key}")
            continue

        name, script = ML_SCRIPTS[key]
        print(f"[START] {name}")

        p = subprocess.Popen(
            [sys.executable, script],
            cwd="/opt/TLSOC-ML"
        )
        running_processes.append((name, p))


def shutdown_handler(sig, frame):
    print("\n[SHUTDOWN] Stopping all ML engines...")
    for name, p in running_processes:
        print(f"[STOP] {name}")
        p.terminate()
    sys.exit(0)


if __name__ == "__main__":
    signal.signal(signal.SIGINT, shutdown_handler)
    signal.signal(signal.SIGTERM, shutdown_handler)

    print_menu()
    choice = input("Enter choice: ").strip()
    selected = [x.strip() for x in choice.split(",")]

    start_engines(selected)

    print("\n[INFO] TLSOC-ML engines running. Press Ctrl+C to stop.\n")

    while True:
        time.sleep(5)

        for name, p in running_processes:
            if p.poll() is not None:
                print(f"[CRASH] {name} stopped unexpectedly!")
