import json
import pandas as pd

def extract_events(lines):
    rows = []

    for line in lines:
        try:
            evt = json.loads(line)

            user = evt.get("user", {}).get("name")
            outcome = evt.get("event", {}).get("outcome")
            ip = evt.get("source", {}).get("ip")

            if not user or not outcome:
                continue

            rows.append({
                "user": user,
                "success": 1 if outcome == "success" else 0,
                "failure": 1 if outcome == "failure" else 0,
                "ip": ip
            })

        except Exception:
            continue

    return pd.DataFrame(rows)


def update_profiles(profiles, events):
    if events.empty:
        return profiles

    for _, row in events.iterrows():
        user = row["user"]

        if user not in profiles.index:
            profiles.loc[user] = {
                "total": 0,
                "success": 0,
                "failure": 0,
                "unique_ips": set()
            }

        profiles.at[user, "total"] += 1
        profiles.at[user, "success"] += row["success"]
        profiles.at[user, "failure"] += row["failure"]

        if row["ip"]:
            profiles.at[user, "unique_ips"].add(row["ip"])

    return profiles
