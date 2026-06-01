import json
import pandas as pd
from datetime import datetime

def extract_events(lines):
    rows = []

    for line in lines:
        try:
            evt = json.loads(line)

            sender = evt.get("email", {}).get("from")
            recipient = evt.get("email", {}).get("to")
            outcome = evt.get("event", {}).get("outcome")
            ts = evt.get("@timestamp")

            if not sender or not ts:
                continue

            hour = datetime.fromisoformat(ts.replace("Z", "")).hour

            rows.append({
                "sender": sender,
                "recipient": recipient,
                "bounced": 1 if outcome == "bounced" else 0,
                "hour": hour
            })

        except Exception:
            continue

    return pd.DataFrame(rows)


def update_profiles(profiles, events):
    if events.empty:
        return profiles

    for _, row in events.iterrows():
        sender = row["sender"]

        if sender not in profiles.index:
            profiles.loc[sender] = {
                "total_sent": 0,
                "unique_recipients": set(),
                "bounces": 0,
                "sending_hours": []
            }

        profiles.at[sender, "total_sent"] += 1

        if row["recipient"]:
            profiles.at[sender, "unique_recipients"].add(row["recipient"])

        profiles.at[sender, "bounces"] += row["bounced"]
        profiles.at[sender, "sending_hours"].append(row["hour"])

    return profiles
