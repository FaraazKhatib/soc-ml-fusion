import json
import pandas as pd

def extract_events(lines):
    rows = []

    for line in lines:
        try:
            evt = json.loads(line)
            module = evt.get("event", {}).get("module")
            
            # We only care about ModSecurity alerts for this plugin
            if module != "modsec_audit_log":
                continue

            # Extract IP
            ip = evt.get("source", {}).get("ip")
            if not ip:
                continue

            # Extract Severity (ModSec: 0=Emergency, 7=Debug. Lower is worse.)
            # We invert it for scoring: Score = 10 - severity
            severity_list = evt.get("severity", ["7"])
            severity_val = int(severity_list[0]) if severity_list else 7
            risk_score = 10 - severity_val

            # Extract Rule ID (to detect scanners triggering multiple rules)
            rule_list = evt.get("rule", {}).get("id", [])
            rule_id = rule_list[0] if rule_list else "unknown"

            rows.append({
                "ip": ip,
                "risk_score": risk_score,
                "rule_id": rule_id,
                "uri": evt.get("url", {}).get("path", "unknown")
            })

        except Exception:
            continue

    return pd.DataFrame(rows)


def update_profiles(profiles, events):
    if events.empty:
        return profiles

    for _, row in events.iterrows():
        ip = row["ip"]

        if ip not in profiles.index:
            profiles.loc[ip] = {
                "total_alerts": 0,
                "accumulated_risk": 0, # Sum of severity scores
                "unique_rules": set(), # Set of rule IDs triggered
                "targeted_uris": set() # Set of paths hit
            }

        profiles.at[ip, "total_alerts"] += 1
        profiles.at[ip, "accumulated_risk"] += row["risk_score"]
        profiles.at[ip, "unique_rules"].add(row["rule_id"])
        profiles.at[ip, "targeted_uris"].add(row["uri"])

    return profiles
