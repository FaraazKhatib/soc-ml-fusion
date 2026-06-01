import pandas as pd
from sklearn.ensemble import IsolationForest

# Allowlist for known scanners/internal IPs if needed
ALLOWLIST_IPS = [
    "127.0.0.1",
    "10.130.171.243" # Example: internal proxy
]

KNOWN_ANOMALIES = set()

def detect(profiles: pd.DataFrame):
    if len(profiles) < 5:
        return pd.DataFrame()

    df = profiles.copy()

    # ---- FEATURE ENGINEERING ----
    # Convert sets to counts for ML
    df["rule_diversity"] = df["unique_rules"].apply(len)
    df["target_diversity"] = df["targeted_uris"].apply(len)
    
    # Filter out Allowlist
    df = df[~df.index.isin(ALLOWLIST_IPS)]

    if df.empty:
        return pd.DataFrame()

    # Features for the model:
    # 1. How many alerts?
    # 2. How severe are they (accumulated)?
    # 3. How many different attack types (rules)?
    features = ["total_alerts", "accumulated_risk", "rule_diversity"]
    X = df[features].fillna(0)

    # ---- MODEL ----
    model = IsolationForest(
        n_estimators=100,
        contamination="auto", # Let the model decide the threshold
        random_state=42
    )

    df["anomaly"] = model.fit_predict(X)
    
    # Get the outliers (-1)
    anomalies = df[df["anomaly"] == -1]

    # ---- HEURISTIC BOOST ----
    # Filter: Only report if Risk is high enough or multiple rules triggered
    # This reduces noise from single false positives
    anomalies = anomalies[
        (anomalies["accumulated_risk"] > 10) | 
        (anomalies["rule_diversity"] > 1)
    ]
    
    # Filter out already alerted IPs to prevent spamming
    new_anomalies = anomalies[~anomalies.index.isin(KNOWN_ANOMALIES)]

    for ip in new_anomalies.index:
        KNOWN_ANOMALIES.add(ip)

    if not new_anomalies.empty:
        print(f"\n[ML] WAF Anomalies Detected:\n{new_anomalies[features].to_string()}")

    return new_anomalies
