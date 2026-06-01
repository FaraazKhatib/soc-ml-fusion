import pandas as pd
from sklearn.ensemble import IsolationForest

# ---- SOC TUNABLES ----
ALLOWLIST_SENDERS = [
    "root@",
    "mailer-daemon@",
    "postmaster@"
]

MIN_USERS = 10
MIN_EVENTS = 50
MIN_SENT_THRESHOLD = 5

KNOWN_ANOMALIES = set()


def detect(profiles: pd.DataFrame):
    if profiles.empty:
        return pd.DataFrame()

    df = profiles.copy()

    # ---- WARM-UP CHECKS ----
    if len(df) < MIN_USERS:
        print(f"[ML] Warm-up: only {len(df)} users, need {MIN_USERS}")
        return pd.DataFrame()

    if df["total_sent"].sum() < MIN_EVENTS:
        print(
            f"[ML] Warm-up: only {df['total_sent'].sum()} events, "
            f"need {MIN_EVENTS}"
        )
        return pd.DataFrame()

    # ---- FEATURE ENGINEERING ----
    df["unique_rcpt_count"] = df["unique_recipients"].apply(
        lambda x: len(x) if isinstance(x, set) else 0
    )

    df["avg_send_hour"] = df.apply(
        lambda r: (sum(r["sending_hours"]) / len(r["sending_hours"]))
        if isinstance(r["sending_hours"], list) and len(r["sending_hours"]) > 0
        else 0,
        axis=1
    )

    # ---- ALLOWLIST FILTER ----
    for prefix in ALLOWLIST_SENDERS:
        df = df[~df.index.str.startswith(prefix)]

    if df.empty:
        return pd.DataFrame()

    feature_cols = [
        "total_sent",
        "unique_rcpt_count",
        "bounces",
        "avg_send_hour"
    ]

    X = df[feature_cols].fillna(0)

    print("\n[ML] Feature snapshot (first 5 users):")
    print(X.head().to_string())

    # ---- MODEL ----
    model = IsolationForest(
        n_estimators=100,
        contamination="auto",
        random_state=42
    )

    df["anomaly"] = model.fit_predict(X)
    anomalies = df[df["anomaly"] == -1]

    # ---- POST FILTERING ----
    anomalies = anomalies[
        (anomalies["total_sent"] >= MIN_SENT_THRESHOLD) &
        (~anomalies.index.isin(KNOWN_ANOMALIES))
    ]

    if anomalies.empty:
        return pd.DataFrame()

    for user in anomalies.index:
        KNOWN_ANOMALIES.add(user)

    print("\n[ML] Postfix anomalous senders detected:")
    print(anomalies[feature_cols].to_string())

    return anomalies
