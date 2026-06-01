from sklearn.ensemble import IsolationForest

def detect_anomalies(df):
    if len(df) < 5:
        return df.iloc[0:0]

    df = df.copy()

    features = df[["total", "failure", "success", "unique_ips"]]

    model = IsolationForest(
        contamination="auto",
        random_state=42
    )

    df["anomaly"] = model.fit_predict(features)

    return df[df["anomaly"] == -1]
