from core.anomaly import detect_anomalies

def detect(profiles):
    # Ensure required columns exist
    required = ["total", "success", "failure", "unique_ips"]
    for col in required:
        if col not in profiles.columns:
            profiles[col] = 0

    # Skip detection until baseline exists
    if len(profiles) < 3:
        return profiles.iloc[0:0]

    return detect_anomalies(profiles.copy())
