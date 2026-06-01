import pandas as pd
from sklearn.ensemble import IsolationForest
pd.set_option('future.no_silent_downcasting', True)
# How many historical batches to keep for training (e.g. last 1000 intervals)
HISTORY_SIZE = 1000 

def detect(history: pd.DataFrame, current_batch: pd.DataFrame):
    # 1. Add current batch to history
    updated_history = pd.concat([history, current_batch], ignore_index=True)
    
    # Keep history size manageable (Sliding Window)
    if len(updated_history) > HISTORY_SIZE:
        updated_history = updated_history.iloc[-HISTORY_SIZE:]

    # 2. Warm-up
    if len(updated_history) < 20:
        return pd.DataFrame(), updated_history

    # 3. Feature Engineering
    df = updated_history.copy()
    
    # Calculate Ratios (Normalize volume)
    # Avoid division by zero
    df["reqs"] = df["total_reqs"].replace(0, 1) 
    
    df["ip_diversity"] = df["unique_ips"] / df["reqs"]
    df["path_diversity"] = df["unique_paths"] / df["reqs"]
    df["error_rate"] = df["error_count"] / df["reqs"]
    
    # Select Features
    features = ["total_reqs", "ip_diversity", "path_diversity", "error_rate"]
    X = df[features].fillna(0)

    # 4. Model
    model = IsolationForest(contamination=0.05, random_state=42)
    model.fit(X)

    # 5. Predict ONLY the current batch (the last row)
    last_row_features = X.iloc[[-1]]
    is_anomaly = model.predict(last_row_features)[0]
    
    anomalies = pd.DataFrame()
    if is_anomaly == -1 and current_batch.iloc[0]["total_reqs"] > 5:
        # We only alert if there was actual traffic (ignore quiet anomalies)
        score = model.decision_function(last_row_features)[0]
        current_batch["anomaly_score"] = score
        anomalies = current_batch.copy()
        
        print(f"\n[ML] GLOBAL TRAFFIC ANOMALY DETECTED:")
        print(f"Stats: {current_batch.to_dict(orient='records')[0]}")
        print(f"Reason: Score {score:.3f} (Low is bad)\n")

    return anomalies, updated_history
