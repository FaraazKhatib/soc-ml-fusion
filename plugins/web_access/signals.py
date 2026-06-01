import json
import pandas as pd

def extract_features(lines):
    if not lines:
        return pd.DataFrame([{
            "total_reqs": 0, "unique_ips": 0, "unique_paths": 0, 
            "error_count": 0, "bytes_sent": 0,
            "top_sources": [], "top_targets": [], "log_sources": []
        }])

    df_data = []
    valid_modules = ["web_apache_access", "mail_apache_access", "waf-nginx-access"]

    for line in lines:
        try:
            evt = json.loads(line)
            module = evt.get("event", {}).get("module")
            if module not in valid_modules:
                continue

            ip = evt.get("source", {}).get("ip", "unknown")
            status = int(evt.get("http", {}).get("response", {}).get("status_code", 200))
            path = evt.get("url", {}).get("path", "/")
            bytes_val = int(evt.get("http", {}).get("response", {}).get("body", {}).get("bytes", 0))

            df_data.append({
                "ip": ip,
                "status": status,
                "path": path,
                "bytes": bytes_val,
                "module": module
            })
        except:
            continue

    if not df_data:
        return pd.DataFrame([{
            "total_reqs": 0, "unique_ips": 0, "unique_paths": 0, 
            "error_count": 0, "bytes_sent": 0,
            "top_sources": [], "top_targets": [], "log_sources": []
        }])

    batch_df = pd.DataFrame(df_data)

    # ---- FORENSICS: Who is doing what? ----
    # 1. Top 3 Source IPs
    top_ips = batch_df["ip"].value_counts().head(3)
    top_sources_list = [f"{ip} ({count})" for ip, count in top_ips.items()]

    # 2. Top 3 Target Paths
    top_paths = batch_df["path"].value_counts().head(3)
    top_targets_list = [f"{path} ({count})" for path, count in top_paths.items()]

    # 3. Which logs contributed?
    log_sources_list = batch_df["module"].unique().tolist()

    stats = {
        "total_reqs": len(batch_df),
        "unique_ips": batch_df["ip"].nunique(),
        "unique_paths": batch_df["path"].nunique(),
        "error_count": len(batch_df[batch_df["status"] >= 400]),
        "bytes_sent": batch_df["bytes"].sum(),
        # Metadata columns (The ML ignores these, but the Alert uses them)
        "top_sources": top_sources_list,
        "top_targets": top_targets_list,
        "log_sources": log_sources_list
    }

    return pd.DataFrame([stats])
