import json
import os
import sys
import time

from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from statistics import mean, median

from sklearn.ensemble import IsolationForest


# =====================================================
# CONFIG
# =====================================================

AUTH_LOG_FILE = "/var/log/soc_output/mail_auth.json"

SHORT_WINDOW_MINUTES = 5
LONG_WINDOW_MINUTES = 60

SHORT_WINDOW = timedelta(minutes=SHORT_WINDOW_MINUTES)
LONG_WINDOW = timedelta(minutes=LONG_WINDOW_MINUTES)

FAST_RETRY_THRESHOLD = 1
HIGH_ATTEMPT_RATE_THRESHOLD = 3
BURST_THRESHOLD = 3

AUTOMATION_RETRY_THRESHOLD = 0.5
AUTOMATION_ATTEMPT_RATE = 5
AUTOMATION_BURST_THRESHOLD = 5

sys.stdout.reconfigure(line_buffering=True)


# =====================================================
# STATE
# =====================================================

failed_login_tracker = defaultdict(deque)
long_failed_login_tracker = defaultdict(deque)

last_attempt_event_time = {}
last_source_activity = {}

source_user_tracker = defaultdict(deque)
attack_start_time = {}
recent_attack_activity = {}

source_attack_tracker = defaultdict(deque)
source_burst_tracker = defaultdict(deque)

training_failed_attempts = []
training_retry_times = []
training_attempt_rates = []
training_unique_users = []

baseline = {}
model = None


# =====================================================
# HELPERS
# =====================================================

def log_print(msg):
    print(msg, flush=True)


def extract_real_event_timestamp(log):

    event = log.get("event", {})

    original = event.get(
        "original",
        ""
    )

    try:

        first_token = original.split()[0]

        return datetime.fromisoformat(
            first_token
        )

    except Exception:

        try:

            return datetime.fromisoformat(
                log.get(
                    "@timestamp",
                    ""
                ).replace(
                    "Z",
                    "+00:00"
                )
            )

        except Exception:

            return datetime.now(
                timezone.utc
            )


def cleanup_datetime_deque(deq, now, window):
    while deq and deq[0] < now - window:
        deq.popleft()


def cleanup_tuple_deque(deq, now, window):
    while deq and deq[0][1] < now - window:
        deq.popleft()

def cleanup_recent_attacks(now):

    expired = []

    for user, data in recent_attack_activity.items():

        delta = (
            now -
            data["timestamp"]
        ).total_seconds()

        if delta > 3600:
            expired.append(user)

    for user in expired:
        del recent_attack_activity[user]


# =====================================================
# NORMALIZE
# =====================================================

def normalize_log(log):
    event = log.get("event", {})
    user = log.get("user", {})
    observer = log.get("observer", {})
    source = log.get("source", {})

    message = str(
        event.get("original", "")
    ).lower()

    invalid_user = (
        "invalid user" in message
    )

    return {
        "timestamp": extract_real_event_timestamp(log),
        "user": user.get("name", "unknown"),
        "host": observer.get("source_host", "unknown"),
        "source_ip": source.get("ip", "unknown"),
        "raw_message": message,
        "invalid_user": invalid_user
    }

# =====================================================
# AUTH FAILURE FILTER
# =====================================================

def is_auth_failure(log):
    msg = log["raw_message"]
    return (
        "failed password" in msg or
        "authentication failure" in msg or
        "invalid user" in msg
    )


#Authentication sucesses#

def is_auth_success(log):
    msg = log["raw_message"]

    return (
        "accepted password" in msg or
        "authentication succeeded" in msg or
        "login successful" in msg
    )

def detect_success_after_bruteforce(log):

    user = log["user"]

    if user not in recent_attack_activity:
        return None

    attack = recent_attack_activity[user]

    delta = (
        log["timestamp"] -
        attack["timestamp"]
    ).total_seconds()

    if delta > 3600:
        return None

    if attack["failed_attempts"] < 3:
        return None

    if attack["source_ip"] != log["source_ip"]:
        return None

    return attack


# =====================================================
# ACCOUNT RISK
# =====================================================

def get_account_risk(user):
    user = user.lower()

    if user == "root":
        return 5
    elif user in ["admin", "administrator"]:
        return 4
    elif user in ["mysql", "oracle", "postgres"]:
        return 3

    return 1


# =====================================================
# FEATURE EXTRACTION
# =====================================================

def extract_features(log):
    now = log["timestamp"]
    user = log["user"]
    source_ip = log["source_ip"]

    pair_key = f"{source_ip}:{user}"
    user_key = user
    ip_key = source_ip

    # -------------------------------------------
    # Short-window tracking
    # -------------------------------------------
    for key in [pair_key, user_key, ip_key]:
        failed_login_tracker[key].append(now)
        cleanup_datetime_deque(
            failed_login_tracker[key],
            now,
            SHORT_WINDOW
        )

    pair_failed_attempts = len(
        failed_login_tracker[pair_key]
    )

    user_failed_attempts = len(
        failed_login_tracker[user_key]
    )

    ip_failed_attempts = len(
        failed_login_tracker[ip_key]
    )

    failed_attempts = max(
        pair_failed_attempts,
        user_failed_attempts,
        ip_failed_attempts
    )

    # -------------------------------------------
    # Long-window tracking
    # -------------------------------------------
    for key in [pair_key, user_key, ip_key]:
        long_failed_login_tracker[key].append(now)
        cleanup_datetime_deque(
            long_failed_login_tracker[key],
            now,
            LONG_WINDOW
        )

    long_failed_attempts = max(
        len(long_failed_login_tracker[pair_key]),
        len(long_failed_login_tracker[user_key]),
        len(long_failed_login_tracker[ip_key])
    )

    # -------------------------------------------
    # Source IP attempt rate
    # -------------------------------------------
    source_attack_tracker[source_ip].append(now)

    cleanup_datetime_deque(
        source_attack_tracker[source_ip],
        now,
        SHORT_WINDOW
    )

    source_attempt_rate = round(
        len(source_attack_tracker[source_ip]) /
        SHORT_WINDOW_MINUTES,
        2
    )

    # -------------------------------------------
    # Burst detection
    # -------------------------------------------
    source_burst_tracker[source_ip].append(now)

    cleanup_datetime_deque(
        source_burst_tracker[source_ip],
        now,
        timedelta(seconds=1)
    )

    source_burst_attempts = len(
        source_burst_tracker[source_ip]
    )

    # -------------------------------------------
    # Retry delta
    # -------------------------------------------
    seconds_since_last_attempt = 300

    if pair_key in last_attempt_event_time:

        delta = (
            now -
            last_attempt_event_time[pair_key]
        ).total_seconds()

        if delta < 0:

            delta = 0

        seconds_since_last_attempt = min(
            delta,
            300
        )

    last_attempt_event_time[pair_key] = now
    # -------------------------------------------
    # Password spraying
    # -------------------------------------------
    source_user_tracker[source_ip].append(
        (user, now)
    )

    cleanup_tuple_deque(
        source_user_tracker[source_ip],
        now,
        SHORT_WINDOW
    )

    unique_users_targeted = len(
        {u for u, _ in source_user_tracker[source_ip]}
    )

    # -------------------------------------------
    # Persistence
    # -------------------------------------------
    if source_ip not in attack_start_time:

        attack_start_time[source_ip] = now

    else:

        inactivity = (
                now -
            last_source_activity[source_ip]
        ).total_seconds()

        if inactivity > 1800:

            attack_start_time[source_ip] = now

    last_source_activity[source_ip] = now

    persistence_minutes = round(
        (
            now -
            attack_start_time[source_ip]
        ).total_seconds() / 60,
        2
    )

    return {
         "failed_attempts": failed_attempts,
        "pair_failed_attempts": pair_failed_attempts,
        "user_failed_attempts": user_failed_attempts,
        "ip_failed_attempts": ip_failed_attempts,
        "long_failed_attempts": long_failed_attempts,
        "seconds_since_last_attempt": round(
            seconds_since_last_attempt,
            4
        ),
        "source_attempt_rate": source_attempt_rate,
        "source_burst_attempts": source_burst_attempts,
        "unique_users_targeted": unique_users_targeted,
        "persistence_minutes": persistence_minutes,
        "account_risk": get_account_risk(user),

        "user_validity": 0 if log["invalid_user"] else 1
    }


# =====================================================
# VECTOR
# =====================================================

def features_to_vector(features):
    return [[
        features["failed_attempts"],
        features["long_failed_attempts"],
        features["seconds_since_last_attempt"],
        features["source_attempt_rate"],
        features["source_burst_attempts"],
        features["unique_users_targeted"],
        features["persistence_minutes"],
        features["account_risk"],
        features["user_validity"]
    ]]


# =====================================================
# RISK SCORE
# =====================================================

def calculate_risk_score(features):
    score = 0
    reasons = []

    if features["failed_attempts"] >= 5:
        score += 15
        reasons.append("multiple_failed_attempts")

    if features["failed_attempts"] >= 10:
        score += 20
        reasons.append("high_failed_attempts")

    if features["long_failed_attempts"] >= 15:
        score += 15
        reasons.append("persistent_failures")

    if features["seconds_since_last_attempt"] < FAST_RETRY_THRESHOLD:
        score += 8
        reasons.append("fast_retries")

    if features["source_attempt_rate"] >= HIGH_ATTEMPT_RATE_THRESHOLD:
        score += 20
        reasons.append("high_source_attempt_rate")

    if features["source_burst_attempts"] >= BURST_THRESHOLD:
        score += 20
        reasons.append("burst_attack")

    if features["unique_users_targeted"] >= 5:
        score += 15
        reasons.append("password_spraying")

    if features["persistence_minutes"] >= 30:
        score += 10
        reasons.append("persistent_attack")

    if features["user_validity"] == 1:

        if features["failed_attempts"] >= 20:
            score += 25
            reasons.append("valid_account_targeted")

        elif features["failed_attempts"] >= 10:
            score += 15
            reasons.append("valid_account_targeted")

        elif features["failed_attempts"] >= 4:
            score += 5
            reasons.append("valid_account_targeted")
        else:
            score -= 15
            reasons.append("invalid_account_targeted")

    score += features["account_risk"] * 5

    score = max(score, 0)

    return min(score, 100), reasons


# =====================================================
# CLASSIFY
# =====================================================

def classify_attack(score):
    if score >= 80:
        return "CRITICAL"
    elif score >= 60:
        return "HIGH"
    elif score >= 40:
        return "MEDIUM"
    elif score >= 20:
        return "LOW"
    return "NORMAL"


# =====================================================
# AUTOMATION
# =====================================================

def detect_automation(features):
    automation_score = 0

    if features["seconds_since_last_attempt"] < AUTOMATION_RETRY_THRESHOLD:
        automation_score += 1

    if features["source_attempt_rate"] >= AUTOMATION_ATTEMPT_RATE:
        automation_score += 1

    if features["source_burst_attempts"] >= AUTOMATION_BURST_THRESHOLD:
        automation_score += 1

    if features["unique_users_targeted"] >= 5:
        automation_score += 1

    return automation_score >= 2


# =====================================================
# LOAD LOGS
# =====================================================

def load_logs():
    logs = []

    with open(AUTH_LOG_FILE, "r") as f:
        for line in f:
            try:
                logs.append(json.loads(line))
            except Exception:
                continue

    return logs


# =====================================================
# TRAIN
# =====================================================

def train_model():
    global model, baseline

    logs = load_logs()
    auth_logs = []

    for raw_log in logs:
        log = normalize_log(raw_log)
        if is_auth_failure(log):
            auth_logs.append(log)

    auth_logs.sort(key=lambda x: x["timestamp"])

    if not auth_logs:
        print("No auth failure logs found.")
        sys.exit(1)

    X_train = []

    for log in auth_logs:
        features = extract_features(log)

        X_train.append(
            features_to_vector(features)[0]
        )

        training_failed_attempts.append(
            features["failed_attempts"]
        )

        training_retry_times.append(
            features["seconds_since_last_attempt"]
        )

        training_attempt_rates.append(
            features["source_attempt_rate"]
        )

        training_unique_users.append(
            features["unique_users_targeted"]
        )

    model = IsolationForest(
        n_estimators=100,
        contamination=0.02,
        random_state=42
    )

    model.fit(X_train)

    baseline = {
        "avg_failed_attempts": round(
            mean(training_failed_attempts), 2
        ),
        "median_retry_time": round(
            median(training_retry_times), 2
        ),
        "avg_source_attempt_rate": round(
            mean(training_attempt_rates), 2
        ),
        "avg_unique_users": round(
            mean(training_unique_users), 2
        )
    }

    log_print("WATCHDOG ACTIVE")


# =====================================================
# LIVE DETECTION
# =====================================================

def process_log(raw_log):
    log = normalize_log(raw_log)

    if is_auth_success(log):

        attack = detect_success_after_bruteforce(log)

        if attack:

            timestamp = datetime.now(
                timezone.utc
            ).strftime(
                "%Y-%m-%d %H:%M:%S UTC"
            )

            log_print(
                f"[{timestamp}] "
                f"[COMPROMISED_ACCOUNT] "
                f"severity=CRITICAL "
                f"user={log['user']} "
                f"source_ip={log['source_ip']} "
                f"target_host={log['host']} "
                f"risk=100 "
                f"previous_risk={attack['risk']} "
                f"failed_attempts={attack['failed_attempts']} "
                f"reason=successful_login_after_bruteforce"
            )

        return

    if not is_auth_failure(log):
        return

    features = extract_features(log)

    prediction = model.predict(
        features_to_vector(features)
    )[0]

    ml_anomaly = (prediction == -1)

    risk_score, reasons = calculate_risk_score(features)

    if ml_anomaly and (
        features["pair_failed_attempts"] >= 3 or
        features["user_failed_attempts"] >= 3 or
        features["ip_failed_attempts"] >= 3
    ):
        risk_score = min(risk_score + 20, 100)
        reasons.append("ml_anomaly_detected")

    severity = classify_attack(risk_score)

    if severity != "NORMAL":

        recent_attack_activity[log["user"]] = {
            "timestamp": log["timestamp"],
            "source_ip": log["source_ip"],
            "failed_attempts": features["failed_attempts"],
            "risk": risk_score,
            "severity": severity
        }

    timestamp = datetime.now(
        timezone.utc
    ).strftime(
        "%Y-%m-%d %H:%M:%S UTC"
    )

    if severity == "NORMAL":
        log_print(
            f"[{timestamp}] [NORMAL] "
            f"user={log['user']} "
            f"source_ip={log['source_ip']} "
            f"risk={risk_score}"
        )
        return

    automated = detect_automation(features)

    attack_type = (
        "AUTOMATED_BRUTE_FORCE"
        if automated
        else "MANUAL_BRUTE_FORCE"
    )

    log_print(
        f"[{timestamp}] "
        f"[{attack_type}] "
        f"severity={severity} "
        f"user={log['user']} "
        f"source_ip={log['source_ip']} "
        f"target_host={log['host']} "
        f"risk={risk_score} "
        f"reasons={reasons} "
        f"features={features}"
    )


# =====================================================
# WATCHDOG
# =====================================================

def start_watchdog():
    f = open(AUTH_LOG_FILE, "r")
    f.seek(0, 2)

    current_inode = os.stat(
        AUTH_LOG_FILE
    ).st_ino

    while True:
        try:
            line = f.readline()

            if not line:
                time.sleep(1)

                try:
                    new_inode = os.stat(
                        AUTH_LOG_FILE
                    ).st_ino

                    if new_inode != current_inode:
                        f.close()
                        f = open(AUTH_LOG_FILE, "r")
                        current_inode = new_inode

                except FileNotFoundError:
                    pass

                continue

            try:
                raw_log = json.loads(line)
                process_log(raw_log)
            except Exception:
                continue

        except KeyboardInterrupt:
            f.close()
            break


# =====================================================
# MAIN
# =====================================================

if __name__ == "__main__":
    train_model()
    start_watchdog()
