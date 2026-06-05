import json
import os
import sys
import time
import numpy as np

from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from statistics import mean, stdev

from sklearn.ensemble import IsolationForest


# =====================================================
# CONFIG
# =====================================================

AUTH_LOG_FILE = "/var/log/soc_output/mail_auth.json"

SHORT_WINDOW_MINUTES = 5
LONG_WINDOW_MINUTES  = 60

SHORT_WINDOW = timedelta(minutes=SHORT_WINDOW_MINUTES)
LONG_WINDOW  = timedelta(minutes=LONG_WINDOW_MINUTES)

CV_THRESHOLD   = 0.2
CV_MIN_SAMPLES = 4

SEVERE_THRESHOLD = 0.5

# 3+ distinct IPs targeting the same user → distributed alert
DISTRIBUTED_IP_THRESHOLD = 3

# 5+ distinct IPs targeting the same user → automated botnet
DISTRIBUTED_BOT_THRESHOLD = 5

sys.stdout.reconfigure(line_buffering=True)


# =====================================================
# STATE
# =====================================================

failed_login_tracker      = defaultdict(deque)
long_failed_login_tracker = defaultdict(deque)

last_attempt_event_time = {}
last_source_activity    = {}

source_user_tracker    = defaultdict(deque)
attack_start_time      = {}
recent_attack_activity = {}

source_attack_tracker = defaultdict(deque)
source_burst_tracker  = defaultdict(deque)

active_alerts      = {}
active_auto_states = {}
alert_last_seen    = {}

user_critical_fired = {}

retry_interval_tracker = defaultdict(deque)

ip_to_users_tracker = defaultdict(set)
user_to_ips_tracker = defaultdict(set)

user_ips_window_tracker = defaultdict(deque)

model_ip        = None
model_user      = None

_ip_score_min   = None
_ip_score_max   = None

_user_score_min = None
_user_score_max = None

user_ip_attempts_tracker = defaultdict(lambda: defaultdict(int))
user_ip_first_seen       = defaultdict(dict)


# =====================================================
# HELPERS
# =====================================================

def reset_live_state():
    failed_login_tracker.clear()
    long_failed_login_tracker.clear()
    last_attempt_event_time.clear()
    last_source_activity.clear()
    source_user_tracker.clear()
    attack_start_time.clear()
    recent_attack_activity.clear()
    source_attack_tracker.clear()
    source_burst_tracker.clear()
    retry_interval_tracker.clear()
    ip_to_users_tracker.clear()
    user_to_ips_tracker.clear()
    user_ips_window_tracker.clear()
    user_ip_attempts_tracker.clear()
    user_ip_first_seen.clear()
    active_alerts.clear()
    active_auto_states.clear()
    alert_last_seen.clear()
    user_critical_fired.clear()


def log_print(msg):
    print(msg, flush=True)


def print_alert(timestamp, severity, auto_tag, automated, auto_sigs,
                source_ip, user, host, score, score_ip, score_user,
                pattern, ip_feats, unique_ips_for_user,
                all_users_for_ip, all_ips_for_user):

    attempt_rate       = ip_feats["source_attempt_rate"]
    failed_attempts    = ip_feats["failed_attempts"]
    persistence        = ip_feats["persistence_minutes"]
    unique_users       = ip_feats["unique_users_targeted"]
    is_distributed     = unique_ips_for_user >= DISTRIBUTED_IP_THRESHOLD

    if is_distributed:
        what = (
            f"{unique_ips_for_user} different IPs are all targeting the '{user}' account. "
            f"Each IP makes only a few attempts to stay under the radar, but together "
            f"they have made {failed_attempts} failed login attempts. "
            f"This looks like a coordinated botnet."
        )
    elif "brute_force" in pattern:
        what = (
            f"A single attacker at {source_ip} is repeatedly guessing the password for '{user}'. "
            f"They have made {failed_attempts} failed attempts at around {attempt_rate:.0f} "
            f"tries per minute -- too fast to be a human typing. This is almost certainly a bot."
        )
    elif "credential_stuffing" in pattern:
        what = (
            f"{source_ip} is trying many different usernames ({unique_users} so far), "
            f"likely using a leaked password list. This is called credential stuffing."
        )
    elif "password_spray" in pattern:
        what = (
            f"{source_ip} tried {unique_users} different accounts with only 1-2 guesses each. "
            f"This is a password spray -- trying common passwords across many accounts to avoid lockouts."
        )
    else:
        what = (
            f"{source_ip} has made {failed_attempts} failed login attempt(s) against '{user}'."
        )

    if persistence >= 5:
        what += f" This has been going on for {int(persistence)} minutes."

    if automated and auto_sigs:
        what += f" Detected as automated because: {', '.join(auto_sigs)}."

    lines = [
        f"[{timestamp}] [{severity}] [{auto_tag}]",
        f"  Who:    {source_ip} -> {user} on {host}",
        f"  What:   {what}",
        f"  Score:  {score:.2f}/1.00  (ip model: {score_ip:.2f}, user model: {score_user:.2f})",
        f"  Tags:   {pattern}",
    ]

    if len(all_ips_for_user) > 1:
        lines.append(f"  All IPs targeting '{user}': {', '.join(all_ips_for_user)}")
    if len(all_users_for_ip) > 1:
        lines.append(f"  Accounts tried from {source_ip}: {', '.join(all_users_for_ip)}")

    print("\n".join(lines), flush=True)


def print_compromised(timestamp, user, source_ip, host,
                      failed_attempts, anomaly_score, severity,
                      all_ips_for_user):
    lines = [
        f"[{timestamp}] [CRITICAL] [COMPROMISED ACCOUNT]",
        f"  Who:    {source_ip} -> {user} on {host}",
        f"  What:   After {failed_attempts} failed attempts, this IP just logged in successfully. "
        f"The attacker likely guessed the correct password.",
        f"  Action: Reset {user}'s password immediately and check for suspicious activity.",
        f"  Prior score: {anomaly_score:.2f} ({severity})",
    ]
    if len(all_ips_for_user) > 1:
        lines.append(f"  Other IPs that targeted this account: {', '.join(all_ips_for_user)}")
    print("\n".join(lines), flush=True)


def extract_real_event_timestamp(log):
    event    = log.get("event", {})
    original = str(event.get("original", ""))

    try:
        first_token = original.split()[0]
        return datetime.fromisoformat(first_token)
    except Exception:
        pass

    raise ValueError(
        f"Cannot parse event timestamp from original={original!r}"
    )


def cleanup_datetime_deque(deq, now, window):
    while deq and deq[0] < now - window:
        deq.popleft()


def cleanup_tuple_deque(deq, now, window):
    while deq and deq[0][1] < now - window:
        deq.popleft()


def compute_cv(source_ip):
    intervals = list(retry_interval_tracker[source_ip])

    if len(intervals) < CV_MIN_SAMPLES:
        return 1.0

    interval_mean = mean(intervals)

    if interval_mean == 0:
        return 0.0

    return round(stdev(intervals) / interval_mean, 4)


def cleanup_old_alerts(now):
    expired = [
        key for key, ts in list(alert_last_seen.items())
        if (now - ts).total_seconds() > 3600
    ]
    for key in expired:
        active_alerts.pop(key, None)
        active_auto_states.pop(key, None)
        alert_last_seen.pop(key, None)

    expired_users = [
        u for u, ts in list(user_critical_fired.items())
        if (now - ts).total_seconds() > 3600
    ]
    for u in expired_users:
        user_critical_fired.pop(u, None)


# =====================================================
# NORMALIZE
# =====================================================

def normalize_log(log):
    event    = log.get("event", {})
    user     = log.get("user", {})
    observer = log.get("observer", {})
    source   = log.get("source", {})

    message      = str(event.get("original", "")).lower()
    invalid_user = "invalid user" in message

    try:
        timestamp = extract_real_event_timestamp(log)
    except ValueError as e:
        log_print(f"[SKIP] {e}")
        return None

    return {
        "timestamp":    timestamp,
        "user":         user.get("name", "unknown"),
        "host":         observer.get("source_host", "unknown"),
        "source_ip":    source.get("ip", "unknown"),
        "raw_message":  message,
        "invalid_user": invalid_user,
    }


# =====================================================
# AUTH FILTERS
# =====================================================

def is_auth_failure(log):
    msg = log["raw_message"]
    return (
        "failed password"        in msg or
        "authentication failure" in msg or
        "invalid user"           in msg
    )


def is_auth_success(log):
    msg = log["raw_message"]
    return (
        "accepted password"        in msg or
        "authentication succeeded" in msg or
        "login successful"         in msg
    )


def detect_success_after_bruteforce(log):
    user = log["user"]

    if user not in recent_attack_activity:
        return None

    attack = recent_attack_activity[user]
    delta  = (log["timestamp"] - attack["timestamp"]).total_seconds()

    if delta > 3600:
        return None

    if attack["failed_attempts"] < 3:
        return None

    return attack


def get_account_risk(user):
    user_lower = user.lower()
    if user_lower == "root":
        return 5
    elif user_lower in ("admin", "administrator"):
        return 4
    elif user_lower in ("mysql", "oracle", "postgres"):
        return 3
    return 1


# =====================================================
# FEATURE EXTRACTION — IP LEVEL (model_ip)
# =====================================================

def extract_features(log):
    now       = log["timestamp"]
    user      = log["user"]
    source_ip = log["source_ip"]

    pair_key = f"{source_ip}:{user}"

    for key in (pair_key, user, source_ip):
        failed_login_tracker[key].append(now)
        cleanup_datetime_deque(failed_login_tracker[key], now, SHORT_WINDOW)

    pair_failed_attempts = len(failed_login_tracker[pair_key])
    user_failed_attempts = len(failed_login_tracker[user])
    ip_failed_attempts   = len(failed_login_tracker[source_ip])
    failed_attempts      = max(pair_failed_attempts, user_failed_attempts, ip_failed_attempts)

    for key in (pair_key, user, source_ip):
        long_failed_login_tracker[key].append(now)
        cleanup_datetime_deque(long_failed_login_tracker[key], now, LONG_WINDOW)

    long_failed_attempts = max(
        len(long_failed_login_tracker[pair_key]),
        len(long_failed_login_tracker[user]),
        len(long_failed_login_tracker[source_ip]),
    )

    source_attack_tracker[source_ip].append(now)
    cleanup_datetime_deque(source_attack_tracker[source_ip], now, SHORT_WINDOW)
    source_attempt_rate = round(
        len(source_attack_tracker[source_ip]) / SHORT_WINDOW_MINUTES, 2
    )

    source_burst_tracker[source_ip].append(now)
    cleanup_datetime_deque(source_burst_tracker[source_ip], now, timedelta(seconds=1))
    source_burst_attempts = len(source_burst_tracker[source_ip])

    seconds_since_last_attempt = 300.0
    if pair_key in last_attempt_event_time:
        delta = (now - last_attempt_event_time[pair_key]).total_seconds()
        seconds_since_last_attempt = min(max(delta, 0.0), 300.0)
    last_attempt_event_time[pair_key] = now

    ip_seconds_since_last_attempt = 300.0
    if source_ip in last_source_activity:
        ip_gap = (now - last_source_activity[source_ip]).total_seconds()
        ip_seconds_since_last_attempt = min(max(ip_gap, 0.0), 300.0)

        if ip_gap > 0:
            retry_interval_tracker[source_ip].append(ip_gap)
            while len(retry_interval_tracker[source_ip]) > 8:
                retry_interval_tracker[source_ip].popleft()

    last_source_activity[source_ip] = now
    interval_cv = compute_cv(source_ip)

    source_user_tracker[source_ip].append((user, now))
    cleanup_tuple_deque(source_user_tracker[source_ip], now, SHORT_WINDOW)
    unique_users_targeted = len({u for u, _ in source_user_tracker[source_ip]})

    if source_ip not in attack_start_time:
        attack_start_time[source_ip] = now
    else:
        if source_ip in last_source_activity:
            inactivity = (now - last_source_activity[source_ip]).total_seconds()
            if inactivity > 1800:
                attack_start_time[source_ip] = now

    persistence_minutes = round(
        (now - attack_start_time[source_ip]).total_seconds() / 60, 2
    )

    ip_to_users_tracker[source_ip].add(user)
    user_to_ips_tracker[user].add(source_ip)

    user_ips_window_tracker[user].append((source_ip, now))
    cleanup_tuple_deque(user_ips_window_tracker[user], now, SHORT_WINDOW)
    unique_ips_targeting_user = len({ip for ip, _ in user_ips_window_tracker[user]})

    return {
        "source_ip":                     source_ip,
        "failed_attempts":               failed_attempts,
        "pair_failed_attempts":          pair_failed_attempts,
        "user_failed_attempts":          user_failed_attempts,
        "ip_failed_attempts":            ip_failed_attempts,
        "long_failed_attempts":          long_failed_attempts,
        "seconds_since_last_attempt":    round(seconds_since_last_attempt, 4),
        "ip_seconds_since_last_attempt": round(ip_seconds_since_last_attempt, 4),
        "source_attempt_rate":           source_attempt_rate,
        "source_burst_attempts":         source_burst_attempts,
        "unique_users_targeted":         unique_users_targeted,
        "unique_ips_targeting_user":     unique_ips_targeting_user,
        "persistence_minutes":           persistence_minutes,
        "account_risk":                  get_account_risk(user),
        "user_validity":                 0 if log["invalid_user"] else 1,
        "interval_cv":                   interval_cv,
    }


# =====================================================
# FEATURE EXTRACTION — USER LEVEL (model_user)
# =====================================================

def extract_user_features(log, ip_features):
    now       = log["timestamp"]
    user      = log["user"]
    source_ip = log["source_ip"]

    expired_ips = [
        ip for ip, first_seen in user_ip_first_seen[user].items()
        if now - first_seen > SHORT_WINDOW
    ]
    for ip in expired_ips:
        user_ip_attempts_tracker[user].pop(ip, None)
        user_ip_first_seen[user].pop(ip, None)

    if source_ip not in user_ip_first_seen[user]:
        user_ip_first_seen[user][source_ip] = now

    user_ip_attempts_tracker[user][source_ip] = (
        user_ip_attempts_tracker[user].get(source_ip, 0) + 1
    )

    unique_ips          = len(user_ip_attempts_tracker[user])
    all_attempt_counts  = list(user_ip_attempts_tracker[user].values())
    user_failed         = sum(all_attempt_counts)
    mean_attempts_per_ip = round(mean(all_attempt_counts), 4) if all_attempt_counts else 0.0
    max_attempts_per_ip  = max(all_attempt_counts) if all_attempt_counts else 0

    unique_ips_rate = round(unique_ips / SHORT_WINDOW_MINUTES, 4)

    return {
        "unique_ips_targeting_user": unique_ips,
        "user_failed_attempts":      user_failed,
        "unique_ips_rate":           unique_ips_rate,
        "mean_attempts_per_ip":      mean_attempts_per_ip,
        "max_attempts_per_ip":       max_attempts_per_ip,
        "account_risk":              get_account_risk(user),
        "user_validity":             0 if log["invalid_user"] else 1,
    }


# =====================================================
# FEATURE VECTORS
# =====================================================

def ip_features_to_vector(features):
    return [[
        features["failed_attempts"],
        features["long_failed_attempts"],
        features["seconds_since_last_attempt"],
        features["source_attempt_rate"],
        features["source_burst_attempts"],
        features["unique_users_targeted"],
        features["unique_ips_targeting_user"],
        features["persistence_minutes"],
        features["account_risk"],
        features["user_validity"],
        features["interval_cv"],
    ]]


def user_features_to_vector(features):
    return [[
        features["unique_ips_targeting_user"],
        features["user_failed_attempts"],
        features["unique_ips_rate"],
        features["mean_attempts_per_ip"],
        features["max_attempts_per_ip"],
        features["account_risk"],
        features["user_validity"],
    ]]


# =====================================================
# ANOMALY SCORES
# =====================================================

def _normalize_score(raw, score_min, score_max):
    raw_clamped = max(score_min, min(score_max, raw))
    if score_max == score_min:
        return 0.0
    normalised = (score_max - raw_clamped) / (score_max - score_min)
    return round(float(normalised), 4)


def anomaly_score_ip(vector):
    raw = model_ip.decision_function(vector)[0]
    return _normalize_score(raw, _ip_score_min, _ip_score_max)


def anomaly_score_user(vector):
    raw = model_user.decision_function(vector)[0]
    return _normalize_score(raw, _user_score_min, _user_score_max)


def combined_anomaly_score(ip_vector, user_vector):
    score_ip   = anomaly_score_ip(ip_vector)
    score_user = anomaly_score_user(user_vector)
    final      = round(max(score_ip, score_user), 4)
    return final, score_ip, score_user


def classify_attack(score):
    return "CRITICAL" if score >= SEVERE_THRESHOLD else "LOW"


# =====================================================
# AUTOMATION DETECTION
# =====================================================

def detect_automation(features, unique_ips_for_user):
    signals   = []
    source_ip = features["source_ip"]

    cv_ready  = len(retry_interval_tracker[source_ip]) >= CV_MIN_SAMPLES
    is_bot_cv = cv_ready and features["interval_cv"] < CV_THRESHOLD
    if is_bot_cv:
        signals.append(f"regular_interval(cv={features['interval_cv']})")

    speed_signals = 0
    if features.get("ip_seconds_since_last_attempt", 300.0) < 1.0:
        speed_signals += 1
        signals.append(
            f"sub_second_gap({features['ip_seconds_since_last_attempt']}s)"
        )
    if features["source_attempt_rate"] > 3:
        speed_signals += 1
        signals.append(f"high_rate({features['source_attempt_rate']}/min)")
    if features["source_burst_attempts"] >= 2:
        speed_signals += 1
        signals.append(f"burst({features['source_burst_attempts']}_in_1s)")

    is_bot_speed = speed_signals >= 2

    is_bot_distributed = (
        unique_ips_for_user >= DISTRIBUTED_BOT_THRESHOLD and
        features["user_failed_attempts"] >= DISTRIBUTED_BOT_THRESHOLD
    )
    if is_bot_distributed:
        signals.append(
            f"distributed_botnet({unique_ips_for_user}_ips_targeting_same_user)"
        )

    return (is_bot_cv or is_bot_speed or is_bot_distributed), signals


# =====================================================
# ATTACK PATTERN CLASSIFICATION
# =====================================================

def classify_attack_pattern(features, automated, unique_ips_for_user):
    patterns = []

    unique   = features["unique_users_targeted"]
    pair_att = features["pair_failed_attempts"]
    persist  = features["persistence_minutes"]

    if unique_ips_for_user >= DISTRIBUTED_IP_THRESHOLD:
        if automated:
            patterns.append("automated_distributed")
        else:
            patterns.append("distributed")

    if unique >= 5 and automated:
        patterns.append("credential_stuffing")
    elif unique >= 3 and pair_att <= 3:
        patterns.append("password_spray")

    if pair_att >= 10:
        patterns.append("brute_force")

    if persist >= 30:
        patterns.append(f"persistence({int(persist)}min)")

    if not patterns:
        patterns.append("recon")

    return "+".join(patterns)


# =====================================================
# PIPELINE
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


def train_model():
    global model_ip, model_user
    global _ip_score_min, _ip_score_max
    global _user_score_min, _user_score_max

    logs      = load_logs()
    auth_logs = []

    for raw_log in logs:
        log = normalize_log(raw_log)
        if log is None:
            continue
        if is_auth_failure(log):
            auth_logs.append(log)

    auth_logs.sort(key=lambda x: x["timestamp"])

    if not auth_logs:
        print("No auth failure logs found.")
        sys.exit(1)

    X_train_ip   = []
    X_train_user = []

    for log in auth_logs:
        ip_features   = extract_features(log)
        user_features = extract_user_features(log, ip_features)

        X_train_ip.append(ip_features_to_vector(ip_features)[0])
        X_train_user.append(user_features_to_vector(user_features)[0])

    model_ip = IsolationForest(
        n_estimators=200,
        contamination="auto",
        random_state=42,
    )
    model_ip.fit(X_train_ip)

    ip_scores     = model_ip.decision_function(X_train_ip)
    _ip_score_min = float(ip_scores.min())
    _ip_score_max = float(ip_scores.max())

    model_user = IsolationForest(
        n_estimators=200,
        contamination="auto",
        random_state=42,
    )
    model_user.fit(X_train_user)

    user_scores     = model_user.decision_function(X_train_user)
    _user_score_min = float(user_scores.min())
    _user_score_max = float(user_scores.max())

    reset_live_state()
    print("WATCHDOG ACTIVE", flush=True)


def process_log(raw_log):
    log = normalize_log(raw_log)
    if log is None:
        return

    cleanup_old_alerts(log["timestamp"])

    if is_auth_success(log):
        attack = detect_success_after_bruteforce(log)
        if attack:
            ts               = log["timestamp"].strftime("%Y-%m-%d %H:%M:%S UTC")
            all_ips_for_user = sorted(user_to_ips_tracker.get(log["user"], set()))
            print_compromised(
                timestamp=ts,
                user=log["user"],
                source_ip=log["source_ip"],
                host=log["host"],
                failed_attempts=attack["failed_attempts"],
                anomaly_score=attack["anomaly_score"],
                severity=attack["severity"],
                all_ips_for_user=all_ips_for_user,
            )
        return

    if not is_auth_failure(log):
        return

    ip_feats   = extract_features(log)
    user_feats = extract_user_features(log, ip_feats)

    ip_vec   = ip_features_to_vector(ip_feats)
    user_vec = user_features_to_vector(user_feats)

    score, score_ip, score_user = combined_anomaly_score(ip_vec, user_vec)
    severity                    = classify_attack(score)

    source_ip           = log["source_ip"]
    user                = log["user"]
    unique_ips_for_user = ip_feats["unique_ips_targeting_user"]

    if unique_ips_for_user >= DISTRIBUTED_IP_THRESHOLD:
        identity_key = f"DISTRIBUTED:{user}"
    else:
        identity_key = source_ip

    automated, auto_sigs = detect_automation(ip_feats, unique_ips_for_user)

    alert_last_seen[identity_key] = log["timestamp"]

    previous_severity    = active_alerts.get(identity_key)
    previously_automated = active_auto_states.get(identity_key, False)

    if previously_automated:
        automated = True
        if not auto_sigs:
            auto_sigs = ["historical_bot_memory"]

    pattern = classify_attack_pattern(ip_feats, automated, unique_ips_for_user)

    should_alert = False

    is_distributed_key  = identity_key.startswith("DISTRIBUTED:")
    user_already_crit   = user in user_critical_fired

    if previous_severity is None and not (severity == "CRITICAL" and user_already_crit):
        should_alert = True
    elif previous_severity is None and severity == "LOW":
        should_alert = True
    elif previous_severity == "CRITICAL" and is_distributed_key:
        should_alert = False
    elif previous_severity == "LOW" and severity == "CRITICAL":
        if user_already_crit:
            should_alert = False
        else:
            should_alert = True
    elif not previously_automated and automated and not (is_distributed_key and previous_severity == "CRITICAL"):
        should_alert = True

    if ip_feats["failed_attempts"] >= 3:
        recent_attack_activity[user] = {
            "timestamp":       log["timestamp"],
            "source_ip":       source_ip,
            "failed_attempts": ip_feats["failed_attempts"],
            "anomaly_score":   score,
            "severity":        severity,
        }

    if not should_alert:
        return

    active_alerts[identity_key]      = severity
    active_auto_states[identity_key] = automated

    if severity == "CRITICAL" and user not in user_critical_fired:
        user_critical_fired[user] = log["timestamp"]

    ts       = log["timestamp"].strftime("%Y-%m-%d %H:%M:%S UTC")
    auto_tag = "AUTOMATED" if automated else "MANUAL"

    all_users_for_ip = sorted(ip_to_users_tracker.get(source_ip, set()))
    all_ips_for_user = sorted(user_to_ips_tracker.get(user, set()))

    print_alert(
        timestamp=ts,
        severity=severity,
        auto_tag=auto_tag,
        automated=automated,
        auto_sigs=auto_sigs,
        source_ip=source_ip,
        user=user,
        host=log["host"],
        score=score,
        score_ip=score_ip,
        score_user=score_user,
        pattern=pattern,
        ip_feats=ip_feats,
        unique_ips_for_user=unique_ips_for_user,
        all_users_for_ip=all_users_for_ip,
        all_ips_for_user=all_ips_for_user,
    )


# =====================================================
# WATCHDOG
# =====================================================

def start_watchdog():
    f             = open(AUTH_LOG_FILE, "r")
    f.seek(0, 2)
    current_inode = os.stat(AUTH_LOG_FILE).st_ino

    while True:
        try:
            line = f.readline()

            if not line:
                time.sleep(1)
                try:
                    new_inode = os.stat(AUTH_LOG_FILE).st_ino
                    if new_inode != current_inode:
                        f.close()
                        f             = open(AUTH_LOG_FILE, "r")
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
