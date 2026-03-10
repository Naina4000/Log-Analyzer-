from collections import defaultdict


# ---------------- SSH DETECTIONS ---------------- #

def detect_bruteforce(parsed_logs, threshold, time_window):
    failed_attempts = defaultdict(list)
    alerts = []

    for log in parsed_logs:
        if log.get("log_type") == "SSH" and log["status"] == "FAILED":
            failed_attempts[log["ip"]].append(log["timestamp"])

    for ip, timestamps in failed_attempts.items():
        timestamps.sort()

        for i in range(len(timestamps) - threshold + 1):
            start_time = timestamps[i]
            end_time = timestamps[i + threshold - 1]

            if (end_time - start_time).total_seconds() <= time_window:
                alerts.append({
                    "type": "Brute Force",
                    "ip": ip,
                    "severity": "HIGH",
                    "start_time": start_time,
                    "end_time": end_time
                })
                break

    return alerts


def detect_username_enumeration(parsed_logs, threshold, time_window):
    ip_user_map = defaultdict(list)
    alerts = []

    for log in parsed_logs:
        if log.get("log_type") == "SSH" and log["status"] == "FAILED":
            ip_user_map[log["ip"]].append((log["timestamp"], log["username"]))

    for ip, entries in ip_user_map.items():
        entries.sort()

        for i in range(len(entries)):
            start_time = entries[i][0]
            users = set()

            for j in range(i, len(entries)):
                if (entries[j][0] - start_time).total_seconds() <= time_window:
                    users.add(entries[j][1])
                    if len(users) >= threshold:
                        alerts.append({
                            "type": "Username Enumeration",
                            "ip": ip,
                            "severity": "MEDIUM"
                        })
                        break
                else:
                    break

    return alerts


def detect_unusual_login_time(parsed_logs, start, end):
    alerts = []

    for log in parsed_logs:
        if log.get("log_type") == "SSH" and log["status"] == "SUCCESS":
            if log["timestamp"].hour < start or log["timestamp"].hour >= end:
                alerts.append({
                    "type": "Unusual Login Time",
                    "ip": log["ip"],
                    "severity": "LOW"
                })

    return alerts


# ---------------- APACHE DETECTIONS ---------------- #

def detect_404_flood(parsed_logs, threshold=5):
    ip_counter = defaultdict(int)
    alerts = []

    for log in parsed_logs:
        if log.get("log_type") == "APACHE" and log["status_code"] == 404:
            ip_counter[log["ip"]] += 1
            if ip_counter[log["ip"]] == threshold:
                alerts.append({
                    "type": "404 Flood",
                    "ip": log["ip"],
                    "severity": "MEDIUM"
                })

    return alerts


def detect_sql_injection(parsed_logs):
    alerts = []
    patterns = ["' OR", "UNION SELECT", "--", "'1'='1"]

    for log in parsed_logs:
        if log.get("log_type") == "APACHE":
            for pattern in patterns:
                if pattern.lower() in log["url"].lower():
                    alerts.append({
                        "type": "SQL Injection Attempt",
                        "ip": log["ip"],
                        "severity": "HIGH"
                    })

    return alerts


def detect_xss(parsed_logs):
    alerts = []

    for log in parsed_logs:
        if log.get("log_type") == "APACHE":
            if "<script>" in log["url"].lower():
                alerts.append({
                    "type": "XSS Attempt",
                    "ip": log["ip"],
                    "severity": "HIGH"
                })

    return alerts


# ---------------- BLACKLIST ---------------- #

def detect_blacklisted_ip(parsed_logs, blacklist):
    alerts = []

    for log in parsed_logs:
        if log["ip"] in blacklist:
            alerts.append({
                "type": "Blacklisted IP Activity",
                "ip": log["ip"],
                "severity": "CRITICAL"
            })

    return alerts


# ---------------- CORRELATION ---------------- #

def correlate_incidents(alerts, scores):
    ip_scores = defaultdict(int)
    incidents = []

    for alert in alerts:
        ip_scores[alert["ip"]] += scores.get(alert["type"], 0)

    for ip, score in ip_scores.items():
        if score >= 100:
            level = "CRITICAL"
        elif score >= 70:
            level = "HIGH"
        else:
            level = "MEDIUM"

        incidents.append({
            "ip": ip,
            "total_score": score,
            "incident_level": level
        })

    return incidents

def deduplicate_alerts(alerts):
    from collections import defaultdict

    grouped = defaultdict(lambda: {"count": 0, "alert": None})

    for alert in alerts:
        key = (alert["type"], alert["ip"])

        grouped[key]["count"] += 1
        grouped[key]["alert"] = alert

    deduped = []

    for key, value in grouped.items():
        alert = value["alert"]
        alert["occurrences"] = value["count"]
        deduped.append(alert)

    return deduped
