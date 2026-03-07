from collections import defaultdict


def detect_bruteforce(parsed_logs, threshold, time_window):
    failed_attempts = defaultdict(list)
    alerts = []

    for log in parsed_logs:
        if log["status"] == "FAILED":
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
                    "attempts": threshold,
                    "severity": "HIGH",
                    "start_time": start_time,
                    "end_time": end_time,
                    "duration_seconds": int(
                        (end_time - start_time).total_seconds()
                    )
                })
                break

    return alerts


def detect_username_enumeration(parsed_logs, threshold, time_window):
    ip_user_map = defaultdict(list)
    alerts = []

    for log in parsed_logs:
        if log["status"] == "FAILED":
            ip_user_map[log["ip"]].append(
                (log["timestamp"], log["username"])
            )

    for ip, entries in ip_user_map.items():
        entries.sort()

        for i in range(len(entries)):
            start_time = entries[i][0]
            unique_users = set()

            for j in range(i, len(entries)):
                if (entries[j][0] - start_time).total_seconds() <= time_window:
                    unique_users.add(entries[j][1])

                    if len(unique_users) >= threshold:
                        alerts.append({
                            "type": "Username Enumeration",
                            "ip": ip,
                            "attempts": len(unique_users),
                            "severity": "MEDIUM",
                            "start_time": start_time,
                            "end_time": entries[j][0],
                            "duration_seconds": int(
                                (entries[j][0] - start_time).total_seconds()
                            )
                        })
                        break
                else:
                    break

    return alerts


def detect_unusual_login_time(parsed_logs, business_start, business_end):
    alerts = []

    for log in parsed_logs:
        if log["status"] == "SUCCESS":
            login_hour = log["timestamp"].hour

            if login_hour < business_start or login_hour >= business_end:
                alerts.append({
                    "type": "Unusual Login Time",
                    "ip": log["ip"],
                    "username": log["username"],
                    "severity": "LOW",
                    "login_time": log["timestamp"]
                })

    return alerts

def detect_blacklisted_ip(parsed_logs, blacklist_ips):
    alerts = []

    for log in parsed_logs:
        if log["ip"] in blacklist_ips:
            alerts.append({
                "type": "Blacklisted IP Activity",
                "ip": log["ip"],
                "severity": "CRITICAL",
                "timestamp": log["timestamp"]
            })

    return alerts


def correlate_incidents(alerts, score_config):
    from collections import defaultdict

    ip_scores = defaultdict(int)
    incident_reports = []

    # Calculate score per IP
    for alert in alerts:
        alert_type = alert["type"]
        ip = alert["ip"]

        if alert_type in score_config:
            ip_scores[ip] += score_config[alert_type]

    # Generate incident level
    for ip, total_score in ip_scores.items():
        if total_score >= 100:
            level = "CRITICAL"
        elif total_score >= 70:
            level = "HIGH"
        else:
            level = "MEDIUM"

        incident_reports.append({
            "ip": ip,
            "total_score": total_score,
            "incident_level": level
        })

    return incident_reports
