
import json
from log_analyzer.parser import parse_ssh_log
from log_analyzer.detector import (
    detect_bruteforce,
    detect_username_enumeration,
    detect_unusual_login_time,
    detect_blacklisted_ip,
    correlate_incidents
)
from log_analyzer.reporter import print_alerts


def load_config():
    with open("config.json", "r") as f:
        return json.load(f)


def load_blacklist():
    try:
        with open("blacklist.txt", "r") as f:
            return set(line.strip() for line in f if line.strip())
    except FileNotFoundError:
        return set()


def main():
    config = load_config()
    blacklist_ips = load_blacklist()

    threshold = config["brute_force_threshold"]
    time_window = config["time_window_seconds"]
    username_threshold = config["username_enumeration_threshold"]
    business_start = config["business_hours_start"]
    business_end = config["business_hours_end"]

    parsed_logs = []

    # Parse SSH log file
    with open("logs/ssh.log", "r") as file:
        for line in file:
            parsed = parse_ssh_log(line)
            if parsed:
                parsed_logs.append(parsed)

    alerts = []

    # Rule-based detections
    alerts.extend(
        detect_bruteforce(parsed_logs, threshold, time_window)
    )

    alerts.extend(
        detect_username_enumeration(
            parsed_logs,
            username_threshold,
            time_window
        )
    )

    alerts.extend(
        detect_unusual_login_time(
            parsed_logs,
            business_start,
            business_end
        )
    )

    alerts.extend(
        detect_blacklisted_ip(parsed_logs, blacklist_ips)
    )

    # 🔥 Threat Scoring / Correlation Engine
    incident_reports = correlate_incidents(alerts, config["scores"])

    print_alerts(alerts, config, incident_reports)


if __name__ == "__main__":
    main()
