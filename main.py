import json
import argparse
from collections import defaultdict

from log_analyzer.parser import parse_ssh_log, parse_apache_log
from log_analyzer.detector import *
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


def deduplicate_alerts(alerts):
    grouped = defaultdict(lambda: {"count": 0, "alert": None})

    for alert in alerts:
        key = (alert["type"], alert["ip"])

        grouped[key]["count"] += 1
        grouped[key]["alert"] = alert

    deduped = []

    for _, value in grouped.items():
        alert = value["alert"]
        alert["occurrences"] = value["count"]
        deduped.append(alert)

    return deduped


def parse_logs(ssh_path, apache_path):
    parsed_logs = []

    if ssh_path:
        with open(ssh_path, "r") as f:
            for line in f:
                parsed = parse_ssh_log(line)
                if parsed:
                    parsed_logs.append(parsed)

    if apache_path:
        with open(apache_path, "r") as f:
            for line in f:
                parsed = parse_apache_log(line)
                if parsed:
                    parsed_logs.append(parsed)

    return parsed_logs


def main():
    parser = argparse.ArgumentParser(description="Multi-Source Log Analyzer")
    parser.add_argument("--ssh", help="Path to SSH log file")
    parser.add_argument("--apache", help="Path to Apache log file")

    args = parser.parse_args()

    config = load_config()
    blacklist = load_blacklist()

    parsed_logs = parse_logs(args.ssh, args.apache)

    alerts = []

    alerts.extend(
        detect_bruteforce(parsed_logs,
                          config["brute_force_threshold"],
                          config["time_window_seconds"])
    )

    alerts.extend(
        detect_username_enumeration(parsed_logs,
                                    config["username_enumeration_threshold"],
                                    config["time_window_seconds"])
    )

    alerts.extend(
        detect_unusual_login_time(parsed_logs,
                                  config["business_hours_start"],
                                  config["business_hours_end"])
    )

    alerts.extend(detect_404_flood(parsed_logs))
    alerts.extend(detect_sql_injection(parsed_logs))
    alerts.extend(detect_xss(parsed_logs))

    alerts.extend(detect_blacklisted_ip(parsed_logs, blacklist))

    # 🔹 Deduplicate alerts
    alerts = deduplicate_alerts(alerts)

    incidents = correlate_incidents(alerts, config["scores"])

    print_alerts(alerts, config, incidents)

if __name__ == "__main__":
    main()
