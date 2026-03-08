import json
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


def main():
    config = load_config()
    blacklist = load_blacklist()

    parsed_logs = []

    # Parse SSH logs
    with open("logs/ssh.log", "r") as f:
        for line in f:
            parsed = parse_ssh_log(line)
            if parsed:
                parsed_logs.append(parsed)

    # Parse Apache logs
    with open("logs/apache.log", "r") as f:
        for line in f:
            parsed = parse_apache_log(line)
            if parsed:
                parsed_logs.append(parsed)

    alerts = []

    # SSH detections
    alerts.extend(detect_bruteforce(parsed_logs,
                                    config["brute_force_threshold"],
                                    config["time_window_seconds"]))

    alerts.extend(detect_username_enumeration(parsed_logs,
                                              config["username_enumeration_threshold"],
                                              config["time_window_seconds"]))

    alerts.extend(detect_unusual_login_time(parsed_logs,
                                            config["business_hours_start"],
                                            config["business_hours_end"]))

    # Apache detections
    alerts.extend(detect_404_flood(parsed_logs))
    alerts.extend(detect_sql_injection(parsed_logs))
    alerts.extend(detect_xss(parsed_logs))

    # Blacklist
    alerts.extend(detect_blacklisted_ip(parsed_logs, blacklist))

    # Correlation
    incidents = correlate_incidents(alerts, config["scores"])

    print_alerts(alerts, config, incidents)


if __name__ == "__main__":
    main()
