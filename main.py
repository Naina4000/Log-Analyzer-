import json
from log_analyzer.parser import parse_ssh_log
from log_analyzer.detector import (
    detect_bruteforce,
    detect_username_enumeration,
    detect_unusual_login_time
)
from log_analyzer.reporter import print_alerts


def load_config():
    with open("config.json", "r") as f:
        return json.load(f)


def main():
    config = load_config()

    threshold = config["brute_force_threshold"]
    time_window = config["time_window_seconds"]
    username_threshold = config["username_enumeration_threshold"]
    business_start = config["business_hours_start"]
    business_end = config["business_hours_end"]

    parsed_logs = []

    with open("logs/ssh.log", "r") as file:
        for line in file:
            parsed = parse_ssh_log(line)
            if parsed:
                parsed_logs.append(parsed)

    alerts = []

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

    print_alerts(alerts, config)


if __name__ == "__main__":
    main()
