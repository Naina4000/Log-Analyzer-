import json
from log_analyzer.parser import parse_ssh_log
from log_analyzer.detector import (
    detect_bruteforce,
    detect_username_enumeration
)
from log_analyzer.reporter import print_alerts


def load_config():
    """Load configuration settings from config.json"""
    with open("config.json", "r") as f:
        return json.load(f)


def main():
    # Load configuration
    config = load_config()
    threshold = config["brute_force_threshold"]
    time_window = config["time_window_seconds"]
    username_threshold = config["username_enumeration_threshold"]

    parsed_logs = []

    # Read and parse SSH log file
    with open("logs/ssh.log", "r") as file:
        for line in file:
            parsed = parse_ssh_log(line)
            if parsed:
                parsed_logs.append(parsed)

    # Collect alerts from different detection engines
    alerts = []

    # Brute force detection
    alerts.extend(
        detect_bruteforce(parsed_logs, threshold, time_window)
    )

    # Username enumeration detection
    alerts.extend(
        detect_username_enumeration(parsed_logs, username_threshold, time_window)
    )

    # Print all alerts
    print_alerts(alerts)


if __name__ == "__main__":
    main()
