import re
from datetime import datetime

def parse_ssh_log(line):
    """
    Parses a single SSH log line.
    Returns structured dictionary or None.
    """

    year = datetime.now().year

    # Failed login pattern
    failed_pattern = re.search(
        r"(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+).*Failed password for (invalid user )?(?P<user>\w+) from (?P<ip>\d+\.\d+\.\d+\.\d+)",
        line
    )

    if failed_pattern:
        timestamp_str = failed_pattern.group("timestamp")
        timestamp = datetime.strptime(
            f"{timestamp_str} {year}",
            "%b %d %H:%M:%S %Y"
        )

        return {
            "timestamp": timestamp,
            "ip": failed_pattern.group("ip"),
            "username": failed_pattern.group("user"),
            "status": "FAILED"
        }

    # Successful login pattern
    success_pattern = re.search(
        r"(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+).*Accepted password for (?P<user>\w+) from (?P<ip>\d+\.\d+\.\d+\.\d+)",
        line
    )

    if success_pattern:
        timestamp_str = success_pattern.group("timestamp")
        timestamp = datetime.strptime(
            f"{timestamp_str} {year}",
            "%b %d %H:%M:%S %Y"
        )

        return {
            "timestamp": timestamp,
            "ip": success_pattern.group("ip"),
            "username": success_pattern.group("user"),
            "status": "SUCCESS"
        }

    return None

