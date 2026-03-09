
import re
from datetime import datetime


def parse_ssh_log(line):
    year = datetime.now().year

    # Failed login
    failed_pattern = re.search(
        r"(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+).*Failed password for (invalid user )?(?P<user>\w+) from (?P<ip>\d+\.\d+\.\d+\.\d+)",
        line
    )

    if failed_pattern:
        timestamp = datetime.strptime(
            f"{failed_pattern.group('timestamp')} {year}",
            "%b %d %H:%M:%S %Y"
        )

        return {
            "timestamp": timestamp,
            "ip": failed_pattern.group("ip"),
            "username": failed_pattern.group("user"),
            "status": "FAILED",
            "log_type": "SSH"
        }

    # Successful login
    success_pattern = re.search(
        r"(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+).*Accepted password for (?P<user>\w+) from (?P<ip>\d+\.\d+\.\d+\.\d+)",
        line
    )

    if success_pattern:
        timestamp = datetime.strptime(
            f"{success_pattern.group('timestamp')} {year}",
            "%b %d %H:%M:%S %Y"
        )

        return {
            "timestamp": timestamp,
            "ip": success_pattern.group("ip"),
            "username": success_pattern.group("user"),
            "status": "SUCCESS",
            "log_type": "SSH"
        }

    return None


def parse_apache_log(line):
    pattern = re.search(
        r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[(?P<timestamp>.*?)\] "(?P<method>\w+) (?P<url>.*?) HTTP/.*" (?P<status>\d+)',
        line
    )

    if pattern:
        timestamp = datetime.strptime(
            pattern.group("timestamp"),
            "%d/%b/%Y:%H:%M:%S"
        )

        return {
            "timestamp": timestamp,
            "ip": pattern.group("ip"),
            "method": pattern.group("method"),
            "url": pattern.group("url"),
            "status_code": int(pattern.group("status")),
            "log_type": "APACHE"
        }

    return None
