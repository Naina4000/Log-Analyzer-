MITRE_MAP = {
    "Brute Force": ("T1110", "Brute Force"),
    "Username Enumeration": ("T1110.003", "Password Spraying"),
    "Unusual Login Time": ("T1078", "Valid Accounts"),
    "SQL Injection Attempt": ("T1190", "Exploit Public-Facing Application"),
    "XSS Attempt": ("T1059", "Command and Scripting Interpreter"),
    "404 Flood": ("T1595", "Active Scanning"),
    "Blacklisted IP Activity": ("T1071", "Application Layer Protocol")
}


def get_mitre_mapping(alert_type):
    return MITRE_MAP.get(alert_type, ("N/A", "Unknown Technique"))
