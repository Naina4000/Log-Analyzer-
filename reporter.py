import json
import csv
from datetime import datetime

from log_analyzer.geoip import get_geoip
from log_analyzer.mitre_mapper import get_mitre_mapping


def print_alerts(alerts, config, incidents):

    print("\n========== LOG ANALYZER SUMMARY ==========")
    print("Detection Engines Active:")
    print(f"- Time Window Brute Force (Threshold: {config['brute_force_threshold']} in {config['time_window_seconds']}s)")
    print(f"- Username Enumeration (Threshold: {config['username_enumeration_threshold']})")
    print(f"- Business Hours Monitoring ({config['business_hours_start']}:00 - {config['business_hours_end']}:00)")
    print("- Blacklist Monitoring Enabled")
    print("- Threat Scoring & Correlation Enabled")
    print("- JSON Report Export Enabled")
    print("- CSV Report Export Enabled")
    print("- GeoIP Enrichment Enabled")
    print("- MITRE ATT&CK Mapping Enabled")
    print("==========================================\n")

    if not alerts:
        print("No threats detected.\n")
    else:
        print("🚨 ALERTS DETECTED 🚨\n")

        for alert in alerts:

            print(f"[{alert['severity']}] {alert['type']} detected!")
            print(f"IP: {alert['ip']}")

            # GeoIP enrichment
            geo = get_geoip(alert["ip"])
            print(f"Country: {geo['country']}")
            print(f"Region: {geo['region']}")
            print(f"ISP: {geo['isp']}")

            # MITRE ATT&CK mapping
            mitre_id, mitre_name = get_mitre_mapping(alert["type"])
            print(f"MITRE Technique: {mitre_id} ({mitre_name})")

            if "start_time" in alert:
                print(f"Start Time: {alert['start_time']}")

            if "end_time" in alert:
                print(f"End Time: {alert['end_time']}")

            if "occurrences" in alert:
                print(f"Occurrences: {alert['occurrences']}")

            print()

    print("========== INCIDENT CORRELATION ==========\n")

    for incident in incidents:
        print(f"IP: {incident['ip']}")
        print(f"Total Threat Score: {incident['total_score']}")
        print(f"Incident Level: {incident['incident_level']}")
        print()

    generate_json_report(alerts, incidents)
    generate_csv_report(alerts)


def generate_json_report(alerts, incidents):

    def serialize(obj):
        if hasattr(obj, "isoformat"):
            return obj.isoformat()
        return obj

    report = {
        "analysis_time": datetime.now().isoformat(),
        "total_alerts": len(alerts),
        "total_incidents": len(incidents),
        "alerts": alerts,
        "incidents": incidents
    }

    with open("report.json", "w") as f:
        json.dump(report, f, indent=4, default=serialize)

    print("Report saved as report.json")


def generate_csv_report(alerts):

    with open("report.csv", "w", newline="") as file:

        writer = csv.writer(file)

        writer.writerow([
            "Alert Type",
            "IP",
            "Severity",
            "Country",
            "MITRE Technique",
            "Occurrences"
        ])

        for alert in alerts:

            geo = get_geoip(alert["ip"])
            mitre_id, _ = get_mitre_mapping(alert["type"])

            writer.writerow([
                alert["type"],
                alert["ip"],
                alert["severity"],
                geo["country"],
                mitre_id,
                alert.get("occurrences", 1)
            ])

    print("Report saved as report.csv\n")

