
import json
from datetime import datetime


def print_alerts(alerts, config, incidents):
    print("\n========== LOG ANALYZER SUMMARY ==========")
    print("Detection Engines Active:")
    print(f"- Time Window Brute Force (Threshold: {config['brute_force_threshold']} in {config['time_window_seconds']}s)")
    print(f"- Username Enumeration (Threshold: {config['username_enumeration_threshold']})")
    print(f"- Business Hours Monitoring ({config['business_hours_start']}:00 - {config['business_hours_end']}:00)")
    print("- Blacklist Monitoring Enabled")
    print("- Threat Scoring & Correlation Enabled")
    print("- JSON Report Export Enabled")
    print("==========================================\n")

    if not alerts:
        print("No threats detected.\n")
    else:
        print("🚨 ALERTS DETECTED 🚨\n")

        for alert in alerts:
            print(f"[{alert['severity']}] {alert['type']} detected!")
            print(f"IP: {alert['ip']}")

            if "start_time" in alert:
                print(f"Start Time: {alert['start_time']}")

            if "end_time" in alert:
                print(f"End Time: {alert['end_time']}")

            if "duration_seconds" in alert:
                print(f"Duration: {alert['duration_seconds']} seconds")

            print()

    print("========== INCIDENT CORRELATION ==========\n")

    for incident in incidents:
        print(f"IP: {incident['ip']}")
        print(f"Total Threat Score: {incident['total_score']}")
        print(f"Incident Level: {incident['incident_level']}")
        print()

    generate_json_report(alerts, incidents)


def generate_json_report(alerts, incidents):
    def serialize(obj):
        if hasattr(obj, "isoformat"):
            return obj.isoformat()
        return obj

    report_data = {
        "analysis_timestamp": datetime.now().isoformat(),
        "total_alerts": len(alerts),
        "total_incidents": len(incidents),
        "alerts": alerts,
        "incidents": incidents
    }

    with open("report.json", "w") as f:
        json.dump(report_data, f, default=serialize, indent=4)

    print("Report saved as report.json\n")
