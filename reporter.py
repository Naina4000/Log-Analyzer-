def print_alerts(alerts, config, incidents):
    print("\n========== LOG ANALYZER SUMMARY ==========")
    print("Detection Engines Active:")
    print(f"- Time Window Brute Force (Threshold: {config['brute_force_threshold']} in {config['time_window_seconds']}s)")
    print(f"- Username Enumeration (Threshold: {config['username_enumeration_threshold']})")
    print(f"- Business Hours Monitoring ({config['business_hours_start']}:00 - {config['business_hours_end']}:00)")
    print("- Blacklist Monitoring Enabled")
    print("- Threat Scoring & Correlation Enabled")
    print("==========================================\n")

    if not alerts:
        print("No threats detected.\n")
    else:
        print("🚨 ALERTS DETECTED 🚨\n")

        for alert in alerts:
            print(f"[{alert['severity']}] {alert['type']} detected!")
            print(f"IP: {alert['ip']}")

            if "attempts" in alert:
                print(f"Attempts: {alert['attempts']}")

            if "start_time" in alert:
                print(f"Start Time: {alert['start_time']}")
                print(f"End Time: {alert['end_time']}")
                print(f"Duration: {alert['duration_seconds']} seconds")

            if "login_time" in alert:
                print(f"Login Time: {alert['login_time']}")
                print(f"Username: {alert['username']}")

            print()

    # 🔥 Incident Correlation Section
    print("========== INCIDENT CORRELATION ==========\n")

    if not incidents:
        print("No correlated incidents.\n")
        return

    for incident in incidents:
        print(f"IP: {incident['ip']}")
        print(f"Total Threat Score: {incident['total_score']}")
        print(f"Incident Level: {incident['incident_level']}")
        print()
