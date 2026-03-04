def print_alerts(alerts):
    if not alerts:
        print("No threats detected.")
        return

    print("\n🚨 ALERTS DETECTED 🚨\n")

    for alert in alerts:
        print(f"[{alert['severity']}] {alert['type']} detected!")
        print(f"IP: {alert['ip']}")
        print(f"Failed Attempts: {alert['attempts']}")

        # Print time details if available
        if "start_time" in alert:
            print(f"Start Time: {alert['start_time']}")
            print(f"End Time: {alert['end_time']}")
            print(f"Attack Duration: {alert['duration_seconds']} seconds")

        print()

