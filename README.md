# 🔐 Log Analyzer – Mini SIEM Security Monitoring Tool

A **Python-based security log analysis and threat detection system** that simulates core capabilities of a **Security Information and Event Management (SIEM)** platform.

The tool analyzes **SSH and Apache logs**, detects malicious activity, enriches alerts with threat intelligence, correlates incidents, and generates security reports.

This project demonstrates how **SOC detection pipelines** work in real-world cybersecurity environments.

---

# 🚀 Overview

Security teams rely heavily on log monitoring to detect attacks such as brute force attempts, web exploitation, and reconnaissance activity.

This project implements a **multi-layer log detection pipeline** that performs:

* Log parsing
* Threat detection
* Threat intelligence enrichment
* Incident correlation
* Security reporting

The goal is to simulate a **mini SIEM detection engine** for cybersecurity learning and portfolio demonstration.

---

# ⚡ Key Features

## 🔐 SSH Attack Detection

* Brute Force attack detection
* Username enumeration detection
* Login outside business hours detection

## 🌐 Web Attack Detection

* SQL Injection attempt detection
* Cross-Site Scripting (XSS) detection
* 404 flood / directory scanning detection

## 🧠 Threat Intelligence

* Blacklisted IP detection
* GeoIP enrichment (Country / Region / ISP)
* MITRE ATT&CK technique mapping

## 📊 Incident Analysis

* Threat scoring engine
* Incident correlation
* Alert deduplication

## 📑 Reporting

* Terminal alert dashboard
* JSON report export
* CSV report export

## 🛠 Tool Capabilities

* Command-line interface
* Configurable detection thresholds
* Modular architecture

---

# 🏗 System Architecture

The project follows a **modular detection pipeline similar to SIEM systems**.

```text
                +-------------------+
                |     Log Files     |
                |  SSH / Apache     |
                +---------+---------+
                          |
                          v
                 +----------------+
                 |   Log Parser   |
                 |  (parser.py)   |
                 +--------+-------+
                          |
                          v
                +-------------------+
                | Detection Engine  |
                | (detector.py)     |
                +---------+---------+
                          |
                          v
               +----------------------+
               | Threat Intelligence  |
               | GeoIP + MITRE        |
               +----------+-----------+
                          |
                          v
                +-------------------+
                | Incident Scoring  |
                | & Correlation     |
                +---------+---------+
                          |
                          v
                +-------------------+
                | Reporting Engine  |
                | (reporter.py)     |
                +---------+---------+
                          |
                          v
           +----------------------------------+
           | JSON Reports + CSV Reports       |
           | Security Alert Output            |
           +----------------------------------+
```

---

# 📂 Project Structure

```text
LOG/
│
├── log_analyzer/
│   ├── __init__.py
│   ├── parser.py
│   ├── detector.py
│   ├── reporter.py
│   ├── geoip.py
│   └── mitre_mapper.py
│
├── logs/
│   ├── ssh.log
│   └── apache.log
│
├── blacklist.txt
├── config.json
├── main.py
├── requirements.txt
├── report.json
├── report.csv
└── README.md
```

---

# ⚙ Installation

Install dependencies:

```bash
pip install -r requirements.txt
```

---

# ▶ Usage

Analyze SSH and Apache logs:

```bash
python main.py --ssh logs/ssh.log --apache logs/apache.log
```

Analyze only SSH logs:

```bash
python main.py --ssh logs/ssh.log
```

Analyze only Apache logs:

```bash
python main.py --apache logs/apache.log
```

---

# 📊 Example Output

```text
🚨 ALERTS DETECTED

[HIGH] Brute Force detected!
IP: 192.168.1.43
Country: India
MITRE Technique: T1110 (Brute Force)

[HIGH] SQL Injection Attempt detected!
IP: 192.168.1.60
MITRE Technique: T1190 (Exploit Public-Facing Application)

========== INCIDENT CORRELATION ==========

IP: 192.168.1.43
Total Threat Score: 180
Incident Level: CRITICAL
```

---

# 📑 Generated Reports

After analysis the system automatically generates:

```text
report.json
report.csv
```

### Example CSV

```text
Alert Type,IP,Severity,Country,MITRE Technique,Occurrences
Brute Force,192.168.1.43,HIGH,India,T1110,1
SQL Injection Attempt,192.168.1.60,HIGH,USA,T1190,2
```

---

# 🧠 MITRE ATT&CK Mapping

| Attack Type             | MITRE Technique |
| ----------------------- | --------------- |
| Brute Force             | T1110           |
| Username Enumeration    | T1110.003       |
| SQL Injection           | T1190           |
| XSS                     | T1059           |
| Web Scanning            | T1595           |
| Blacklisted IP Activity | T1071           |

---

# 🛠 Technologies Used

* Python
* Regular Expressions (Regex)
* JSON & CSV reporting
* GeoIP API
* MITRE ATT&CK Framework
* CLI argument parsing (argparse)

---

# 🎯 Use Cases

* SOC analyst training
* Cybersecurity log monitoring practice
* SIEM simulation project
* Cybersecurity portfolio project

---

# 📈 Future Improvements

Possible upgrades:

* Real-time log monitoring
* SOC dashboard (Flask)
* Machine learning anomaly detection
* Integration with SIEM platforms

---

# 👨‍💻 Author

Developed as a **cybersecurity log analysis project** demonstrating SOC detection and incident response concepts.
