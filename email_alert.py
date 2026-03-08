import smtplib
from email.mime.text import MIMEText


def send_email_alert(ip, score, level):

    sender = "your_email@gmail.com"
    receiver = "receiver_email@gmail.com"
    password = "your_app_password"

    subject = "🚨 Critical Security Alert"

    body = f"""
Critical incident detected.

IP Address: {ip}
Threat Score: {score}
Incident Level: {level}
"""

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = receiver

    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(sender, password)
        server.sendmail(sender, receiver, msg.as_string())
        server.quit()

        print("Email alert sent successfully")

    except Exception as e:
        print("Email alert failed:", e)
