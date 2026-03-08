import requests

def get_geoip(ip):
    try:
        url = f"http://ip-api.com/json/{ip}"
        response = requests.get(url, timeout=3)
        data = response.json()

        if data["status"] == "success":
            return {
                "country": data.get("country"),
                "region": data.get("regionName"),
                "isp": data.get("isp")
            }

    except Exception:
        pass

    return {
        "country": "Unknown",
        "region": "Unknown",
        "isp": "Unknown"
    }
