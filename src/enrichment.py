import os
import ipaddress
import requests
from dotenv import load_dotenv


load_dotenv()

API_KEY = os.getenv("ABUSEIPDB_API_KEY")

API_URL = "https://api.abuseipdb.com/api/v2/check"


def is_private_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def check_ip(ip):
    # Ignore private/internal IP addresses
    if is_private_ip(ip):
        return {
            "ip": ip,
            "status": "SKIPPED",
            "reason": "Private IP - no public threat intelligence lookup"
        }

    if not API_KEY:
        return {
            "ip": ip,
            "status": "ERROR",
            "reason": "ABUSEIPDB_API_KEY not found"
        }

    headers = {
        "Accept": "application/json",
        "Key": API_KEY
    }

    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }

    try:
        response = requests.get(
            API_URL,
            headers=headers,
            params=params,
            timeout=10
        )

        if response.status_code != 200:
            return {
                "ip": ip,
                "status": "ERROR",
                "reason": f"API returned HTTP {response.status_code}"
            }

        data = response.json().get("data", {})

        return {
            "ip": data.get("ipAddress", ip),
            "status": "ENRICHED",
            "abuse_score": data.get("abuseConfidenceScore"),
            "country": data.get("countryCode"),
            "usage_type": data.get("usageType"),
            "isp": data.get("isp"),
            "domain": data.get("domain"),
            "total_reports": data.get("totalReports"),
            "last_reported": data.get("lastReportedAt")
        }

    except requests.RequestException as e:
        return {
            "ip": ip,
            "status": "ERROR",
            "reason": str(e)
        }


if __name__ == "__main__":
    test_ip = "118.25.6.39"

    result = check_ip(test_ip)

    print("\n===== ABUSEIPDB THREAT INTELLIGENCE =====")

    for key, value in result.items():
        print(f"{key.replace('_', ' ').title():20}: {value}")

    print("==========================================\n")
