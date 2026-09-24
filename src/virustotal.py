import os
import ipaddress
import requests
from dotenv import load_dotenv


load_dotenv()

API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

API_URL = "https://www.virustotal.com/api/v3/ip_addresses/{}"


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
            "reason": "VIRUSTOTAL_API_KEY not found"
        }

    headers = {
        "accept": "application/json",
        "x-apikey": API_KEY
    }

    try:

        response = requests.get(
            API_URL.format(ip),
            headers=headers,
            timeout=10
        )

        if response.status_code != 200:
            return {
                "ip": ip,
                "status": "ERROR",
                "reason": f"API returned HTTP {response.status_code}"
            }

        data = response.json().get("data", {})
        attributes = data.get("attributes", {})

        analysis_stats = attributes.get(
            "last_analysis_stats",
            {}
        )

        return {
            "ip": ip,
            "status": "ENRICHED",
            "reputation": attributes.get("reputation"),
            "malicious": analysis_stats.get("malicious", 0),
            "suspicious": analysis_stats.get("suspicious", 0),
            "harmless": analysis_stats.get("harmless", 0),
            "undetected": analysis_stats.get("undetected", 0),
            "country": attributes.get("country"),
            "asn": attributes.get("asn"),
            "as_owner": attributes.get("as_owner")
        }

    except requests.RequestException as e:

        return {
            "ip": ip,
            "status": "ERROR",
            "reason": str(e)
        }


if __name__ == "__main__":

    test_ip = "8.8.8.8"

    result = check_ip(test_ip)

    print("\n===== VIRUSTOTAL THREAT INTELLIGENCE =====")

    for key, value in result.items():
        print(f"{key.replace('_', ' ').title():20}: {value}")

    print("===========================================\n")
