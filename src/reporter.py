from datetime import datetime
from pathlib import Path

REPORT_DIR = Path("data/reports")


def generate_report(
    signature,
    severity,
    priority,
    source_ip,
    source_type,
    destination_ip,
    destination_type,
    protocol,
    interface,
    threat_intelligence,
    risk_level,
    risk_reasons=None,
    mitre_mapping=None
):
    """
    Generate an automated SOC incident report.

    Includes:
    - Suricata detection
    - Alert priority
    - Network indicators
    - AbuseIPDB intelligence
    - VirusTotal intelligence
    - Risk assessment and reasons
    - MITRE ATT&CK mapping
    - Analyst notes
    """

    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    safe_signature = (
        signature
        .replace("/", "_")
        .replace(" ", "_")
        .replace(":", "")
        .replace("\\", "_")
    )

    filename = (
        f"incident_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}"
        f"_{safe_signature[:40]}.md"
    )

    report_path = REPORT_DIR / filename

    if risk_reasons is None:
        risk_reasons = []

    report = []

    # =========================================================
    # HEADER
    # =========================================================

    report.append("# SOC Incident Report\n")

    # =========================================================
    # INCIDENT SUMMARY
    # =========================================================

    report.append("## Incident Summary\n")
    report.append("| Field | Value |")
    report.append("|---|---|")
    report.append(f"| Detection Time | {timestamp} |")
    report.append(f"| Alert Signature | {signature} |")
    report.append(f"| Suricata Severity | {severity} |")
    report.append(f"| Alert Priority | **{priority}** |")
    report.append(f"| Risk Level | **{risk_level}** |")
    report.append(f"| Protocol | {protocol} |")
    report.append(f"| Interface | {interface} |")

    report.append("\n---\n")

    # =========================================================
    # NETWORK INDICATORS
    # =========================================================

    report.append("## Network Indicators\n")
    report.append("| Indicator | Value | Type |")
    report.append("|---|---|---|")
    report.append(f"| Source IP | `{source_ip}` | {source_type} |")
    report.append(
        f"| Destination IP | `{destination_ip}` | {destination_type} |"
    )

    report.append("\n---\n")

    # =========================================================
    # THREAT INTELLIGENCE
    # =========================================================

    report.append("## Threat Intelligence\n")

    if threat_intelligence:

        report.append("| Source | Field | Value |")
        report.append("|---|---|---|")

        for key, value in threat_intelligence.items():

            if key.startswith("abuseipdb_"):
                provider = "AbuseIPDB"
                clean_key = key.replace("abuseipdb_", "", 1)

            elif key.startswith("virustotal_"):
                provider = "VirusTotal"
                clean_key = key.replace("virustotal_", "", 1)

            else:
                provider = "Other"
                clean_key = key

            display_key = clean_key.replace("_", " ").title()

            report.append(
                f"| {provider} | {display_key} | {value} |"
            )

    else:
        report.append(
            "No public IP threat-intelligence data was available."
        )

    report.append("\n---\n")

    # =========================================================
    # RISK ASSESSMENT
    # =========================================================

    report.append("## Risk Assessment\n")
    report.append(f"**Risk Level:** `{risk_level}`\n")

    report.append(
        "The risk level was calculated using Suricata alert severity, "
        "AbuseIPDB reputation data, and VirusTotal detection results."
    )

    report.append(
        "These signals are combined by the project's SOC risk engine.\n"
    )

    report.append("### Risk Reasons\n")

    if risk_reasons:

        for reason in risk_reasons:
            report.append(f"- {reason}")

    else:

        report.append(
            "- No specific risk indicators were recorded."
        )

    report.append("\n---\n")

    # =========================================================
    # MITRE ATT&CK
    # =========================================================

    report.append("## MITRE ATT&CK Mapping\n")

    if mitre_mapping:

        report.append("| Field | Value |")
        report.append("|---|---|")

        report.append(
            f"| Tactic | {mitre_mapping.get('tactic', 'Unknown')} |"
        )

        report.append(
            f"| Technique ID | "
            f"{mitre_mapping.get('technique_id', 'Unknown')} |"
        )

        report.append(
            f"| Technique | "
            f"{mitre_mapping.get('technique_name', 'Unknown')} |"
        )

        report.append(
            f"| Confidence | "
            f"{mitre_mapping.get('confidence', 'Unknown')} |"
        )

        report.append(
            f"| Rationale | "
            f"{mitre_mapping.get('rationale', 'Not available')} |"
        )

    else:

        report.append(
            "No MITRE ATT&CK mapping was found for this alert."
        )

    report.append("\n---\n")

    # =========================================================
    # ANALYST NOTES
    # =========================================================

    report.append("## Analyst Notes\n")

    report.append(
        "- Review the source and destination IP addresses."
    )

    report.append(
        "- Validate whether the traffic was expected."
    )

    report.append(
        "- Correlate this alert with other Suricata events."
    )

    report.append(
        "- Investigate repeated activity from the same source."
    )

    report.append(
        "- Review AbuseIPDB and VirusTotal intelligence."
    )

    report.append(
        "- Review the associated MITRE ATT&CK technique."
    )

    report.append(
        "- Check whether the source IP appears in other security events."
    )

    report.append(
        "- Escalate according to the organization's incident-response procedure."
    )

    report.append("\n---\n")

    # =========================================================
    # DETECTION SOURCE
    # =========================================================

    report.append("## Detection Source\n")

    report.append(
        "**Suricata IDS + Python Threat Enrichment Automation**"
    )

    report.append(
        "Generated automatically by the "
        "**SOC Threat Detection & IOC Enrichment Automation** project."
    )

    report.append("\n---\n")

    # =========================================================
    # INVESTIGATION WORKFLOW
    # =========================================================

    report.append("## Investigation Workflow\n")

    report.append("Suricata Detection")
    report.append("        ↓")
    report.append("EVE JSON Event")
    report.append("        ↓")
    report.append("Python IOC Parser")
    report.append("        ↓")
    report.append("AbuseIPDB + VirusTotal Enrichment")
    report.append("        ↓")
    report.append("SOC Risk Engine")
    report.append("        ↓")
    report.append("MITRE ATT&CK Mapping")
    report.append("        ↓")
    report.append("Automated Incident Report")

    report.append("\n---\n")

    # =========================================================
    # AUTOMATION STATUS
    # =========================================================

    report.append("## Automation Status\n")

    report.append("| Component | Status |")
    report.append("|---|---|")

    report.append("| Suricata IDS | Active |")
    report.append("| EVE JSON Parsing | Active |")
    report.append("| Stateful Processing | Active |")
    report.append("| AbuseIPDB Enrichment | Active |")
    report.append("| VirusTotal Enrichment | Active |")
    report.append("| Risk Engine | Active |")
    report.append("| MITRE ATT&CK Mapping | Active |")
    report.append("| Incident Reporting | Active |")

    # =========================================================
    # WRITE REPORT
    # =========================================================

    with open(report_path, "w") as file:
        file.write("\n".join(report))

    return report_path


if __name__ == "__main__":

    test_report = generate_report(
        signature="SOC LAB - Test Detection",
        severity=2,
        priority="HIGH",
        source_ip="203.0.113.50",
        source_type="Public",
        destination_ip="10.0.15.61",
        destination_type="Private",
        protocol="TCP",
        interface="ens5",
        threat_intelligence={
            "abuseipdb_abuse_score": 75,
            "virustotal_malicious": 4
        },
        risk_level="HIGH",
        risk_reasons=[
            "AbuseIPDB abuse confidence score is elevated",
            "VirusTotal has multiple malicious engine detections",
            "Suricata severity indicates a high-priority alert"
        ],
        mitre_mapping={
            "tactic": "Discovery",
            "technique_id": "T1046",
            "technique_name": "Network Service Scanning",
            "confidence": "Medium",
            "rationale": "Test mapping for report generation."
        }
    )

    print("\n==========================================")
    print("       INCIDENT REPORT TEST")
    print("==========================================")
    print(f"Report created: {test_report}")
    print("==========================================\n")
