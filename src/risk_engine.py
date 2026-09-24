def normalize_values(severity, abuse_score, vt_malicious):
    try:
        severity = int(severity)
    except (ValueError, TypeError):
        severity = 3

    try:
        abuse_score = int(abuse_score)
    except (ValueError, TypeError):
        abuse_score = 0

    try:
        vt_malicious = int(vt_malicious)
    except (ValueError, TypeError):
        vt_malicious = 0

    return severity, abuse_score, vt_malicious


def calculate_risk(severity, abuse_score, vt_malicious=0):
    severity, abuse_score, vt_malicious = normalize_values(
        severity,
        abuse_score,
        vt_malicious
    )

    if (
        abuse_score >= 80 and severity <= 2
    ) or vt_malicious >= 5:
        return "CRITICAL"

    if (
        abuse_score >= 50
        or severity == 1
        or vt_malicious >= 2
    ):
        return "HIGH"

    if (
        abuse_score >= 20
        or severity == 2
        or vt_malicious >= 1
    ):
        return "MEDIUM"

    return "LOW"


def explain_risk(severity, abuse_score, vt_malicious=0):
    severity, abuse_score, vt_malicious = normalize_values(
        severity,
        abuse_score,
        vt_malicious
    )

    reasons = []

    if abuse_score >= 80 and severity <= 2:
        reasons.append(
            "High AbuseIPDB score combined with high-severity Suricata alert"
        )

    if vt_malicious >= 5:
        reasons.append(
            "VirusTotal reports multiple malicious detections"
        )

    if abuse_score >= 50:
        reasons.append(
            "AbuseIPDB abuse confidence score is elevated"
        )

    if severity == 1:
        reasons.append(
            "Suricata severity is critical"
        )

    if vt_malicious >= 2:
        reasons.append(
            "VirusTotal has multiple malicious engine detections"
        )

    if abuse_score >= 20:
        reasons.append(
            "AbuseIPDB reports measurable abuse confidence"
        )

    if severity == 2:
        reasons.append(
            "Suricata severity indicates a high-priority alert"
        )

    if vt_malicious >= 1:
        reasons.append(
            "VirusTotal has at least one malicious engine detection"
        )

    if not reasons:
        reasons.append(
            "No strong threat-intelligence or severity indicators were observed"
        )

    return reasons


if __name__ == "__main__":

    test_cases = [
        (1, 95, 10),
        (2, 60, 3),
        (2, 20, 1),
        (3, 25, 0),
        (3, 5, 0),
    ]

    print("\n===== SOC RISK ENGINE =====\n")

    for severity, abuse_score, vt_malicious in test_cases:

        risk = calculate_risk(
            severity,
            abuse_score,
            vt_malicious
        )

        reasons = explain_risk(
            severity,
            abuse_score,
            vt_malicious
        )

        print(
            f"Severity: {severity} | "
            f"Abuse Score: {abuse_score} | "
            f"VT Malicious: {vt_malicious} | "
            f"Risk: {risk}"
        )

        print("Reasons:")

        for reason in reasons:
            print(f"  - {reason}")

        print()

    print("===========================\n")
