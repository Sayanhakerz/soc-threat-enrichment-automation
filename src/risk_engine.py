def calculate_risk(severity, abuse_score, vt_malicious=0):
    """
    Calculate SOC risk using:

    1. Suricata severity
    2. AbuseIPDB abuse confidence score
    3. VirusTotal malicious engine count
    """

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

    # Critical
    if (
        abuse_score >= 80 and severity <= 2
    ) or vt_malicious >= 5:
        return "CRITICAL"

    # High
    if (
        abuse_score >= 50
        or severity == 1
        or vt_malicious >= 2
    ):
        return "HIGH"

    # Medium
    if (
        abuse_score >= 20
        or severity == 2
        or vt_malicious >= 1
    ):
        return "MEDIUM"

    # Low
    return "LOW"


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

        print(
            f"Severity: {severity} | "
            f"Abuse Score: {abuse_score} | "
            f"VT Malicious: {vt_malicious} | "
            f"Risk: {risk}"
        )

    print("\n===========================\n")
