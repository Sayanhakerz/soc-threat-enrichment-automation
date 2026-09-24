import json
import ipaddress

from enrichment import check_ip
from virustotal import check_ip as vt_check_ip
from risk_engine import calculate_risk
from reporter import generate_report
from mitre_mapper import get_mitre_mapping


EVE_LOG = "/var/log/suricata/eve.json"
STATE_FILE = "data/state.json"

enrichment_cache = {}
virustotal_cache = {}


def get_ip_type(ip):
    try:
        address = ipaddress.ip_address(ip)

        if address.is_private:
            return "Private IP"

        return "Public IP"

    except ValueError:
        return "Unknown"


def get_enrichment(ip):

    if ip in enrichment_cache:
        return enrichment_cache[ip]

    result = check_ip(ip)

    enrichment_cache[ip] = result

    return result


def get_virustotal(ip):

    if ip in virustotal_cache:
        return virustotal_cache[ip]

    result = vt_check_ip(ip)

    virustotal_cache[ip] = result

    return result


def print_result(result):

    for key, value in result.items():
        print(f"{key.replace('_', ' ').title():20}: {value}")


def load_state():

    try:

        with open(STATE_FILE, "r") as file:
            return json.load(file)

    except (FileNotFoundError, json.JSONDecodeError):

        return {"last_line": 0}


def save_state(last_line):

    with open(STATE_FILE, "w") as file:

        json.dump(
            {"last_line": last_line},
            file,
            indent=4
        )


def read_alerts():

    state = load_state()

    last_line = state.get("last_line", 0)

    with open(EVE_LOG, "r") as file:

        lines = file.readlines()

    total_lines = len(lines)

    # ----------------------------------------------------------
    # FIRST RUN
    # ----------------------------------------------------------

    if last_line == 0:

        save_state(total_lines)

        print("\n==========================================")
        print("       SOC PIPELINE INITIALIZED")
        print("==========================================")
        print(f"Existing EVE log lines : {total_lines}")
        print("Old alerts skipped     : YES")
        print("Waiting for new alerts : YES")
        print("==========================================\n")

        return

    # ----------------------------------------------------------
    # NO NEW EVENTS
    # ----------------------------------------------------------

    if last_line >= total_lines:

        print("\nNo new Suricata alerts found.\n")

        return

    new_lines = lines[last_line:]

    print("\n==========================================")
    print("          NEW SOC EVENTS")
    print("==========================================")

    print(f"Previous line : {last_line}")
    print(f"Current line  : {total_lines}")
    print(f"New lines     : {len(new_lines)}")

    print("==========================================")

    processed_events = 0

    # ----------------------------------------------------------
    # PROCESS NEW EVENTS
    # ----------------------------------------------------------

    for line in new_lines:

        try:

            event = json.loads(line)

        except json.JSONDecodeError:

            continue

        # Only process Suricata alert events
        if event.get("event_type") != "alert":

            continue

        processed_events += 1

        alert = event.get("alert", {})

        signature = alert.get(
            "signature",
            "--"
        )

        severity = alert.get(
            "severity",
            3
        )

        source_ip = event.get(
            "src_ip",
            "--"
        )

        destination_ip = event.get(
            "dest_ip",
            "--"
        )

        protocol = event.get(
            "proto",
            "--"
        )

        interface = event.get(
            "in_iface",
            "--"
        )

        source_type = get_ip_type(
            source_ip
        )

        destination_type = get_ip_type(
            destination_ip
        )

        # ------------------------------------------------------
        # ALERT INFORMATION
        # ------------------------------------------------------

        print("\n==========================================")
        print("              NEW SOC ALERT")
        print("==========================================")

        print(
            f"Signature       : {signature}"
        )

        print(
            f"Severity        : {severity}"
        )

        print(
            f"Source IP       : {source_ip}"
        )

        print(
            f"Source Type     : {source_type}"
        )

        print(
            f"Destination IP  : {destination_ip}"
        )

        print(
            f"Destination Type: {destination_type}"
        )

        print(
            f"Protocol        : {protocol}"
        )

        print(
            f"Interface       : {interface}"
        )

        # ------------------------------------------------------
        # ABUSEIPDB
        # ------------------------------------------------------

        print(
            "\n----- ABUSEIPDB THREAT INTELLIGENCE -----"
        )

        source_abuse = None
        destination_abuse = None

        if source_type == "Public IP":

            print(
                "\nSource IP Enrichment:"
            )

            source_abuse = get_enrichment(
                source_ip
            )

            print_result(
                source_abuse
            )

        else:

            print(
                "\nSource IP Enrichment:"
            )

            print(
                "Skipped - source IP is private/internal"
            )

        if destination_type == "Public IP":

            print(
                "\nDestination IP Enrichment:"
            )

            destination_abuse = get_enrichment(
                destination_ip
            )

            print_result(
                destination_abuse
            )

        else:

            print(
                "\nDestination IP Enrichment:"
            )

            print(
                "Skipped - destination IP is private/internal"
            )

        # ------------------------------------------------------
        # VIRUSTOTAL
        # ------------------------------------------------------

        print(
            "\n----- VIRUSTOTAL THREAT INTELLIGENCE -----"
        )

        source_vt = None
        destination_vt = None

        if source_type == "Public IP":

            print(
                "\nSource IP VirusTotal:"
            )

            source_vt = get_virustotal(
                source_ip
            )

            print_result(
                source_vt
            )

        else:

            print(
                "\nSource IP VirusTotal:"
            )

            print(
                "Skipped - source IP is private/internal"
            )

        if destination_type == "Public IP":

            print(
                "\nDestination IP VirusTotal:"
            )

            destination_vt = get_virustotal(
                destination_ip
            )

            print_result(
                destination_vt
            )

        else:

            print(
                "\nDestination IP VirusTotal:"
            )

            print(
                "Skipped - destination IP is private/internal"
            )

        # ------------------------------------------------------
        # RISK ENGINE
        # ------------------------------------------------------

        print(
            "\n----- SOC RISK ASSESSMENT -----"
        )

        abuse_result = (
            source_abuse
            or destination_abuse
        )

        vt_result = (
            source_vt
            or destination_vt
        )

        if abuse_result:

            abuse_score = abuse_result.get(
                "abuse_score"
            )

            if abuse_score is None:

                abuse_score = 0

        else:

            abuse_score = 0

        if vt_result:

            vt_malicious = vt_result.get(
                "malicious",
                0
            )

            if vt_malicious is None:

                vt_malicious = 0

        else:

            vt_malicious = 0

        risk = calculate_risk(
            severity,
            abuse_score,
            vt_malicious
        )

        print(
            f"Suricata Severity : {severity}"
        )

        print(
            f"AbuseIPDB Score   : {abuse_score}"
        )

        print(
            f"VT Malicious      : {vt_malicious}"
        )

        print(
            f"Risk Level        : {risk}"
        )

        # ------------------------------------------------------
        # MITRE ATT&CK
        # ------------------------------------------------------

        print(
            "\n----- MITRE ATT&CK MAPPING -----"
        )

        mitre_mapping = get_mitre_mapping(
            signature
        )

        if mitre_mapping:

            print(
                f"Tactic          : "
                f"{mitre_mapping.get('tactic')}"
            )

            print(
                f"Technique ID    : "
                f"{mitre_mapping.get('technique_id')}"
            )

            print(
                f"Technique Name  : "
                f"{mitre_mapping.get('technique_name')}"
            )

            print(
                f"Confidence      : "
                f"{mitre_mapping.get('confidence')}"
            )

        else:

            print(
                "No MITRE ATT&CK mapping found."
            )

        # ------------------------------------------------------
        # COMBINED THREAT INTELLIGENCE
        # ------------------------------------------------------

        threat_intelligence = {}

        if abuse_result:

            for key, value in abuse_result.items():

                threat_intelligence[
                    f"abuseipdb_{key}"
                ] = value

        if vt_result:

            for key, value in vt_result.items():

                threat_intelligence[
                    f"virustotal_{key}"
                ] = value

        # ------------------------------------------------------
        # INCIDENT REPORT
        # ------------------------------------------------------

        print(
            "\n----- INCIDENT REPORT -----"
        )

        report_path = generate_report(

            signature=signature,

            severity=severity,

            source_ip=source_ip,

            source_type=source_type,

            destination_ip=destination_ip,

            destination_type=destination_type,

            protocol=protocol,

            interface=interface,

            threat_intelligence=threat_intelligence,

            risk_level=risk,

            mitre_mapping=mitre_mapping
        )

        print(
            f"Report generated : {report_path}"
        )

        print(
            "=========================================="
        )

    # ----------------------------------------------------------
    # SAVE STATE
    # ----------------------------------------------------------

    save_state(
        total_lines
    )

    print(
        "\n=========================================="
    )

    print(
        "          PROCESSING COMPLETE"
    )

    print(
        "=========================================="
    )

    print(
        f"New lines processed  : {len(new_lines)}"
    )

    print(
        f"Alerts detected      : {processed_events}"
    )

    print(
        f"State saved at line  : {total_lines}"
    )

    print(
        "==========================================\n"
    )


if __name__ == "__main__":

    read_alerts()
