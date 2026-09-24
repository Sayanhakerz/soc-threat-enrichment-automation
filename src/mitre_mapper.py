import yaml


MAPPING_FILE = "config/mitre_mapping.yaml"


def load_mappings():
    """
    Load MITRE ATT&CK mappings from the YAML configuration file.
    """

    try:
        with open(MAPPING_FILE, "r") as file:
            data = yaml.safe_load(file)

        return data.get("mappings", {})

    except FileNotFoundError:
        print("MITRE mapping file not found.")
        return {}

    except yaml.YAMLError as error:
        print(f"Invalid YAML configuration: {error}")
        return {}


def get_mitre_mapping(signature):
    """
    Return the MITRE ATT&CK mapping for a Suricata signature.

    Uses exact matching first, then checks whether a configured
    signature appears inside the detected signature.
    """

    mappings = load_mappings()

    # Exact match
    if signature in mappings:
        return mappings[signature]

    # Partial match
    for mapped_signature, mapping in mappings.items():

        if mapped_signature in signature:
            return mapping

    return None


if __name__ == "__main__":

    test_signature = "SOC LAB - ICMP Ping Detected"

    result = get_mitre_mapping(test_signature)

    print("\n==========================================")
    print("       MITRE ATT&CK MAPPING TEST")
    print("==========================================")

    if result:

        print(f"Tactic          : {result.get('tactic')}")
        print(f"Technique ID    : {result.get('technique_id')}")
        print(f"Technique Name  : {result.get('technique_name')}")
        print(f"Confidence      : {result.get('confidence')}")
        print(f"Rationale       : {result.get('rationale')}")

    else:

        print("No MITRE ATT&CK mapping found.")

    print("==========================================\n")
