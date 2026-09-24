import csv
import ipaddress
import re
from collections import Counter

DATA_FILE = "data/threats.csv"


def load_threats():
    """Load threat intelligence data from the CSV file."""

    threats = []

    with open(DATA_FILE, "r", newline="", encoding="utf-8") as file:
        reader = csv.DictReader(file)

        for row in reader:
            threats.append(row)

    return threats


def display_threats(threats):
    """Display a summary of the available threats."""

    print("ThreatLens-CTI")
    print("=" * 40)
    print(f"Threats analysed: {len(threats)}")
    print()

    for threat in threats:
        print(f"Threat ID: {threat['threat_id']}")
        print(f"Threat: {threat['threat_name']}")
        print(f"Type: {threat['threat_type']}")
        print(f"Tactic: {threat['tactic']}")
        print(f"Technique: {threat['technique']}")
        print(f"Technique ID: {threat['technique_id']}")
        ioc_valid = validate_ioc(threat["ioc_type"], threat["ioc"])
        print(f"IOC: {threat['ioc']}")
        print(f"IOC validation: {'VALID' if ioc_valid else 'INVALID'}")
        print("-" * 40)

def validate_ioc(ioc_type, ioc):
    """Validate an IOC based on its declared type."""

    if ioc_type == "ip":
        try:
            ipaddress.ip_address(ioc)
            return True
        except ValueError:
            return False

    if ioc_type == "domain":
        domain_pattern = r"^(?=.{1,253}$)([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$"
        return bool(re.match(domain_pattern, ioc))

    if ioc_type == "sha256":
        sha256_pattern = r"^[a-fA-F0-9]{64}$"
        return bool(re.match(sha256_pattern, ioc))

    return False


def display_statistics(threats):
    """Analyse and display statistics about the threat data."""

    tactics = Counter(threat["tactic"] for threat in threats)
    ioc_types = Counter(threat["ioc_type"] for threat in threats)
    techniques = Counter(
        (threat["technique_id"], threat["technique"])
        for threat in threats
    )

    print("\nTACTIC SUMMARY")
    print("-" * 40)

    for tactic, count in sorted(tactics.items()):
        print(f"{tactic}: {count}")

    print("\nIOC SUMMARY")
    print("-" * 40)

    ioc_labels = {
        "ip": "IP addresses",
        "domain": "Domains",
        "sha256": "SHA-256 hashes"
    }

    for ioc_type, count in sorted(ioc_types.items()):
        label = ioc_labels.get(ioc_type, ioc_type)
        print(f"{label}: {count}")

    print("\nMITRE ATT&CK TECHNIQUES")
    print("-" * 40)

    for (technique_id, technique), count in sorted(techniques.items()):
        print(f"{technique_id} - {technique}: {count}")


def main():
    """Run the ThreatLens-CTI analysis."""

    threats = load_threats()

    display_threats(threats)
    display_statistics(threats)


if __name__ == "__main__":
    main()