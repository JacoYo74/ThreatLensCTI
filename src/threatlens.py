import csv

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
        print(f"IOC: {threat['ioc']}")
        print("-" * 40)


def main():
    """Run the ThreatLens-CTI analysis."""

    threats = load_threats()
    display_threats(threats)


if __name__ == "__main__":
    main()
