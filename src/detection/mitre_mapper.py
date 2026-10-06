import json
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[2]

INPUT_FILE = (
    BASE_DIR
    / "data"
    / "raw"
    / "enriched_incidents.jsonl"
)

OUTPUT_FILE = (
    BASE_DIR
    / "data"
    / "raw"
    / "mitre_mapped_incidents.jsonl"
)


MITRE_MAPPINGS = {
    "SM-002": {
        "technique_id": "T1087",
        "technique_name": "Account Discovery",
        "tactic": "Discovery"
    },
    "SM-003": {
        "technique_id": "T1555.004",
        "technique_name": "Credentials from Password Stores",
        "tactic": "Credential Access"
    }
}


def load_incidents():
    if not INPUT_FILE.exists():
        return []

    incidents = []

    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()

            if not line:
                continue

            try:
                incidents.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    return incidents


def map_incident_to_mitre(incident):
    mappings = []
    seen_techniques = set()

    for event in incident.get("events", []):
        rule_id = event.get("rule_id")

        mapping = MITRE_MAPPINGS.get(rule_id)

        if not mapping:
            continue

        technique_id = mapping["technique_id"]

        if technique_id in seen_techniques:
            continue

        mappings.append({
            "rule_id": rule_id,
            "technique_id": technique_id,
            "technique_name": mapping["technique_name"],
            "tactic": mapping["tactic"]
        })

        seen_techniques.add(technique_id)

    enriched = dict(incident)

    enriched["mitre_attack"] = mappings

    return enriched


def run_mapping():
    incidents = load_incidents()

    print(f"Incidents loaded: {len(incidents)}")

    if not incidents:
        print("No enriched incidents found.")
        return

    mapped_incidents = []

    for incident in incidents:
        mapped_incidents.append(
            map_incident_to_mitre(incident)
        )

    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with open(
        OUTPUT_FILE,
        "w",
        encoding="utf-8"
    ) as f:

        for incident in mapped_incidents:
            f.write(
                json.dumps(
                    incident,
                    ensure_ascii=False
                ) + "\n"
            )

    print(
        f"MITRE-mapped incidents: "
        f"{len(mapped_incidents)}"
    )

    print(
        f"Output file: "
        f"{OUTPUT_FILE}"
    )

    print("MITRE ATT&CK mapping completed.")


if __name__ == "__main__":
    run_mapping()