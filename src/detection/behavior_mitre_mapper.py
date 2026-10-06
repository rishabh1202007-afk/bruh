import json
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parents[2]

INPUT_FILE = BASE_DIR / "data" / "raw" / "behavior_detections.jsonl"
OUTPUT_FILE = BASE_DIR / "data" / "raw" / "behavior_mitre_mapped.jsonl"


# ATT&CK mappings based on the behavioral indicators
MITRE_MAPPING = {
    "BT-001": {
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "tactic": "Execution"
    },
    "BT-002": {
        "technique_id": "T1071",
        "technique_name": "Application Layer Protocol",
        "tactic": "Command and Control"
    },
    "BT-003": {
        "technique_id": "T1555",
        "technique_name": "Credentials from Password Stores",
        "tactic": "Credential Access"
    },
    "BT-004": {
        "technique_id": "T1547",
        "technique_name": "Boot or Logon Autostart Execution",
        "tactic": "Persistence"
    },
    "BT-005": {
        "technique_id": "T1068",
        "technique_name": "Exploitation for Privilege Escalation",
        "tactic": "Privilege Escalation"
    }
}


def load_jsonl(file_path):
    records = []

    if not file_path.exists():
        return records

    with file_path.open("r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()

            if not line:
                continue

            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    return records


def map_detection_to_mitre(detection):
    rule_id = detection.get("rule_id")

    mapping = MITRE_MAPPING.get(rule_id)

    mapped = dict(detection)

    if mapping:
        mapped["mitre"] = {
            "technique_id": mapping["technique_id"],
            "technique_name": mapping["technique_name"],
            "tactic": mapping["tactic"],
            "mapping_basis": (
                "Behavioral indicator mapped to an ATT&CK technique "
                "for contextual analysis."
            )
        }
    else:
        mapped["mitre"] = {
            "technique_id": None,
            "technique_name": None,
            "tactic": None,
            "mapping_basis": "No configured ATT&CK mapping."
        }

    return mapped


def main():
    detections = load_jsonl(INPUT_FILE)

    if not detections:
        print("No behavior detections found.")
        return

    mapped_detections = []

    for detection in detections:
        mapped_detections.append(
            map_detection_to_mitre(detection)
        )

    with OUTPUT_FILE.open("w", encoding="utf-8") as file:
        for detection in mapped_detections:
            file.write(
                json.dumps(
                    detection,
                    ensure_ascii=False
                ) + "\n"
            )

    print(f"Behavior detections loaded: {len(detections)}")
    print(f"MITRE-mapped behavior detections: {len(mapped_detections)}")
    print(f"Output file: {OUTPUT_FILE}")
    print("Behavior MITRE mapping completed.")


if __name__ == "__main__":
    main()