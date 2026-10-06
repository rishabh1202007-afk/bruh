import json
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parents[2]

INCIDENT_FILE = (
    BASE_DIR
    / "data"
    / "raw"
    / "enriched_multisource_incidents.jsonl"
)

BEHAVIOR_MITRE_FILE = (
    BASE_DIR
    / "data"
    / "raw"
    / "behavior_mitre_mapped.jsonl"
)

OUTPUT_FILE = (
    BASE_DIR
    / "data"
    / "raw"
    / "mitre_enriched_multisource_incidents.jsonl"
)


# Windows detection -> MITRE mapping
WINDOWS_MITRE_MAPPING = {
    "SM-001": {
        "technique_id": None,
        "technique_name": None,
        "tactic": None
    },
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


def load_jsonl(file_path):
    records = []

    if not file_path.exists():
        return records

    with file_path.open(
        "r",
        encoding="utf-8"
    ) as file:

        for line in file:
            line = line.strip()

            if not line:
                continue

            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    return records


def build_behavior_mitre_index(records):
    index = {}

    for record in records:

        detection_id = record.get(
            "detection_id"
        )

        if not detection_id:
            continue

        mitre = record.get(
            "mitre",
            {}
        )

        technique_id = mitre.get(
            "technique_id"
        )

        if technique_id:
            index[detection_id] = {
                "technique_id": technique_id,
                "technique_name": mitre.get(
                    "technique_name"
                ),
                "tactic": mitre.get(
                    "tactic"
                )
            }

    return index


def add_unique_technique(
    techniques,
    technique
):
    technique_id = technique.get(
        "technique_id"
    )

    if not technique_id:
        return

    existing_ids = [
        item.get("technique_id")
        for item in techniques
    ]

    if technique_id not in existing_ids:
        techniques.append(technique)


def enrich_incident(
    incident,
    behavior_mitre_index
):
    windows_techniques = []
    behavior_techniques = []

    evidence = incident.get(
        "evidence",
        []
    )

    for item in evidence:

        source = item.get(
            "source"
        )

        # -----------------------------------------
        # Windows Security evidence
        # -----------------------------------------

        if source == "windows_security":

            rule_id = item.get(
                "rule_id"
            )

            mapping = WINDOWS_MITRE_MAPPING.get(
                rule_id
            )

            if mapping:
                add_unique_technique(
                    windows_techniques,
                    mapping
                )

        # -----------------------------------------
        # Behavior telemetry evidence
        # -----------------------------------------

        elif source == "behavior_telemetry":

            detection_id = item.get(
                "detection_id"
            )

            mapping = behavior_mitre_index.get(
                detection_id
            )

            if mapping:
                add_unique_technique(
                    behavior_techniques,
                    mapping
                )

    combined_techniques = []

    for technique in (
        windows_techniques +
        behavior_techniques
    ):
        add_unique_technique(
            combined_techniques,
            technique
        )

    tactics_observed = []

    for technique in combined_techniques:

        tactic = technique.get(
            "tactic"
        )

        if tactic and tactic not in tactics_observed:
            tactics_observed.append(tactic)

    enriched = dict(incident)

    enriched["mitre_context"] = {
        "windows_techniques": windows_techniques,

        "behavior_techniques": behavior_techniques,

        "combined_techniques": combined_techniques,

        "technique_count": len(
            combined_techniques
        ),

        "tactics_observed": tactics_observed,

        "mapping_status": (
            "contextual_behavioral_mapping"
        ),

        "attribution_warning": (
            "MITRE technique mapping describes the "
            "behaviors represented by the telemetry. "
            "It does not prove that a specific malware "
            "family performed the activity."
        )
    }

    return enriched


def main():

    incidents = load_jsonl(
        INCIDENT_FILE
    )

    behavior_mitre_records = load_jsonl(
        BEHAVIOR_MITRE_FILE
    )

    if not incidents:
        print(
            "No enriched multi-source incidents found."
        )
        return

    behavior_mitre_index = (
        build_behavior_mitre_index(
            behavior_mitre_records
        )
    )

    enriched_incidents = []

    for incident in incidents:

        enriched = enrich_incident(
            incident,
            behavior_mitre_index
        )

        enriched_incidents.append(
            enriched
        )

    with OUTPUT_FILE.open(
        "w",
        encoding="utf-8"
    ) as file:

        for incident in enriched_incidents:

            file.write(
                json.dumps(
                    incident,
                    ensure_ascii=False
                ) + "\n"
            )

    print(
        f"Incidents loaded: "
        f"{len(incidents)}"
    )

    print(
        f"Behavior MITRE records loaded: "
        f"{len(behavior_mitre_records)}"
    )

    print(
        f"Behavior MITRE index entries: "
        f"{len(behavior_mitre_index)}"
    )

    print(
        f"MITRE-enriched incidents: "
        f"{len(enriched_incidents)}"
    )

    print(
        f"Output file: {OUTPUT_FILE}"
    )

    print(
        "Multi-source MITRE enrichment completed."
    )


if __name__ == "__main__":
    main()