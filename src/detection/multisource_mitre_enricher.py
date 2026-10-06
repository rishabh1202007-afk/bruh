import json
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parents[2]

INPUT_FILE = (
    BASE_DIR
    / "data"
    / "raw"
    / "enriched_multisource_incidents.jsonl"
)

OUTPUT_FILE = (
    BASE_DIR
    / "data"
    / "raw"
    / "mitre_enriched_multisource_incidents.jsonl"
)


# ---------------------------------------------------------
# Windows Security detection mappings
# ---------------------------------------------------------

WINDOWS_MITRE_MAPPING = {
    "SM-001": None,

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


# ---------------------------------------------------------
# Behavior detection mappings
# ---------------------------------------------------------

BEHAVIOR_MITRE_MAPPING = {
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

    with file_path.open(
        "r",
        encoding="utf-8"
    ) as file:

        for line in file:

            line = line.strip()

            if not line:
                continue

            try:
                records.append(
                    json.loads(line)
                )

            except json.JSONDecodeError:
                continue

    return records


def add_unique(
    collection,
    technique
):

    if technique is None:
        return

    technique_id = technique.get(
        "technique_id"
    )

    if not technique_id:
        return

    for existing in collection:

        if existing.get(
            "technique_id"
        ) == technique_id:

            return

    collection.append(
        technique
    )


def enrich_incident(incident):

    windows_techniques = []

    behavior_techniques = []

    evidence = incident.get(
        "evidence",
        []
    )

    # -----------------------------------------------------
    # Process evidence
    # -----------------------------------------------------

    for item in evidence:

        source = item.get(
            "source"
        )

        rule_id = item.get(
            "rule_id"
        )

        # Windows Security
        if source == "windows_security":

            mapping = WINDOWS_MITRE_MAPPING.get(
                rule_id
            )

            add_unique(
                windows_techniques,
                mapping
            )

        # Behavior telemetry
        elif source == "behavior_telemetry":

            mapping = BEHAVIOR_MITRE_MAPPING.get(
                rule_id
            )

            add_unique(
                behavior_techniques,
                mapping
            )

    # -----------------------------------------------------
    # Combine techniques
    # -----------------------------------------------------

    combined_techniques = []

    for technique in (
        windows_techniques +
        behavior_techniques
    ):

        add_unique(
            combined_techniques,
            technique
        )

    # -----------------------------------------------------
    # Extract tactics
    # -----------------------------------------------------

    tactics_observed = []

    for technique in combined_techniques:

        tactic = technique.get(
            "tactic"
        )

        if (
            tactic
            and
            tactic not in tactics_observed
        ):

            tactics_observed.append(
                tactic
            )

    # -----------------------------------------------------
    # Build output
    # -----------------------------------------------------

    enriched = dict(
        incident
    )

    enriched["mitre_context"] = {

        "windows_techniques":
            windows_techniques,

        "behavior_techniques":
            behavior_techniques,

        "combined_techniques":
            combined_techniques,

        "technique_count":
            len(combined_techniques),

        "tactics_observed":
            tactics_observed,

        "mapping_status":
            "contextual_behavioral_mapping",

        "attribution_warning":
            (
                "MITRE technique mapping describes "
                "the behaviors represented by the "
                "telemetry. It does not prove that "
                "a specific malware family performed "
                "the activity."
            )
    }

    return enriched


def main():

    incidents = load_jsonl(
        INPUT_FILE
    )

    if not incidents:

        print(
            "No enriched multi-source incidents found."
        )

        return

    enriched_incidents = []

    for incident in incidents:

        enriched_incidents.append(
            enrich_incident(
                incident
            )
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