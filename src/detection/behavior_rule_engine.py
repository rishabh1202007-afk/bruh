import json
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parents[2]

INPUT_FILE = (
    BASE_DIR
    / "data"
    / "raw"
    / "behavior_telemetry.jsonl"
)

OUTPUT_FILE = (
    BASE_DIR
    / "data"
    / "raw"
    / "behavior_detections.jsonl"
)


BEHAVIOR_RULES = {

    "script_execution": {
        "rule_id": "BT-001",
        "rule_name": "Suspicious Script Execution",
        "severity": "medium",
        "category": "execution"
    },

    "command_and_control_indicator": {
        "rule_id": "BT-002",
        "rule_name": "Possible Command and Control Activity",
        "severity": "high",
        "category": "command_and_control"
    },

    "browser_data_access": {
        "rule_id": "BT-003",
        "rule_name": "Browser Data Access Indicator",
        "severity": "high",
        "category": "credential_access"
    },

    "persistence_indicator": {
        "rule_id": "BT-004",
        "rule_name": "Persistence Activity Indicator",
        "severity": "high",
        "category": "persistence"
    },

    "privilege_indicator": {
        "rule_id": "BT-005",
        "rule_name": "Privilege Activity Indicator",
        "severity": "high",
        "category": "privilege"
    }
}


def load_telemetry():

    if not INPUT_FILE.exists():
        return []

    events = []

    with open(
        INPUT_FILE,
        "r",
        encoding="utf-8"
    ) as f:

        for line in f:

            line = line.strip()

            if not line:
                continue

            try:
                events.append(
                    json.loads(line)
                )

            except json.JSONDecodeError:
                continue

    return events


def create_detection(event, rule):

    return {
        "detection_id": (
            f"{rule['rule_id']}-"
            f"{event.get('telemetry_id')}"
        ),

        "timestamp": event.get(
            "timestamp"
        ),

        "host": event.get(
            "host"
        ),

        "rule_id": rule["rule_id"],

        "rule_name": rule["rule_name"],

        "severity": rule["severity"],

        "category": rule["category"],

        "threat_profile": event.get(
            "threat_profile"
        ),

        "behavior_type": event.get(
            "behavior_type"
        ),

        "process_name": event.get(
            "process_name"
        ),

        "source_telemetry": event.get(
            "telemetry_id"
        ),

        "description": event.get(
            "description"
        )
    }


def run_detection():

    telemetry = load_telemetry()

    print(
        f"Telemetry events loaded: "
        f"{len(telemetry)}"
    )

    if not telemetry:
        print(
            "No behavior telemetry found."
        )
        return

    detections = []

    for event in telemetry:

        behavior_type = event.get(
            "behavior_type"
        )

        rule = BEHAVIOR_RULES.get(
            behavior_type
        )

        if not rule:
            continue

        detection = create_detection(
            event,
            rule
        )

        detections.append(
            detection
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

        for detection in detections:

            f.write(
                json.dumps(
                    detection,
                    ensure_ascii=False
                )
                + "\n"
            )

    print(
        f"Behavior detections generated: "
        f"{len(detections)}"
    )

    print(
        f"Output file: "
        f"{OUTPUT_FILE}"
    )

    print(
        "Behavior detection completed."
    )


if __name__ == "__main__":
    run_detection()