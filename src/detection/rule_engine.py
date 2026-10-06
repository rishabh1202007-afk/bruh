import json
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]

DATA_DIR = PROJECT_ROOT / "data" / "raw"

INPUT_FILE = DATA_DIR / "classified_events.jsonl"
OUTPUT_FILE = DATA_DIR / "detections.jsonl"
CHECKPOINT_FILE = DATA_DIR / "detection_checkpoint.json"


def load_checkpoint():
    """Load the last classified event processed by the detection engine."""

    if not CHECKPOINT_FILE.exists():
        return 0

    with CHECKPOINT_FILE.open("r", encoding="utf-8") as file:
        data = json.load(file)

    return data.get("last_record_number", 0)


def save_checkpoint(record_number):
    """Save the latest processed Record Number."""

    with CHECKPOINT_FILE.open("w", encoding="utf-8") as file:
        json.dump(
            {
                "last_record_number": record_number
            },
            file,
            indent=4
        )


def detect_special_privileges(event):
    """SM-001: Special Privileges Assigned."""

    if event.get("event_id") != 4672:
        return None

    return {
        "timestamp": event.get("timestamp"),
        "host": event.get("host"),
        "event_id": 4672,
        "rule_id": "SM-001",
        "rule_name": "Special Privileges Assigned",
        "severity": "medium",
        "category": "privilege",
        "username": event.get("username"),
        "logon_id": event.get("logon_id"),
        "privileges": event.get("privileges"),
        "source_record": event.get("record_number"),
    }


def detect_account_enumeration(event):
    """SM-002: User Account Enumeration."""

    if event.get("event_id") != 4798:
        return None

    return {
        "timestamp": event.get("timestamp"),
        "host": event.get("host"),
        "event_id": 4798,
        "rule_id": "SM-002",
        "rule_name": "User Account Enumeration",
        "severity": "low",
        "category": "account_discovery",
        "target_username": event.get("target_username"),
        "target_computer": event.get("target_computer"),
        "subject_username": event.get("subject_username"),
        "process_name": event.get("process_name"),
        "source_record": event.get("record_number"),
    }


def detect_credential_access(event):
    """SM-003: Credential Manager Activity."""

    if event.get("event_id") != 5379:
        return None

    return {
        "timestamp": event.get("timestamp"),
        "host": event.get("host"),
        "event_id": 5379,
        "rule_id": "SM-003",
        "rule_name": "Credential Manager Activity",
        "severity": "medium",
        "category": "credential_access",
        "username": event.get("username"),
        "target_computer": event.get("target_computer"),
        "logon_id": event.get("logon_id"),
        "status": event.get("status"),
        "operation": event.get("operation"),
        "result_code": event.get("result_code"),
        "error_code": event.get("error_code"),
        "process_id": event.get("process_id"),
        "source_record": event.get("record_number"),
    }


def run_detection():

    if not INPUT_FILE.exists():
        print("Classified event file not found.")
        return

    last_record_number = load_checkpoint()

    print(
        f"Last detected Record Number: "
        f"{last_record_number}"
    )

    new_events = []

    with INPUT_FILE.open(
        "r",
        encoding="utf-8"
    ) as input_file:

        for line in input_file:

            if not line.strip():
                continue

            event = json.loads(line)

            record_number = event.get(
                "record_number",
                0
            )

            if record_number <= last_record_number:
                continue

            new_events.append(event)

    if not new_events:
        print("No new events to detect.")
        return

    detections = []

    for event in new_events:

        detection = detect_special_privileges(event)

        if detection:
            detections.append(detection)

        detection = detect_account_enumeration(event)

        if detection:
            detections.append(detection)

        detection = detect_credential_access(event)

        if detection:
            detections.append(detection)

    with OUTPUT_FILE.open(
        "a",
        encoding="utf-8"
    ) as output_file:

        for detection in detections:

            output_file.write(
                json.dumps(
                    detection,
                    default=str
                )
                + "\n"
            )

    newest_record_number = max(
        event["record_number"]
        for event in new_events
    )

    save_checkpoint(
        newest_record_number
    )

    print(
        f"New events analyzed : "
        f"{len(new_events)}"
    )

    print(
        f"New detections      : "
        f"{len(detections)}"
    )

    print(
        f"Latest Record Number: "
        f"{newest_record_number}"
    )

    print(
        f"Checkpoint file     : "
        f"{CHECKPOINT_FILE}"
    )

    print("Incremental detection successful.")


if __name__ == "__main__":
    run_detection()