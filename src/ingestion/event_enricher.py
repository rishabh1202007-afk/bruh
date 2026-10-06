import json
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]

RAW_DATA_DIR = PROJECT_ROOT / "data" / "raw"

INPUT_FILE = RAW_DATA_DIR / "normalized_events.jsonl"
OUTPUT_FILE = RAW_DATA_DIR / "enriched_events.jsonl"
CHECKPOINT_FILE = RAW_DATA_DIR / "enrichment_checkpoint.json"


def load_checkpoint():
    """Load the last enriched Record Number."""

    if not CHECKPOINT_FILE.exists():
        return 0

    with CHECKPOINT_FILE.open("r", encoding="utf-8") as file:
        data = json.load(file)

    return data.get("last_record_number", 0)


def save_checkpoint(record_number):
    """Save the latest enriched Record Number."""

    with CHECKPOINT_FILE.open("w", encoding="utf-8") as file:
        json.dump(
            {
                "last_record_number": record_number
            },
            file,
            indent=4
        )


def enrich_event(event):
    """
    Add security-relevant fields to a normalized event.
    """

    enriched = event.copy()

    event_id = event.get("event_id")
    raw_data = event.get("raw_data", [])

    # Event ID 4624 - Successful Logon
    if event_id == 4624:

        enriched["event_name"] = "successful_logon"

        enriched["user_sid"] = (
            raw_data[4] if len(raw_data) > 4 else None
        )

        enriched["username"] = (
            raw_data[5] if len(raw_data) > 5 else None
        )

        enriched["domain"] = (
            raw_data[6] if len(raw_data) > 6 else None
        )

        enriched["logon_type"] = (
            raw_data[8] if len(raw_data) > 8 else None
        )

        enriched["authentication_package"] = (
            raw_data[10] if len(raw_data) > 10 else None
        )

        enriched["process_name"] = (
            raw_data[17] if len(raw_data) > 17 else None
        )

    # Event ID 4672 - Special Privileges Assigned
    elif event_id == 4672:

        enriched["event_name"] = "special_privileges_assigned"

        enriched["user_sid"] = (
            raw_data[0] if len(raw_data) > 0 else None
        )

        enriched["username"] = (
            raw_data[1] if len(raw_data) > 1 else None
        )

        enriched["domain"] = (
            raw_data[2] if len(raw_data) > 2 else None
        )

        enriched["logon_id"] = (
            raw_data[3] if len(raw_data) > 3 else None
        )

        enriched["privileges"] = (
            raw_data[4] if len(raw_data) > 4 else None
        )

    # Event ID 4798 - User Account Enumeration
    elif event_id == 4798:

        enriched["event_name"] = "user_account_enumeration"

        enriched["target_username"] = (
            raw_data[0] if len(raw_data) > 0 else None
        )

        enriched["target_computer"] = (
            raw_data[1] if len(raw_data) > 1 else None
        )

        enriched["target_user_sid"] = (
            raw_data[2] if len(raw_data) > 2 else None
        )

        enriched["subject_user_sid"] = (
            raw_data[3] if len(raw_data) > 3 else None
        )

        enriched["subject_username"] = (
            raw_data[4] if len(raw_data) > 4 else None
        )

        enriched["subject_domain"] = (
            raw_data[5] if len(raw_data) > 5 else None
        )

        enriched["logon_id"] = (
            raw_data[6] if len(raw_data) > 6 else None
        )

        enriched["process_id"] = (
            raw_data[7] if len(raw_data) > 7 else None
        )

        enriched["process_name"] = (
            raw_data[8] if len(raw_data) > 8 else None
        )

    # Event ID 5379 - Credential Manager Access
    elif event_id == 5379:

        enriched["event_name"] = "credential_manager_access"

        enriched["user_sid"] = (
            raw_data[0] if len(raw_data) > 0 else None
        )

        enriched["username"] = (
            raw_data[1] if len(raw_data) > 1 else None
        )

        enriched["target_computer"] = (
            raw_data[2] if len(raw_data) > 2 else None
        )

        enriched["logon_id"] = (
            raw_data[3] if len(raw_data) > 3 else None
        )

        enriched["status"] = (
            raw_data[5] if len(raw_data) > 5 else None
        )

        enriched["operation"] = (
            raw_data[6] if len(raw_data) > 6 else None
        )

        enriched["result_code"] = (
            raw_data[7] if len(raw_data) > 7 else None
        )

        enriched["error_code"] = (
            raw_data[8] if len(raw_data) > 8 else None
        )

        enriched["event_timestamp"] = (
            raw_data[9] if len(raw_data) > 9 else None
        )

        enriched["process_id"] = (
            raw_data[10] if len(raw_data) > 10 else None
        )

    return enriched


def enrich_events():

    if not INPUT_FILE.exists():
        print("Normalized event file not found.")
        return

    last_record_number = load_checkpoint()

    print(
        f"Last enriched Record Number: "
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

            new_events.append(
                enrich_event(event)
            )

    if not new_events:

        print("No new events to enrich.")
        return

    with OUTPUT_FILE.open(
        "a",
        encoding="utf-8"
    ) as output_file:

        for event in new_events:

            output_file.write(
                json.dumps(
                    event,
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
        f"New events enriched : "
        f"{len(new_events)}"
    )

    print(
        f"Latest Record Number: "
        f"{newest_record_number}"
    )

    print(
        f"Output file         : "
        f"{OUTPUT_FILE}"
    )

    print(
        f"Checkpoint file     : "
        f"{CHECKPOINT_FILE}"
    )

    print("Incremental enrichment successful.")


if __name__ == "__main__":
    enrich_events()