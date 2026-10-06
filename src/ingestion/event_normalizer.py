import json
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]

RAW_DATA_DIR = PROJECT_ROOT / "data" / "raw"

INPUT_FILE = RAW_DATA_DIR / "windows_security_events.jsonl"
OUTPUT_FILE = RAW_DATA_DIR / "normalized_events.jsonl"
CHECKPOINT_FILE = RAW_DATA_DIR / "normalization_checkpoint.json"


def load_checkpoint():
    """Load the last normalized Record Number."""

    if not CHECKPOINT_FILE.exists():
        return 0

    with CHECKPOINT_FILE.open("r", encoding="utf-8") as file:
        data = json.load(file)

    return data.get("last_record_number", 0)


def save_checkpoint(record_number):
    """Save the latest normalized Record Number."""

    with CHECKPOINT_FILE.open("w", encoding="utf-8") as file:
        json.dump(
            {
                "last_record_number": record_number
            },
            file,
            indent=4
        )


def normalize_event(raw_event):
    """Convert a raw Windows event into the SentinelMesh schema."""

    return {
        "timestamp": raw_event.get("timestamp"),
        "source": "windows_security",
        "event_id": raw_event.get("event_id"),
        "record_number": raw_event.get("record_number"),
        "host": raw_event.get("computer"),
        "event_type": raw_event.get("event_type"),
        "raw_data": raw_event.get("strings"),
    }


def normalize_events():

    if not INPUT_FILE.exists():
        print("Raw event file not found.")
        return

    last_record_number = load_checkpoint()

    print(
        f"Last normalized Record Number: "
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

            raw_event = json.loads(line)

            record_number = raw_event.get(
                "record_number",
                0
            )

            if record_number <= last_record_number:
                continue

            new_events.append(
                normalize_event(raw_event)
            )

    if not new_events:
        print("No new events to normalize.")
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
        f"New events normalized : "
        f"{len(new_events)}"
    )

    print(
        f"Latest Record Number  : "
        f"{newest_record_number}"
    )

    print(
        f"Output file           : "
        f"{OUTPUT_FILE}"
    )

    print("Incremental normalization successful.")


if __name__ == "__main__":
    normalize_events()