import json
from pathlib import Path
from datetime import timezone

import win32evtlog


# SentinelMesh project paths
PROJECT_ROOT = Path(__file__).resolve().parents[2]

RAW_DATA_DIR = PROJECT_ROOT / "data" / "raw"

OUTPUT_FILE = RAW_DATA_DIR / "windows_security_events.jsonl"
CHECKPOINT_FILE = RAW_DATA_DIR / "ingestion_checkpoint.json"


def convert_event(event):
    """
    Convert a Windows Event Log record into a JSON-serializable dictionary.
    """

    event_id = event.EventID & 0xFFFF

    timestamp = event.TimeGenerated

    if timestamp:
        timestamp = timestamp.replace(
            tzinfo=timezone.utc
        ).isoformat()

    return {
        "event_id": event_id,
        "source": event.SourceName,
        "computer": event.ComputerName,
        "category": event.EventCategory,
        "record_number": event.RecordNumber,
        "timestamp": timestamp,
        "event_type": event.EventType,
        "strings": event.StringInserts,
    }


def load_checkpoint():
    """
    Load the last processed Windows Event Record Number.
    """

    if not CHECKPOINT_FILE.exists():
        return 0

    with CHECKPOINT_FILE.open("r", encoding="utf-8") as file:
        data = json.load(file)

    return data.get("last_record_number", 0)


def save_checkpoint(record_number):
    """
    Save the latest processed Record Number.
    """

    RAW_DATA_DIR.mkdir(parents=True, exist_ok=True)

    with CHECKPOINT_FILE.open("w", encoding="utf-8") as file:
        json.dump(
            {
                "last_record_number": record_number
            },
            file,
            indent=4
        )


def read_new_security_events(max_events=100):
    """
    Read only Windows Security events newer than the checkpoint.
    """

    last_record_number = load_checkpoint()

    print(f"Last processed Record Number: {last_record_number}")

    handle = win32evtlog.OpenEventLog(
        None,
        "Security"
    )

    flags = (
        win32evtlog.EVENTLOG_BACKWARDS_READ
        | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    )

    new_events = []

    try:

        while len(new_events) < max_events:

            batch = win32evtlog.ReadEventLog(
                handle,
                flags,
                0
            )

            if not batch:
                break

            for event in batch:

                record_number = event.RecordNumber

                # We have reached events already processed.
                if record_number <= last_record_number:
                    return list(reversed(new_events))

                new_events.append(
                    convert_event(event)
                )

                if len(new_events) >= max_events:
                    break

    finally:
        win32evtlog.CloseEventLog(handle)

    return list(reversed(new_events))


def save_raw_events(events):
    """
    Append newly collected events to the JSONL file.
    """

    RAW_DATA_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    with OUTPUT_FILE.open(
        "a",
        encoding="utf-8"
    ) as file:

        for event in events:

            file.write(
                json.dumps(
                    event,
                    default=str
                )
                + "\n"
            )


def main():

    print("SentinelMesh Windows Security Event Ingestor")
    print("-" * 50)

    print("Checking for new Security events...")

    events = read_new_security_events(
        max_events=100
    )

    if not events:

        print("No new events found.")

        return

    save_raw_events(events)

    newest_record_number = max(
        event["record_number"]
        for event in events
    )

    save_checkpoint(
        newest_record_number
    )

    print(f"New events collected : {len(events)}")
    print(f"Latest Record Number : {newest_record_number}")
    print(f"Raw event file       : {OUTPUT_FILE}")
    print(f"Checkpoint file      : {CHECKPOINT_FILE}")
    print("Incremental ingestion successful.")


if __name__ == "__main__":
    main()