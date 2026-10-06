import json
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]

RAW_DATA_DIR = PROJECT_ROOT / "data" / "raw"

INPUT_FILE = RAW_DATA_DIR / "enriched_events.jsonl"
OUTPUT_FILE = RAW_DATA_DIR / "classified_events.jsonl"


EVENT_CATEGORIES = {
    4624: "authentication",
    4672: "privilege",
    4798: "account_discovery",
    5379: "credential_access",
}


def classify_event(event):
    """
    Assign a broad security category to an enriched event.
    """

    event_id = event.get("event_id")

    classified = event.copy()

    classified["category"] = EVENT_CATEGORIES.get(
        event_id,
        "other"
    )

    return classified


def classify_events():

    if not INPUT_FILE.exists():
        print("Enriched event file not found.")
        return

    count = 0

    with INPUT_FILE.open(
        "r",
        encoding="utf-8"
    ) as input_file, OUTPUT_FILE.open(
        "w",
        encoding="utf-8"
    ) as output_file:

        for line in input_file:

            if not line.strip():
                continue

            event = json.loads(line)

            classified_event = classify_event(
                event
            )

            output_file.write(
                json.dumps(
                    classified_event,
                    default=str
                )
                + "\n"
            )

            count += 1

    print(f"Events classified : {count}")
    print(f"Output file       : {OUTPUT_FILE}")
    print("Event classification successful.")


if __name__ == "__main__":
    classify_events()