import json
from pathlib import Path
from datetime import datetime

BASE_DIR = Path(__file__).resolve().parents[2]

INPUT_FILE = BASE_DIR / "data" / "raw" / "detections.jsonl"
OUTPUT_FILE = BASE_DIR / "data" / "raw" / "correlated_incidents.jsonl"
CHECKPOINT_FILE = BASE_DIR / "data" / "raw" / "correlation_checkpoint.json"

CORRELATION_WINDOW_SECONDS = 300  # 5 minutes


def parse_timestamp(timestamp):
    if not timestamp:
        return None

    try:
        return datetime.fromisoformat(
            timestamp.replace("Z", "+00:00")
        )
    except ValueError:
        return None


def load_checkpoint():
    if not CHECKPOINT_FILE.exists():
        return 0

    try:
        with open(CHECKPOINT_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data.get("last_record_number", 0)
    except (json.JSONDecodeError, OSError):
        return 0


def save_checkpoint(record_number):
    with open(CHECKPOINT_FILE, "w", encoding="utf-8") as f:
        json.dump(
            {"last_record_number": record_number},
            f,
            indent=2
        )


def load_detections():
    if not INPUT_FILE.exists():
        return []

    detections = []

    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()

            if not line:
                continue

            try:
                detections.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    return detections


def create_incident(discovery_event, credential_event):
    discovery_time = parse_timestamp(
        discovery_event.get("timestamp")
    )

    credential_time = parse_timestamp(
        credential_event.get("timestamp")
    )

    if not discovery_time or not credential_time:
        return None

    if credential_time < discovery_time:
        return None

    time_difference = (
        credential_time - discovery_time
    ).total_seconds()

    if time_difference > CORRELATION_WINDOW_SECONDS:
        return None

    if discovery_event.get("host") != credential_event.get("host"):
        return None

    discovery_record = discovery_event.get("source_record")
    credential_record = credential_event.get("source_record")

    return {
        "incident_id": f"INC-{discovery_record}-{credential_record}",
        "timestamp": credential_event.get("timestamp"),
        "host": credential_event.get("host"),
        "severity": "high",
        "incident_type": "correlated_suspicious_activity",
        "correlation_rule": "CM-001",
        "rule_name": (
            "Account Discovery followed by "
            "Credential Manager Activity"
        ),
        "events": [
            {
                "rule_id": discovery_event.get("rule_id"),
                "rule_name": discovery_event.get("rule_name"),
                "source_record": discovery_record
            },
            {
                "rule_id": credential_event.get("rule_id"),
                "rule_name": credential_event.get("rule_name"),
                "source_record": credential_record
            }
        ],
        "time_window_seconds": int(time_difference),
        "status": "new"
    }


def run_correlation():

    detections = load_detections()

    print(f"Total detections loaded: {len(detections)}")

    if not detections:
        print("No detections available.")
        return

    detections.sort(
        key=lambda event: event.get("timestamp", "")
    )

    discovery_events = [
        event
        for event in detections
        if event.get("rule_id") == "SM-002"
    ]

    credential_events = [
        event
        for event in detections
        if event.get("rule_id") == "SM-003"
    ]

    print(f"SM-002 discovery events : {len(discovery_events)}")
    print(f"SM-003 credential events: {len(credential_events)}")

    incidents = []

    used_discovery_records = set()
    used_credential_records = set()

    for credential_event in credential_events:

        credential_time = parse_timestamp(
            credential_event.get("timestamp")
        )

        if not credential_time:
            continue

        best_match = None
        best_difference = None

        for discovery_event in discovery_events:

            discovery_record = discovery_event.get(
                "source_record"
            )

            credential_record = credential_event.get(
                "source_record"
            )

            if discovery_record in used_discovery_records:
                continue

            if credential_record in used_credential_records:
                continue

            if discovery_event.get("host") != credential_event.get(
                "host"
            ):
                continue

            discovery_time = parse_timestamp(
                discovery_event.get("timestamp")
            )

            if not discovery_time:
                continue

            if credential_time < discovery_time:
                continue

            difference = (
                credential_time - discovery_time
            ).total_seconds()

            if difference > CORRELATION_WINDOW_SECONDS:
                continue

            if best_difference is None or difference < best_difference:
                best_match = discovery_event
                best_difference = difference

        if best_match:

            incident = create_incident(
                best_match,
                credential_event
            )

            if incident:
                incidents.append(incident)

                used_discovery_records.add(
                    best_match.get("source_record")
                )

                used_credential_records.add(
                    credential_event.get("source_record")
                )

    # Rebuild the correlation output cleanly.
    if OUTPUT_FILE.exists():
        OUTPUT_FILE.unlink()

    if incidents:
        OUTPUT_FILE.parent.mkdir(
            parents=True,
            exist_ok=True
        )

        with open(
            OUTPUT_FILE,
            "w",
            encoding="utf-8"
        ) as f:

            for incident in incidents:
                f.write(
                    json.dumps(
                        incident,
                        ensure_ascii=False
                    ) + "\n"
                )

    latest_record_number = max(
        event.get("source_record", 0)
        for event in detections
    )

    save_checkpoint(latest_record_number)

    print(f"Correlated incidents    : {len(incidents)}")
    print(f"Latest Record Number    : {latest_record_number}")
    print("Correlation refinement completed.")


if __name__ == "__main__":
    run_correlation()