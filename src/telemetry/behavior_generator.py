import json
import uuid
from pathlib import Path
from datetime import datetime, timezone, timedelta


BASE_DIR = Path(__file__).resolve().parents[2]

CONFIG_FILE = (
    BASE_DIR
    / "config"
    / "threat_profiles.json"
)

WINDOWS_DETECTIONS_FILE = (
    BASE_DIR
    / "data"
    / "raw"
    / "detections.jsonl"
)

OUTPUT_FILE = (
    BASE_DIR
    / "data"
    / "raw"
    / "behavior_telemetry.jsonl"
)

HOST_NAME = "LAPTOP-SGNH3KHQ"


def load_threat_profiles():

    with open(
        CONFIG_FILE,
        "r",
        encoding="utf-8"
    ) as f:

        data = json.load(f)

    return data["threat_profiles"]


def load_latest_windows_detection():

    if not WINDOWS_DETECTIONS_FILE.exists():
        return None

    latest_detection = None

    with open(
        WINDOWS_DETECTIONS_FILE,
        "r",
        encoding="utf-8"
    ) as f:

        for line in f:

            line = line.strip()

            if not line:
                continue

            try:
                detection = json.loads(line)
            except json.JSONDecodeError:
                continue

            latest_detection = detection

    return latest_detection


def create_event(
    threat_profile,
    behavior_type,
    severity,
    description,
    process_name,
    timestamp
):

    return {
        "telemetry_id": str(uuid.uuid4()),

        "timestamp": timestamp.isoformat(),

        "host": HOST_NAME,

        "source": "endpoint_behavior",

        "synthetic": True,

        "threat_profile": threat_profile,

        "behavior_type": behavior_type,

        "severity": severity,

        "process_name": process_name,

        "description": description
    }


def generate_telemetry():

    threat_profiles = load_threat_profiles()

    latest_detection = load_latest_windows_detection()

    if not latest_detection:
        print(
            "No Windows detection found."
        )
        return

    base_timestamp = datetime.fromisoformat(
        latest_detection["timestamp"].replace(
            "Z",
            "+00:00"
        )
    )

    print(
        "Using latest Windows detection:"
    )

    print(
        f"  Rule ID : "
        f"{latest_detection.get('rule_id')}"
    )

    print(
        f"  Record  : "
        f"{latest_detection.get('source_record')}"
    )

    print(
        f"  Time    : "
        f"{latest_detection.get('timestamp')}"
    )

    events = [

        create_event(
            threat_profile="SocGholish",
            behavior_type="script_execution",
            severity="medium",
            description=(
                "Synthetic telemetry representing "
                "suspicious script execution."
            ),
            process_name="lab-simulator.exe",
            timestamp=base_timestamp + timedelta(
                seconds=10
            )
        ),

        create_event(
            threat_profile="Botnet",
            behavior_type="command_and_control_indicator",
            severity="high",
            description=(
                "Synthetic telemetry representing "
                "repeated command-and-control-like activity."
            ),
            process_name="lab-simulator.exe",
            timestamp=base_timestamp + timedelta(
                seconds=20
            )
        ),

        create_event(
            threat_profile="GlassWorm",
            behavior_type="browser_data_access",
            severity="high",
            description=(
                "Synthetic telemetry representing "
                "suspicious browser-data access."
            ),
            process_name="lab-simulator.exe",
            timestamp=base_timestamp + timedelta(
                seconds=30
            )
        ),

        create_event(
            threat_profile="GlassWorm",
            behavior_type="persistence_indicator",
            severity="high",
            description=(
                "Synthetic telemetry representing "
                "a persistence-related indicator."
            ),
            process_name="lab-simulator.exe",
            timestamp=base_timestamp + timedelta(
                seconds=40
            )
        ),

        create_event(
            threat_profile="LemonDuck",
            behavior_type="privilege_indicator",
            severity="high",
            description=(
                "Synthetic telemetry representing "
                "a privilege-related indicator."
            ),
            process_name="lab-simulator.exe",
            timestamp=base_timestamp + timedelta(
                seconds=50
            )
        )
    ]

    valid_profiles = set(
        threat_profiles.keys()
    )

    events = [
        event
        for event in events
        if event["threat_profile"]
        in valid_profiles
    ]

    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with open(
        OUTPUT_FILE,
        "w",
        encoding="utf-8"
    ) as f:

        for event in events:

            f.write(
                json.dumps(
                    event,
                    ensure_ascii=False
                )
                + "\n"
            )

    print(
        f"Threat profiles loaded: "
        f"{len(threat_profiles)}"
    )

    print(
        f"Telemetry events generated: "
        f"{len(events)}"
    )

    print(
        f"Telemetry host: "
        f"{HOST_NAME}"
    )

    print(
        f"Base timestamp: "
        f"{base_timestamp.isoformat()}"
    )

    print(
        f"Output file: "
        f"{OUTPUT_FILE}"
    )

    print(
        "Controlled correlation telemetry generated."
    )


if __name__ == "__main__":
    generate_telemetry()