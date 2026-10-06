import json
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[2]

INPUT_FILE = BASE_DIR / "data" / "raw" / "correlated_incidents.jsonl"
OUTPUT_FILE = BASE_DIR / "data" / "raw" / "enriched_incidents.jsonl"


def load_incidents():
    if not INPUT_FILE.exists():
        return []

    incidents = []

    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()

            if not line:
                continue

            try:
                incidents.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    return incidents


def enrich_incident(incident):
    events = incident.get("events", [])

    observed_behaviors = []

    for event in events:
        rule_id = event.get("rule_id")

        if rule_id == "SM-002":
            observed_behaviors.append(
                "User account enumeration"
            )

        elif rule_id == "SM-003":
            observed_behaviors.append(
                "Credential Manager activity"
            )

    enriched = dict(incident)

    enriched["summary"] = (
        "Account discovery activity was followed by "
        "Credential Manager activity on the same host "
        "within the configured correlation window."
    )

    enriched["observed_behaviors"] = observed_behaviors

    enriched["analyst_context"] = {
        "why_correlated": (
            "Multiple security detections occurred in sequence "
            "on the same host within five minutes."
        ),
        "interpretation": (
            "This is a correlation signal requiring investigation; "
            "it does not by itself confirm malicious activity."
        )
    }

    enriched["recommended_investigation"] = [
        "Review the involved user and process context.",
        "Review surrounding Windows Security events.",
        "Check whether the activity matches expected administrative behavior.",
        "Correlate with additional host or network telemetry if available."
    ]

    return enriched


def run_enrichment():
    incidents = load_incidents()

    print(f"Incidents loaded: {len(incidents)}")

    if not incidents:
        print("No correlated incidents found.")
        return

    enriched_incidents = []

    for incident in incidents:
        enriched_incidents.append(
            enrich_incident(incident)
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

        for incident in enriched_incidents:
            f.write(
                json.dumps(
                    incident,
                    ensure_ascii=False
                ) + "\n"
            )

    print(
        f"Enriched incidents: "
        f"{len(enriched_incidents)}"
    )

    print(
        f"Output file: "
        f"{OUTPUT_FILE}"
    )

    print("Incident enrichment completed.")


if __name__ == "__main__":
    run_enrichment()