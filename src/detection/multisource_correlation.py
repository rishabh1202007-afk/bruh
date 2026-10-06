import json
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parents[2]

INPUT_FILE = BASE_DIR / "data" / "raw" / "multisource_incidents.jsonl"
OUTPUT_FILE = BASE_DIR / "data" / "raw" / "enriched_multisource_incidents.jsonl"


def load_jsonl(file_path):
    records = []

    if not file_path.exists():
        return records

    with file_path.open("r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()

            if not line:
                continue

            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    return records


def build_enriched_incident(incident):
    evidence = incident.get("evidence", [])

    windows_evidence = []
    behavior_evidence = []

    for item in evidence:
        source = item.get("source")

        if source == "windows_detection":
            windows_evidence.append(item)

        elif source == "behavior_detection":
            behavior_evidence.append(item)

    observed_behaviors = []

    for item in behavior_evidence:
        behavior_type = item.get("behavior_type")

        if behavior_type and behavior_type not in observed_behaviors:
            observed_behaviors.append(behavior_type)

    threat_profile = incident.get("threat_profile", "Unknown")

    evidence_sources = []

    if windows_evidence:
        evidence_sources.append("windows_security")

    if behavior_evidence:
        evidence_sources.append("behavior_telemetry")

    enriched = dict(incident)

    enriched["enrichment"] = {
        "threat_profile_context": (
            f"Telemetry shows behavioral alignment with the "
            f"{threat_profile} profile used in the SentinelMesh lab."
        ),
        "observed_behaviors": observed_behaviors,
        "evidence_source_count": len(evidence_sources),
        "evidence_sources": evidence_sources,
        "windows_evidence_count": len(windows_evidence),
        "behavior_evidence_count": len(behavior_evidence),
        "synthetic_evidence": True,
        "attribution_status": "behavioral_profile_match_only",
        "analyst_interpretation": (
            "Windows Security telemetry and synthetic behavior telemetry "
            "were observed on the same host within the configured "
            "correlation window. This indicates correlated suspicious "
            "activity, but does not by itself confirm malware infection "
            "or attribution to a specific malware family."
        ),
        "recommended_investigation": [
            "Review the correlated Windows Security events.",
            "Review the associated behavior telemetry.",
            "Inspect the process and network context associated with the event.",
            "Check for additional related activity on the same host.",
            "Validate the threat-profile match using additional evidence "
            "before assigning malware attribution."
        ]
    }

    return enriched


def main():
    incidents = load_jsonl(INPUT_FILE)

    if not incidents:
        print("No multi-source incidents found.")
        return

    enriched_incidents = []

    for incident in incidents:
        enriched_incidents.append(
            build_enriched_incident(incident)
        )

    with OUTPUT_FILE.open("w", encoding="utf-8") as file:
        for incident in enriched_incidents:
            file.write(
                json.dumps(
                    incident,
                    ensure_ascii=False
                ) + "\n"
            )

    print(f"Incidents loaded: {len(incidents)}")
    print(f"Enriched incidents: {len(enriched_incidents)}")
    print(f"Output file: {OUTPUT_FILE}")
    print("Multi-source incident enrichment completed.")


if __name__ == "__main__":
    main()