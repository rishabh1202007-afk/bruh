import json
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parents[2]

INPUT_FILE = (
    BASE_DIR
    / "data"
    / "raw"
    / "mitre_mapped_incidents.jsonl"
)

OUTPUT_FILE = (
    BASE_DIR
    / "data"
    / "raw"
    / "risk_scored_incidents.jsonl"
)


SEVERITY_SCORES = {
    "low": 10,
    "medium": 25,
    "high": 40,
    "critical": 40
}


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


def calculate_risk_score(incident):

    # -------------------------
    # 1. Severity component
    # -------------------------

    severity = incident.get(
        "severity",
        "low"
    ).lower()

    severity_score = SEVERITY_SCORES.get(
        severity,
        10
    )

    # -------------------------
    # 2. Behavior component
    # -------------------------

    behaviors = incident.get(
        "observed_behaviors",
        []
    )

    behavior_count = len(behaviors)

    # 10 points per behavior
    # Maximum 20

    behavior_score = min(
        behavior_count * 10,
        20
    )

    # -------------------------
    # 3. MITRE component
    # -------------------------

    mitre_techniques = incident.get(
        "mitre_attack",
        []
    )

    technique_count = len(
        mitre_techniques
    )

    # 20 points per mapped technique
    # Maximum 40

    mitre_score = min(
        technique_count * 20,
        40
    )

    # -------------------------
    # Final score
    # -------------------------

    total_score = (
        severity_score
        + behavior_score
        + mitre_score
    )

    total_score = min(
        total_score,
        100
    )

    return {
        "total": total_score,
        "severity_component": severity_score,
        "behavior_component": behavior_score,
        "mitre_component": mitre_score
    }


def get_risk_level(score):

    if score >= 80:
        return "critical"

    elif score >= 60:
        return "high"

    elif score >= 40:
        return "medium"

    else:
        return "low"


def score_incident(incident):

    score_details = calculate_risk_score(
        incident
    )

    enriched = dict(incident)

    enriched["risk_score"] = (
        score_details["total"]
    )

    enriched["risk_level"] = get_risk_level(
        score_details["total"]
    )

    enriched["risk_breakdown"] = {
        "severity": (
            score_details[
                "severity_component"
            ]
        ),
        "behaviors": (
            score_details[
                "behavior_component"
            ]
        ),
        "mitre_attack": (
            score_details[
                "mitre_component"
            ]
        )
    }

    return enriched


def run_risk_scoring():

    incidents = load_incidents()

    print(
        f"Incidents loaded: "
        f"{len(incidents)}"
    )

    if not incidents:
        print(
            "No MITRE-mapped incidents found."
        )
        return

    scored_incidents = []

    for incident in incidents:

        scored_incidents.append(
            score_incident(incident)
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

        for incident in scored_incidents:

            f.write(
                json.dumps(
                    incident,
                    ensure_ascii=False
                )
                + "\n"
            )

    print(
        f"Risk-scored incidents: "
        f"{len(scored_incidents)}"
    )

    print(
        f"Output file: "
        f"{OUTPUT_FILE}"
    )

    print(
        "Incident risk scoring completed."
    )


if __name__ == "__main__":
    run_risk_scoring()