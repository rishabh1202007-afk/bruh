import json
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parents[2]

INPUT_FILE = (
    BASE_DIR
    / "data"
    / "raw"
    / "mitre_enriched_multisource_incidents.jsonl"
)

OUTPUT_FILE = (
    BASE_DIR
    / "data"
    / "raw"
    / "final_risk_scored_incidents.jsonl"
)

THREAT_PROFILE_FILE = (
    BASE_DIR
    / "config"
    / "threat_profiles.json"
)


# =========================================================
# SCORE LIMITS
# =========================================================

MAX_SCORES = {
    "detection_severity": 15,
    "behavioral_evidence": 15,
    "correlation_strength": 15,
    "mitre_context": 15,
    "threat_profile_alignment": 10,
    "persistence_privilege": 10,
    "network_activity": 10,
    "repetition": 10
}


SEVERITY_SCORES = {
    "critical": 15,
    "high": 12,
    "medium": 8,
    "low": 4,
    "info": 1
}


# =========================================================
# FILE LOADERS
# =========================================================

def load_jsonl(file_path):

    records = []

    if not file_path.exists():
        return records

    with file_path.open(
        "r",
        encoding="utf-8"
    ) as file:

        for line in file:

            line = line.strip()

            if not line:
                continue

            try:
                records.append(
                    json.loads(line)
                )

            except json.JSONDecodeError:
                continue

    return records


def load_threat_profiles():

    if not THREAT_PROFILE_FILE.exists():
        return {}

    try:

        with THREAT_PROFILE_FILE.open(
            "r",
            encoding="utf-8"
        ) as file:

            data = json.load(file)

        return data.get(
            "threat_profiles",
            {}
        )

    except (
        json.JSONDecodeError,
        OSError
    ):

        return {}


# =========================================================
# 1. DETECTION SEVERITY
# =========================================================

def score_detection_severity(incident):

    severity = str(
        incident.get(
            "severity",
            "low"
        )
    ).lower()

    score = min(
        SEVERITY_SCORES.get(
            severity,
            1
        ),
        MAX_SCORES[
            "detection_severity"
        ]
    )

    evidence = [
        f"Incident severity: {severity.upper()}",
        (
            f"Correlation rule: "
            f"{incident.get('correlation_rule', 'N/A')}"
        ),
        (
            f"Detection rule: "
            f"{incident.get('rule_name', 'N/A')}"
        )
    ]

    reason = (
        f"The incident severity is {severity.upper()}, "
        f"which contributes {score} points out of "
        f"{MAX_SCORES['detection_severity']}."
    )

    return score, evidence, reason


# =========================================================
# 2. BEHAVIORAL EVIDENCE
# =========================================================

def score_behavioral_evidence(incident):

    enrichment = incident.get(
        "enrichment",
        {}
    )

    behaviors = enrichment.get(
        "observed_behaviors",
        []
    )

    behavior_count = len(
        behaviors
    )

    if behavior_count >= 4:
        score = 15

    elif behavior_count == 3:
        score = 12

    elif behavior_count == 2:
        score = 9

    elif behavior_count == 1:
        score = 6

    else:
        score = 0

    evidence = []

    for behavior in behaviors:

        evidence.append(
            f"Observed behavior: {behavior}"
        )

    behavior_evidence_count = enrichment.get(
        "behavior_evidence_count",
        0
    )

    evidence.append(
        f"Behavior evidence records: "
        f"{behavior_evidence_count}"
    )

    if behaviors:

        reason = (
            f"{behavior_count} distinct behavioral "
            f"indicator(s) were observed, contributing "
            f"{score} points out of "
            f"{MAX_SCORES['behavioral_evidence']}."
        )

    else:

        reason = (
            "No behavioral indicators were available "
            "for this incident."
        )

    return score, evidence, reason


# =========================================================
# 3. CORRELATION STRENGTH
# =========================================================

def score_correlation_strength(incident):

    enrichment = incident.get(
        "enrichment",
        {}
    )

    source_count = enrichment.get(
        "evidence_source_count",
        0
    )

    evidence_sources = enrichment.get(
        "evidence_sources",
        []
    )

    time_window = incident.get(
        "time_window_seconds"
    )

    if source_count >= 2:
        score = 15

    elif source_count == 1:
        score = 7

    else:
        score = 0

    evidence = [
        (
            f"Evidence sources: "
            f"{', '.join(evidence_sources)}"
            if evidence_sources
            else "Evidence sources: none"
        ),
        f"Evidence source count: {source_count}",
        (
            f"Correlation window: "
            f"{time_window} seconds"
            if time_window is not None
            else "Correlation window: N/A"
        )
    ]

    if source_count >= 2:

        reason = (
            "Multiple telemetry sources corroborate "
            "the same incident, providing strong "
            f"correlation evidence. Score: {score}/"
            f"{MAX_SCORES['correlation_strength']}."
        )

    elif source_count == 1:

        reason = (
            "Only one telemetry source supports the "
            "incident, resulting in partial correlation "
            f"evidence. Score: {score}/"
            f"{MAX_SCORES['correlation_strength']}."
        )

    else:

        reason = (
            "No supporting telemetry sources were "
            "identified."
        )

    return score, evidence, reason


# =========================================================
# 4. MITRE ATT&CK CONTEXT
# =========================================================

def score_mitre_context(incident):

    mitre_context = incident.get(
        "mitre_context",
        {}
    )

    techniques = mitre_context.get(
        "combined_techniques",
        []
    )

    technique_count = len(
        techniques
    )

    if technique_count >= 4:
        score = 15

    elif technique_count == 3:
        score = 12

    elif technique_count == 2:
        score = 9

    elif technique_count == 1:
        score = 6

    else:
        score = 0

    evidence = []

    for technique in techniques:

        evidence.append(
            (
                f"{technique.get('technique_id')} - "
                f"{technique.get('technique_name')} "
                f"({technique.get('tactic')})"
            )
        )

    tactics = mitre_context.get(
        "tactics_observed",
        []
    )

    if tactics:

        evidence.append(
            f"ATT&CK tactics: {', '.join(tactics)}"
        )

    if technique_count:

        reason = (
            f"{technique_count} ATT&CK technique(s) "
            f"are represented by the observed telemetry, "
            f"contributing {score} points out of "
            f"{MAX_SCORES['mitre_context']}."
        )

    else:

        reason = (
            "No ATT&CK techniques were mapped to the "
            "available evidence."
        )

    return score, evidence, reason


# =========================================================
# 5. THREAT PROFILE ALIGNMENT
# =========================================================

def score_threat_profile(
    incident,
    threat_profiles
):

    threat_profile = incident.get(
        "threat_profile"
    )

    enrichment = incident.get(
        "enrichment",
        {}
    )

    observed_behaviors = set(
        enrichment.get(
            "observed_behaviors",
            []
        )
    )

    evidence = []

    if (
        not threat_profile
        or threat_profile == "Unknown"
    ):

        return (
            0,
            ["No configured threat profile."],
            "No threat-profile alignment was available."
        )

    profile = threat_profiles.get(
        threat_profile
    )

    if not profile:

        return (
            0,
            [
                f"Threat profile '{threat_profile}' "
                "is not present in threat_profiles.json."
            ],
            (
                "The incident references a threat profile, "
                "but that profile is not configured."
            )
        )

    configured_behaviors = set(
        profile.get(
            "behaviors",
            []
        )
    )

    matching_behaviors = sorted(
        observed_behaviors.intersection(
            configured_behaviors
        )
    )

    unmatched_behaviors = sorted(
        observed_behaviors.difference(
            configured_behaviors
        )
    )

    evidence.append(
        f"Threat profile: {threat_profile}"
    )

    evidence.append(
        "Configured profile behaviors: "
        + (
            ", ".join(
                sorted(configured_behaviors)
            )
            if configured_behaviors
            else "none"
        )
    )

    evidence.append(
        "Observed behaviors: "
        + (
            ", ".join(
                sorted(observed_behaviors)
            )
            if observed_behaviors
            else "none"
        )
    )

    evidence.append(
        "Matching behaviors: "
        + (
            ", ".join(
                matching_behaviors
            )
            if matching_behaviors
            else "none"
        )
    )

    if unmatched_behaviors:

        evidence.append(
            "Observed behaviors without profile match: "
            + ", ".join(
                unmatched_behaviors
            )
        )

    match_count = len(
        matching_behaviors
    )

    observed_count = len(
        observed_behaviors
    )

    profile_count = len(
        configured_behaviors
    )

    # -----------------------------------------------------
    # Evidence-based scoring
    #
    # 10 = all observed behaviors match the profile
    #  7 = majority of observed behaviors match
    #  4 = partial match
    #  0 = no match
    # -----------------------------------------------------

    if (
        match_count > 0
        and observed_count > 0
        and match_count == observed_count
    ):

        score = 10

        reason = (
            f"All {match_count} observed behavior(s) "
            f"match the configured {threat_profile} "
            "behavioral profile. "
            f"Score: {score}/10."
        )

    elif (
        match_count > 0
        and observed_count > 0
        and (
            match_count / observed_count
        ) >= 0.5
    ):

        score = 7

        reason = (
            f"{match_count} of {observed_count} "
            f"observed behavior(s) match the configured "
            f"{threat_profile} profile. "
            f"Score: {score}/10."
        )

    elif match_count > 0:

        score = 4

        reason = (
            f"Partial behavioral alignment was observed "
            f"with the {threat_profile} profile. "
            f"Score: {score}/10."
        )

    else:

        score = 0

        reason = (
            f"No observed behavior matches the configured "
            f"{threat_profile} behavioral profile. "
            "Score: 0/10."
        )

    evidence.append(
        f"Profile behavior count: {profile_count}"
    )

    evidence.append(
        f"Matched behavior count: {match_count}"
    )

    evidence.append(
        "Profile status: "
        "behavioral_profile_match_only"
    )

    evidence.append(
        "This is contextual profile alignment, "
        "not confirmed malware attribution."
    )

    return score, evidence, reason


# =========================================================
# 6. PERSISTENCE / PRIVILEGE
# =========================================================

def score_persistence_privilege(incident):

    enrichment = incident.get(
        "enrichment",
        {}
    )

    behaviors = enrichment.get(
        "observed_behaviors",
        []
    )

    score = 0

    evidence = []

    if "persistence_indicator" in behaviors:

        score += 6

        evidence.append(
            "Persistence indicator observed."
        )

    if "privilege_indicator" in behaviors:

        score += 6

        evidence.append(
            "Privilege indicator observed."
        )

    score = min(
        score,
        MAX_SCORES[
            "persistence_privilege"
        ]
    )

    if evidence:

        reason = (
            "Persistence and/or privilege-related "
            "behavior contributed "
            f"{score} points out of "
            f"{MAX_SCORES['persistence_privilege']}."
        )

    else:

        evidence.append(
            "No persistence or privilege indicator."
        )

        reason = (
            "No persistence or privilege-related "
            "behavior was observed."
        )

    return score, evidence, reason


# =========================================================
# 7. NETWORK ACTIVITY
# =========================================================

def score_network_activity(incident):

    enrichment = incident.get(
        "enrichment",
        {}
    )

    behaviors = enrichment.get(
        "observed_behaviors",
        []
    )

    network_behaviors = {
        "network_activity",
        "repeated_outbound_connections",
        "command_and_control_indicator",
        "periodic_network_activity"
    }

    matching_behaviors = [
        behavior
        for behavior in behaviors
        if behavior in network_behaviors
    ]

    if len(matching_behaviors) >= 2:
        score = 10

    elif len(matching_behaviors) == 1:
        score = 7

    else:
        score = 0

    evidence = []

    for behavior in matching_behaviors:

        evidence.append(
            f"Network behavior: {behavior}"
        )

    if matching_behaviors:

        reason = (
            f"{len(matching_behaviors)} network-related "
            f"behavior indicator(s) contributed "
            f"{score} points out of "
            f"{MAX_SCORES['network_activity']}."
        )

    else:

        evidence.append(
            "No network-related behavior observed."
        )

        reason = (
            "No network activity indicator was "
            "associated with this incident."
        )

    return score, evidence, reason


# =========================================================
# 8. REPETITION / FREQUENCY
# =========================================================

def score_repetition(incident):

    enrichment = incident.get(
        "enrichment",
        {}
    )

    behavior_count = enrichment.get(
        "behavior_evidence_count",
        0
    )

    windows_count = enrichment.get(
        "windows_evidence_count",
        0
    )

    total_evidence = (
        behavior_count +
        windows_count
    )

    if total_evidence >= 6:
        score = 10

    elif total_evidence >= 4:
        score = 8

    elif total_evidence >= 3:
        score = 6

    elif total_evidence >= 2:
        score = 4

    elif total_evidence == 1:
        score = 2

    else:
        score = 0

    evidence = [
        f"Windows evidence records: {windows_count}",
        f"Behavior evidence records: {behavior_count}",
        (
            f"Total supporting evidence records: "
            f"{total_evidence}"
        )
    ]

    reason = (
        f"The incident contains {total_evidence} "
        "supporting evidence record(s), contributing "
        f"{score} points out of "
        f"{MAX_SCORES['repetition']}."
    )

    return score, evidence, reason


# =========================================================
# RISK LEVEL
# =========================================================

def determine_risk_level(total_score):

    if total_score >= 80:
        return "critical"

    if total_score >= 60:
        return "high"

    if total_score >= 40:
        return "medium"

    return "low"


# =========================================================
# SCORE COMPLETE INCIDENT
# =========================================================

def score_incident(
    incident,
    threat_profiles
):

    factor_details = {}

    score, evidence, reason = (
        score_detection_severity(
            incident
        )
    )

    factor_details[
        "detection_severity"
    ] = {
        "score": score,
        "maximum": 15,
        "evidence": evidence,
        "reason": reason
    }

    score, evidence, reason = (
        score_behavioral_evidence(
            incident
        )
    )

    factor_details[
        "behavioral_evidence"
    ] = {
        "score": score,
        "maximum": 15,
        "evidence": evidence,
        "reason": reason
    }

    score, evidence, reason = (
        score_correlation_strength(
            incident
        )
    )

    factor_details[
        "correlation_strength"
    ] = {
        "score": score,
        "maximum": 15,
        "evidence": evidence,
        "reason": reason
    }

    score, evidence, reason = (
        score_mitre_context(
            incident
        )
    )

    factor_details[
        "mitre_context"
    ] = {
        "score": score,
        "maximum": 15,
        "evidence": evidence,
        "reason": reason
    }

    score, evidence, reason = (
        score_threat_profile(
            incident,
            threat_profiles
        )
    )

    factor_details[
        "threat_profile_alignment"
    ] = {
        "score": score,
        "maximum": 10,
        "evidence": evidence,
        "reason": reason
    }

    score, evidence, reason = (
        score_persistence_privilege(
            incident
        )
    )

    factor_details[
        "persistence_privilege"
    ] = {
        "score": score,
        "maximum": 10,
        "evidence": evidence,
        "reason": reason
    }

    score, evidence, reason = (
        score_network_activity(
            incident
        )
    )

    factor_details[
        "network_activity"
    ] = {
        "score": score,
        "maximum": 10,
        "evidence": evidence,
        "reason": reason
    }

    score, evidence, reason = (
        score_repetition(
            incident
        )
    )

    factor_details[
        "repetition"
    ] = {
        "score": score,
        "maximum": 10,
        "evidence": evidence,
        "reason": reason
    }

    # -----------------------------------------------------
    # Calculate total
    # -----------------------------------------------------

    total_score = sum(
        item["score"]
        for item in factor_details.values()
    )

    risk_level = determine_risk_level(
        total_score
    )

    scores = {
        factor: details["score"]
        for factor, details
        in factor_details.items()
    }

    scored_incident = dict(
        incident
    )

    scored_incident[
        "risk_scoring"
    ] = {

        "model_version":
            "SentinelMesh-Risk-v3",

        "scores":
            scores,

        "factor_details":
            factor_details,

        "maximum_score":
            100,

        "total_score":
            total_score,

        "risk_level":
            risk_level,

        "explanation":
            (
                "Risk score is calculated from detection "
                "severity, behavioral evidence, multi-source "
                "correlation, MITRE ATT&CK context, "
                "evidence-based threat-profile alignment, "
                "persistence or privilege indicators, "
                "network activity, and repetition. Each "
                "factor includes the evidence and reasoning "
                "used to calculate its score."
            )
    }

    return scored_incident


# =========================================================
# MAIN
# =========================================================

def main():

    incidents = load_jsonl(
        INPUT_FILE
    )

    if not incidents:

        print(
            "No MITRE-enriched multi-source incidents found."
        )

        return

    threat_profiles = load_threat_profiles()

    print(
        f"Threat profiles loaded: "
        f"{len(threat_profiles)}"
    )

    scored_incidents = []

    for incident in incidents:

        scored_incidents.append(
            score_incident(
                incident,
                threat_profiles
            )
        )

    with OUTPUT_FILE.open(
        "w",
        encoding="utf-8"
    ) as file:

        for incident in scored_incidents:

            file.write(
                json.dumps(
                    incident,
                    ensure_ascii=False
                ) + "\n"
            )

    print(
        f"Incidents loaded: "
        f"{len(incidents)}"
    )

    print(
        f"Risk-scored incidents: "
        f"{len(scored_incidents)}"
    )

    print(
        f"Output file: {OUTPUT_FILE}"
    )

    print(
        "Final SentinelMesh risk scoring completed."
    )

    print()
    print(
        "Risk score summary:"
    )

    for incident in scored_incidents:

        risk = incident.get(
            "risk_scoring",
            {}
        )

        print(
            f"  {incident.get('incident_id', 'unknown')} "
            f"-> {risk.get('total_score', 0)}/100 "
            f"({risk.get('risk_level', 'unknown')})"
        )


if __name__ == "__main__":
    main()