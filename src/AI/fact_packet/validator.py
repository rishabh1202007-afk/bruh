from typing import Any, Dict, List


REQUIRED_PACKET_SECTIONS = [
    "incident",
    "correlation",
    "timeline",
    "events",
    "detections",
    "behaviors",
    "entities",
    "mitre",
    "threat_profiles",
    "risk",
    "evidence",
    "known_facts",
    "uncertainties",
    "evidence_gaps",
]


def validate_fact_packet(
    fact_packet: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Validate a SentinelMesh Fact Packet before it is consumed
    by the AI or Incident Intelligence Graph.

    Validation is deterministic.
    No AI inference is performed here.
    """

    errors: List[str] = []
    warnings: List[str] = []

    if not isinstance(fact_packet, dict):
        return {
            "valid": False,
            "errors": ["Fact Packet must be a dictionary."],
            "warnings": [],
        }

    # ---------------------------------------------------------
    # 1. REQUIRED TOP-LEVEL SECTIONS
    # ---------------------------------------------------------

    for section in REQUIRED_PACKET_SECTIONS:
        if section not in fact_packet:
            errors.append(
                f"Missing required section: {section}"
            )

    # ---------------------------------------------------------
    # 2. INCIDENT
    # ---------------------------------------------------------

    incident = fact_packet.get("incident", {})

    if not isinstance(incident, dict):
        errors.append("incident must be a dictionary.")
    else:
        if not incident.get("incident_id"):
            errors.append(
                "incident.incident_id is required."
            )

        if not incident.get("host"):
            warnings.append(
                "Incident does not contain a host."
            )

        if not incident.get("timestamp"):
            warnings.append(
                "Incident does not contain a timestamp."
            )

    # ---------------------------------------------------------
    # 3. CORRELATION
    # ---------------------------------------------------------

    correlation = fact_packet.get("correlation", {})

    if not isinstance(correlation, dict):
        errors.append(
            "correlation must be a dictionary."
        )
    else:
        if not correlation.get("rule_id"):
            warnings.append(
                "No correlation rule is present."
            )

        # Current SentinelMesh schema uses this field.
        if (
            "time_window_seconds" not in correlation
            and correlation.get("rule_id")
        ):
            warnings.append(
                "Correlation rule exists but "
                "time_window_seconds is missing."
            )

    # ---------------------------------------------------------
    # 4. COLLECTION TYPES
    # ---------------------------------------------------------

    collection_sections = [
        "timeline",
        "events",
        "detections",
        "behaviors",
        "behavior_detections",
        "threat_profiles",
        "evidence",
        "known_facts",
        "uncertainties",
        "evidence_gaps",
    ]

    for section in collection_sections:
        value = fact_packet.get(section)

        if value is not None and not isinstance(value, list):
            errors.append(
                f"{section} must be a list."
            )

    # ---------------------------------------------------------
    # 5. DETECTION VALIDATION
    # ---------------------------------------------------------

    for index, detection in enumerate(
        fact_packet.get("detections", [])
    ):
        if not isinstance(detection, dict):
            errors.append(
                f"detections[{index}] must be a dictionary."
            )
            continue

        if not (
            detection.get("detection_id")
            or detection.get("rule_id")
        ):
            warnings.append(
                f"detections[{index}] has no detection_id "
                "or rule_id."
            )

    # ---------------------------------------------------------
    # 6. BEHAVIOR TELEMETRY VALIDATION
    # ---------------------------------------------------------

    for index, behavior in enumerate(
        fact_packet.get("behaviors", [])
    ):
        if not isinstance(behavior, dict):
            errors.append(
                f"behaviors[{index}] must be a dictionary."
            )
            continue

        if not behavior.get("telemetry_id"):
            warnings.append(
                f"behaviors[{index}] has no telemetry_id."
            )

        # SentinelMesh synthetic behavior MUST remain explicitly
        # marked as synthetic.
        if behavior.get("source") == "endpoint_behavior":
            if behavior.get("synthetic") is not True:
                errors.append(
                    f"behaviors[{index}] endpoint behavior "
                    "must explicitly contain synthetic=true."
                )

    # ---------------------------------------------------------
    # 6B. BEHAVIOR DETECTION VALIDATION
    # ---------------------------------------------------------

    for index, detection in enumerate(
        fact_packet.get("behavior_detections", [])
    ):
        if not isinstance(detection, dict):
            errors.append(
                f"behavior_detections[{index}] "
                "must be a dictionary."
            )
            continue

        if not detection.get("detection_id"):
            errors.append(
                f"behavior_detections[{index}] "
                "is missing detection_id."
            )

        if not detection.get("rule_id"):
            warnings.append(
                f"behavior_detections[{index}] "
                "has no rule_id."
            )

        if not detection.get("source_telemetry"):
            warnings.append(
                f"behavior_detections[{index}] "
                "has no source_telemetry reference."
            )

    # ---------------------------------------------------------
    # 7. MITRE VALIDATION
    # ---------------------------------------------------------

    mitre = fact_packet.get(
        "mitre",
        {},
    )

    if not isinstance(mitre, dict):
        errors.append(
            "mitre must be a dictionary using the "
            "canonical MITRE context schema."
        )
        mitre = {}

    mitre_list_sections = [
        "windows_techniques",
        "behavior_techniques",
        "combined_techniques",
        "tactics_observed",
    ]

    for section in mitre_list_sections:
        value = mitre.get(section)

        if value is not None and not isinstance(value, list):
            errors.append(
                f"mitre.{section} must be a list."
            )

    techniques = (
        mitre.get("combined_techniques")
        if isinstance(mitre.get("combined_techniques"), list)
        else []
    )

    for index, technique in enumerate(techniques):
        if not isinstance(technique, dict):
            errors.append(
                "mitre.combined_techniques"
                f"[{index}] must be a dictionary."
            )
            continue

        if not technique.get("technique_id"):
            errors.append(
                "mitre.combined_techniques"
                f"[{index}] is missing technique_id."
            )

    # ---------------------------------------------------------
    # 8. THREAT PROFILE VALIDATION
    # ---------------------------------------------------------

    for index, profile in enumerate(
        fact_packet.get("threat_profiles", [])
    ):
        if isinstance(profile, str):
            continue

        if not isinstance(profile, dict):
            errors.append(
                f"threat_profiles[{index}] must be "
                "a string or dictionary."
            )
            continue

        attribution_status = profile.get(
            "attribution_status"
        )

        if attribution_status:
            if attribution_status != (
                "behavioral_profile_match_only"
            ):
                warnings.append(
                    f"threat_profiles[{index}] uses "
                    f"attribution_status={attribution_status}."
                )

    # ---------------------------------------------------------
    # 9. RISK VALIDATION
    # ---------------------------------------------------------

    risk = fact_packet.get("risk", {})

    if not isinstance(risk, dict):
        errors.append("risk must be a dictionary.")
    elif risk:
        total_score = risk.get("total_score")
        risk_level = risk.get("risk_level")

        if total_score is None:
            warnings.append(
                "Risk object does not contain total_score."
            )

        if not risk_level:
            warnings.append(
                "Risk object does not contain risk_level."
            )

    # ---------------------------------------------------------
    # 10. EVIDENCE VALIDATION
    # ---------------------------------------------------------

    for index, evidence in enumerate(
        fact_packet.get("evidence", [])
    ):
        if not isinstance(evidence, dict):
            errors.append(
                f"evidence[{index}] must be a dictionary."
            )
            continue

        if not evidence.get("source"):
            warnings.append(
                f"evidence[{index}] has no source."
            )

        # Evidence should be traceable to something concrete.
        traceable_fields = [
            "evidence_id",
            "source_record",
            "detection_id",
            "telemetry_id",
            "rule_id",
        ]

        if not any(
            evidence.get(field)
            for field in traceable_fields
        ):
            warnings.append(
                f"evidence[{index}] has no obvious "
                "traceability identifier."
            )

    # ---------------------------------------------------------
    # 11. KNOWN FACTS MUST NOT CONTAIN RECOMMENDATIONS
    # ---------------------------------------------------------

    recommendation_words = [
        "should",
        "recommend",
        "check",
        "investigate",
        "review",
        "validate",
        "inspect",
    ]

    for index, fact in enumerate(
        fact_packet.get("known_facts", [])
    ):
        if not isinstance(fact, str):
            continue

        lowered = fact.lower()

        if any(
            word in lowered
            for word in recommendation_words
        ):
            errors.append(
                "known_facts contains recommendation-like "
                f"content at index {index}."
            )

    # ---------------------------------------------------------
    # 12. SYNTHETIC EVIDENCE CONSISTENCY
    # ---------------------------------------------------------

    synthetic_behaviors = [
        behavior
        for behavior in fact_packet.get(
            "behaviors",
            [],
        )
        if isinstance(behavior, dict)
        and behavior.get("synthetic") is True
    ]

    if synthetic_behaviors:
        warnings.append(
            "Fact Packet contains synthetic behavior telemetry. "
            "Synthetic telemetry must not be presented as "
            "confirmed real malicious activity."
        )

    # ---------------------------------------------------------
    # 13. ATTRIBUTION SAFETY
    # ---------------------------------------------------------

    for profile in fact_packet.get(
        "threat_profiles",
        [],
    ):
        if not isinstance(profile, dict):
            continue

        if profile.get("profile_name"):
            status = profile.get(
                "attribution_status"
            )

            if status != (
                "behavioral_profile_match_only"
            ):
                warnings.append(
                    "Threat profile is present without the "
                    "expected behavioral_profile_match_only "
                    "attribution status."
                )

    # ---------------------------------------------------------
    # FINAL RESULT
    # ---------------------------------------------------------

    return {
        "valid": len(errors) == 0,
        "errors": errors,
        "warnings": warnings,
    }


def assert_valid_fact_packet(
    fact_packet: Dict[str, Any],
) -> None:
    """
    Raise ValueError when a Fact Packet is invalid.
    """

    result = validate_fact_packet(fact_packet)

    if not result["valid"]:
        message = "\n".join(
            f"- {error}"
            for error in result["errors"]
        )

        raise ValueError(
            "Invalid SentinelMesh Fact Packet:\n"
            + message
        )
