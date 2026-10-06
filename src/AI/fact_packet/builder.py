from typing import Any, Dict, List


def build_fact_packet(
    incident: Dict[str, Any],
    detections: List[Dict[str, Any]] | None = None,
    behaviors: List[Dict[str, Any]] | None = None,
    behavior_detections: List[Dict[str, Any]] | None = None,
    mitre: List[Dict[str, Any]] | None = None,
    risk: Dict[str, Any] | None = None,
    evidence: List[Dict[str, Any]] | None = None,
) -> Dict[str, Any]:
    """
    Build the canonical SentinelMesh Fact Packet.

    The Fact Packet is an evidence-preserving representation
    of an already processed SentinelMesh incident.

    This layer does not:
    - calculate risk
    - infer attribution
    - create detections
    - create MITRE mappings
    - convert synthetic telemetry into real telemetry
    """

    detections = detections or []
    behaviors = behaviors or []
    mitre = _as_dict_list(mitre)
    evidence = evidence or []
    behavior_detections = behavior_detections or []

    risk_scoring = (
        risk.get("risk_scoring", risk)
        if risk
        else {}
    )

    packet = {
        "incident": _build_incident(incident),

        "correlation": _build_correlation(incident),

        "timeline": [],

        "events": incident.get(
            "events",
            []
        ),

        "detections": detections,

        "behaviors": behaviors,

        "behavior_detections": behavior_detections,

        "entities": {
            "hosts": [],
            "users": [],
            "processes": [],
            "ips": [],
        },

        "mitre": _build_mitre(
            incident,
            mitre
        ),

        "threat_profiles": (
            _build_threat_profiles(
                incident
            )
        ),

        "risk": _build_risk(
            risk_scoring
        ),

        "evidence": evidence,

        "known_facts": [],

        "uncertainties": [],

        "evidence_gaps": [],
    }

    _extract_entities(packet)
    _build_known_facts(packet)
    _build_uncertainties(packet)
    _build_timeline(packet)

    return packet


def _build_incident(
    incident: Dict[str, Any]
) -> Dict[str, Any]:

    return {
        "incident_id": incident.get(
            "incident_id"
        ),
        "timestamp": incident.get(
            "timestamp"
        ),
        "host": incident.get(
            "host"
        ),
        "severity": incident.get(
            "severity"
        ),
        "incident_type": incident.get(
            "incident_type"
        ),
        "status": incident.get(
            "status"
        ),
        "correlation_rule": incident.get(
            "correlation_rule"
        ),
        "rule_name": incident.get(
            "rule_name"
        ),
    }


def _build_correlation(
    incident: Dict[str, Any]
) -> Dict[str, Any]:

    return {
        "rule_id": incident.get(
            "correlation_rule"
        ),
        "rule_name": incident.get(
            "rule_name"
        ),
        "time_window_seconds": incident.get(
            "time_window_seconds"
        ),
        "conditions": {
            "same_host": True,
            "chronological_order": True,
        },
    }


def _build_mitre(
    incident: Dict[str, Any],
    mitre: List[Dict[str, Any]]
) -> Dict[str, Any]:

    context = incident.get(
        "mitre_context",
        {}
    )

    if not isinstance(context, dict):
        context = {}

    windows_techniques = _as_dict_list(
        context.get("windows_techniques")
    )

    behavior_techniques = _as_dict_list(
        context.get("behavior_techniques")
    )

    combined_techniques = _as_dict_list(
        context.get(
            "combined_techniques",
            mitre,
        )
    )

    if not combined_techniques:
        combined_techniques = (
            windows_techniques
            + behavior_techniques
        )

    tactics_observed = context.get(
        "tactics_observed",
        [],
    )

    if not isinstance(tactics_observed, list):
        tactics_observed = []

    if not tactics_observed:
        tactics_observed = sorted(
            {
                str(technique.get("tactic"))
                for technique in combined_techniques
                if technique.get("tactic")
            }
        )

    return {
        "windows_techniques": windows_techniques,
        "behavior_techniques": behavior_techniques,
        "combined_techniques": combined_techniques,
        "technique_count": context.get(
            "technique_count",
            len(combined_techniques)
        ),
        "tactics_observed": tactics_observed,
        "mapping_status": context.get(
            "mapping_status"
        ),
        "attribution_warning": context.get(
            "attribution_warning"
        ),
    }


def canonical_mitre_techniques(
    mitre: Any,
) -> List[Dict[str, Any]]:
    """
    Return the canonical MITRE technique list.

    Canonical Fact Packets store MITRE context as an object whose
    authoritative technique list is combined_techniques.

    A bare list is accepted only as legacy input.
    """

    if isinstance(mitre, list):
        return _as_dict_list(mitre)

    if not isinstance(mitre, dict):
        return []

    combined = _as_dict_list(
        mitre.get("combined_techniques")
    )

    if combined:
        return combined

    return (
        _as_dict_list(mitre.get("windows_techniques"))
        + _as_dict_list(mitre.get("behavior_techniques"))
    )


def _as_dict_list(
    value: Any,
) -> List[Dict[str, Any]]:
    if not isinstance(value, list):
        return []

    return [
        dict(item)
        for item in value
        if isinstance(item, dict)
    ]


def _build_threat_profiles(
    incident: Dict[str, Any]
) -> List[Dict[str, Any]]:

    profile = incident.get(
        "threat_profile"
    )

    if not profile or profile == "Unknown":
        return []

    enrichment = incident.get(
        "enrichment",
        {}
    )

    return [
        {
            "profile_name": profile,
            "attribution_status": enrichment.get(
                "attribution_status",
                "behavioral_profile_match_only"
            ),
        }
    ]


def _build_risk(
    risk_scoring: Dict[str, Any]
) -> Dict[str, Any]:

    factors = []

    factor_details = risk_scoring.get(
        "factor_details",
        {}
    )

    for name, details in factor_details.items():

        factors.append(
            {
                "name": name,
                "score": details.get(
                    "score"
                ),
                "maximum": details.get(
                    "maximum"
                ),
                "evidence": details.get(
                    "evidence",
                    []
                ),
                "reason": details.get(
                    "reason"
                ),
            }
        )

    return {
        "model_version": risk_scoring.get(
            "model_version"
        ),
        "maximum_score": risk_scoring.get(
            "maximum_score",
            100
        ),
        "total_score": risk_scoring.get(
            "total_score"
        ),
        "risk_level": risk_scoring.get(
            "risk_level"
        ),
        "scores": risk_scoring.get(
            "scores",
            {}
        ),
        "factors": factors,
        "explanation": risk_scoring.get(
            "explanation"
        ),
    }


def _extract_entities(
    packet: Dict[str, Any]
) -> None:

    hosts = set()
    users = set()
    processes = set()
    ips = set()

    incident = packet["incident"]

    if incident.get("host"):
        hosts.add(
            incident["host"]
        )

    for detection in packet["detections"]:

        if detection.get("host"):
            hosts.add(
                detection["host"]
            )

        for key in (
            "username",
            "target_username",
            "subject_username",
        ):

            if detection.get(key):
                users.add(
                    detection[key]
                )

        if detection.get("process_name"):
            processes.add(
                detection["process_name"]
            )

    for behavior in packet["behaviors"]:

        if behavior.get("host"):
            hosts.add(
                behavior["host"]
            )

        if behavior.get("process_name"):
            processes.add(
                behavior["process_name"]
            )

        for key in (
            "ip",
            "source_ip",
            "destination_ip",
            "remote_ip",
        ):

            if behavior.get(key):
                ips.add(
                    behavior[key]
                )

    packet["entities"]["hosts"] = sorted(
        hosts
    )

    packet["entities"]["users"] = sorted(
        users
    )

    packet["entities"]["processes"] = sorted(
        processes
    )

    packet["entities"]["ips"] = sorted(
        ips
    )


def _build_known_facts(
    packet: Dict[str, Any]
) -> None:

    facts = []

    incident = packet["incident"]

    if incident.get("incident_id"):
        facts.append(
            f"Incident {incident['incident_id']} "
            "exists in SentinelMesh."
        )

    if incident.get("host"):
        facts.append(
            f"The incident is associated with "
            f"host {incident['host']}."
        )

    if incident.get("severity"):
        facts.append(
            f"SentinelMesh assigned severity "
            f"{incident['severity']}."
        )

    if incident.get("correlation_rule"):
        facts.append(
            "The incident was created by correlation "
            f"rule {incident['correlation_rule']}."
        )

    for detection in packet["detections"]:

        rule_name = detection.get(
            "rule_name"
        )

        if rule_name:
            facts.append(
                f"Detection observed: {rule_name}."
            )

    for behavior in packet["behaviors"]:

        behavior_type = behavior.get(
            "behavior_type"
        )

        if behavior_type:
            facts.append(
                f"Behavior telemetry observed: "
                f"{behavior_type}."
            )

    risk = packet["risk"]

    if risk.get("total_score") is not None:

        facts.append(
            "SentinelMesh calculated a deterministic "
            f"risk score of {risk['total_score']}/"
            f"{risk.get('maximum_score', 100)}."
        )

    if risk.get("risk_level"):

        facts.append(
            "SentinelMesh assigned risk level "
            f"{risk['risk_level']}."
        )

    packet["known_facts"] = facts


def _build_uncertainties(
    packet: Dict[str, Any]
) -> None:

    uncertainties = []

    threat_profiles = packet.get(
        "threat_profiles",
        []
    )

    if threat_profiles:

        uncertainties.append(
            "Threat profile alignment does not "
            "confirm malware attribution."
        )

    if not packet["entities"]["ips"]:

        uncertainties.append(
            "No IP addresses are present in the "
            "supplied evidence."
        )

    if any(
        behavior.get("synthetic") is True
        for behavior in packet["behaviors"]
    ):

        uncertainties.append(
            "Some behavior telemetry is synthetic "
            "and must not be presented as confirmed "
            "real-world malicious activity."
        )

    packet["uncertainties"] = uncertainties


def _build_timeline(
    packet: Dict[str, Any]
) -> None:

    timeline = []

    for event in packet.get(
        "events",
        []
    ):

        if event.get("timestamp"):

            timeline.append(
                {
                    "timestamp": event.get(
                        "timestamp"
                    ),
                    "source": "event",
                    "reference": event.get(
                        "source_record"
                    ),
                    "description": event.get(
                        "rule_name",
                        event.get(
                            "event_type",
                            "Security event"
                        )
                    ),
                }
            )

    for detection in packet.get(
        "detections",
        []
    ):

        if detection.get("timestamp"):

            timeline.append(
                {
                    "timestamp": detection.get(
                        "timestamp"
                    ),
                    "source": "detection",
                    "reference": (
                        detection.get(
                            "detection_id"
                        )
                        or detection.get(
                            "rule_id"
                        )
                    ),
                    "description": detection.get(
                        "rule_name",
                        "Security detection"
                    ),
                }
            )

    for behavior in packet.get(
        "behaviors",
        []
    ):

        if behavior.get("timestamp"):

            timeline.append(
                {
                    "timestamp": behavior.get(
                        "timestamp"
                    ),
                    "source": "behavior",
                    "reference": (
                        behavior.get(
                            "telemetry_id"
                        )
                        or behavior.get(
                            "detection_id"
                        )
                    ),
                    "description": behavior.get(
                        "description",
                        behavior.get(
                            "behavior_type",
                            "Behavior telemetry"
                        )
                    ),
                }
            )

    timeline.sort(
        key=lambda item: item.get(
            "timestamp",
            ""
        )
    )

    packet["timeline"] = timeline
