from typing import Any, Dict

from ..fact_packet.builder import canonical_mitre_techniques
from .graph_models import GraphEdge, GraphNode, IncidentGraph


def build_incident_graph(
    fact_packet: Dict[str, Any],
) -> IncidentGraph:
    """
    Build an Incident Intelligence Graph from a SentinelMesh
    canonical Fact Packet.

    The graph contains only relationships supported by the
    Fact Packet. No AI inference is performed here.
    """

    graph = IncidentGraph()

    incident = fact_packet.get("incident", {})
    incident_id = incident.get("incident_id")

    if not incident_id:
        raise ValueError(
            "Fact Packet does not contain an incident_id."
        )

    # =========================================================
    # 1. INCIDENT
    # =========================================================

    incident_node = GraphNode(
        node_id=f"incident:{incident_id}",
        node_type="incident",
        source="sentinelmesh",
        properties=incident,
    )

    graph.add_node(incident_node)

    # =========================================================
    # 2. CORRELATION RULE
    # =========================================================

    correlation = fact_packet.get("correlation", {})
    correlation_rule = correlation.get("rule_id")

    if correlation_rule:
        correlation_node = GraphNode(
            node_id=f"correlation:{correlation_rule}",
            node_type="correlation_rule",
            source="sentinelmesh",
            properties=correlation,
        )

        graph.add_node(correlation_node)

        graph.add_edge(
            GraphEdge(
                source_id=incident_node.node_id,
                target_id=correlation_node.node_id,
                relationship="CORRELATED_BY",
                source="sentinelmesh",
                properties={
                    "basis": "deterministic_correlation"
                },
            )
        )

    # =========================================================
    # 3. EVENTS
    # =========================================================

    for index, event in enumerate(
        fact_packet.get("events", [])
    ):
        event_id = (
            event.get("source_record")
            or event.get("event_id")
            or f"event-{index}"
        )

        event_node = GraphNode(
            node_id=f"event:{event_id}",
            node_type="event",
            source=event.get(
                "source",
                "windows_security",
            ),
            properties=event,
        )

        graph.add_node(event_node)

    # =========================================================
    # 4. WINDOWS DETECTIONS
    # =========================================================

    for index, detection in enumerate(
        fact_packet.get("detections", [])
    ):
        detection_id = (
            detection.get("detection_id")
            or detection.get("rule_id")
            or f"detection-{index}"
        )

        detection_node = GraphNode(
            node_id=f"detection:{detection_id}",
            node_type="detection",
            source="sentinelmesh",
            properties=detection,
        )

        graph.add_node(detection_node)

        # Incident -> Detection
        graph.add_edge(
            GraphEdge(
                source_id=incident_node.node_id,
                target_id=detection_node.node_id,
                relationship="CONTAINS",
                source="sentinelmesh",
                properties={
                    "basis": "incident_detection_membership"
                },
            )
        )

        # Detection -> Original Windows event
        source_record = detection.get("source_record")

        if source_record is not None:
            event_node_id = f"event:{source_record}"

            if graph.get_node(event_node_id):
                graph.add_edge(
                    GraphEdge(
                        source_id=detection_node.node_id,
                        target_id=event_node_id,
                        relationship="DERIVED_FROM",
                        source="sentinelmesh",
                        properties={
                            "basis": "source_record_traceability"
                        },
                    )
                )

        _connect_detection_entities(
            graph,
            detection_node,
            detection,
        )

    # =========================================================
    # 5. BEHAVIOR TELEMETRY
    # =========================================================

    for index, behavior in enumerate(
        fact_packet.get("behaviors", [])
    ):
        telemetry_id = (
            behavior.get("telemetry_id")
            or behavior.get("detection_id")
            or f"behavior-{index}"
        )

        behavior_node = GraphNode(
            node_id=f"behavior:{telemetry_id}",
            node_type="behavior_telemetry",
            source=behavior.get(
                "source",
                "endpoint_behavior",
            ),
            properties=behavior,
        )

        graph.add_node(behavior_node)

        # Incident -> Behavior Telemetry
        graph.add_edge(
            GraphEdge(
                source_id=incident_node.node_id,
                target_id=behavior_node.node_id,
                relationship="CONTAINS",
                source="sentinelmesh",
                properties={
                    "basis": "incident_behavior_membership"
                },
            )
        )

        _connect_behavior_entities(
            graph,
            behavior_node,
            behavior,
        )

    # =========================================================
    # 6. BEHAVIOR DETECTIONS
    # =========================================================

    for index, behavior_detection in enumerate(
        fact_packet.get("behavior_detections", [])
    ):
        detection_id = (
            behavior_detection.get("detection_id")
            or behavior_detection.get("rule_id")
            or f"behavior-detection-{index}"
        )

        behavior_detection_node = GraphNode(
            node_id=f"behavior_detection:{detection_id}",
            node_type="behavior_detection",
            source="sentinelmesh",
            properties=behavior_detection,
        )

        graph.add_node(behavior_detection_node)

        # Incident -> Behavior Detection
        graph.add_edge(
            GraphEdge(
                source_id=incident_node.node_id,
                target_id=behavior_detection_node.node_id,
                relationship="CONTAINS",
                source="sentinelmesh",
                properties={
                    "basis": "incident_behavior_detection_membership"
                },
            )
        )

        # Behavior Detection -> Behavior Telemetry
        source_telemetry = behavior_detection.get(
            "source_telemetry"
        )

        if source_telemetry:
            behavior_node_id = (
                f"behavior:{source_telemetry}"
            )

            if graph.get_node(behavior_node_id):
                graph.add_edge(
                    GraphEdge(
                        source_id=behavior_detection_node.node_id,
                        target_id=behavior_node_id,
                        relationship="DERIVED_FROM",
                        source="sentinelmesh",
                        properties={
                            "basis": "source_telemetry_traceability"
                        },
                    )
                )

        _connect_behavior_detection_entities(
            graph,
            behavior_detection_node,
            behavior_detection,
        )

    # =========================================================
    # 7. MITRE ATT&CK TECHNIQUES
    # =========================================================

    for technique in _mitre_techniques(
        fact_packet.get("mitre")
    ):
        technique_id = technique.get("technique_id")

        if not technique_id:
            continue

        technique_node = GraphNode(
            node_id=f"mitre:{technique_id}",
            node_type="mitre_technique",
            source="sentinelmesh",
            properties=technique,
        )

        graph.add_node(technique_node)

        source_detection = technique.get(
            "source_detection"
        )

        if source_detection:
            source_node_id = None

            # Windows detection
            detection_node_id = (
                f"detection:{source_detection}"
            )

            if graph.get_node(detection_node_id):
                source_node_id = detection_node_id

            # Behavior detection
            behavior_detection_node_id = (
                f"behavior_detection:{source_detection}"
            )

            if graph.get_node(
                behavior_detection_node_id
            ):
                source_node_id = (
                    behavior_detection_node_id
                )

            if source_node_id:
                graph.add_edge(
                    GraphEdge(
                        source_id=source_node_id,
                        target_id=technique_node.node_id,
                        relationship="MAPPED_TO",
                        source="sentinelmesh",
                        properties={
                            "basis": technique.get(
                                "mapping_basis",
                                "deterministic_mitre_mapping",
                            )
                        },
                    )
                )

    # =========================================================
    # 8. THREAT PROFILES
    # =========================================================

    for profile in fact_packet.get(
        "threat_profiles",
        [],
    ):
        if isinstance(profile, str):
            profile_name = profile
            profile_data = {
                "profile_name": profile_name
            }
        else:
            profile_name = profile.get(
                "profile_name"
            )
            profile_data = profile

        if not profile_name:
            continue

        profile_node = GraphNode(
            node_id=f"threat_profile:{profile_name}",
            node_type="threat_profile",
            source="sentinelmesh",
            properties=profile_data,
        )

        graph.add_node(profile_node)

        graph.add_edge(
            GraphEdge(
                source_id=incident_node.node_id,
                target_id=profile_node.node_id,
                relationship="ALIGNS_WITH",
                source="sentinelmesh",
                properties={
                    "basis": "deterministic_profile_alignment",
                    "attribution_status": profile_data.get(
                        "attribution_status",
                        "behavioral_profile_match_only",
                    ),
                },
            )
        )

    # =========================================================
    # 9. RISK FACTORS
    # =========================================================

    risk = fact_packet.get("risk", {})

    if risk:
        factors = risk.get("factors", [])

        for index, factor in enumerate(factors):
            factor_name = factor.get(
                "name",
                f"factor-{index}",
            )

            factor_node = GraphNode(
                node_id=f"risk_factor:{factor_name}",
                node_type="risk_factor",
                source="sentinelmesh",
                properties=factor,
            )

            graph.add_node(factor_node)

            graph.add_edge(
                GraphEdge(
                    source_id=incident_node.node_id,
                    target_id=factor_node.node_id,
                    relationship="HAS_RISK_FACTOR",
                    source="sentinelmesh",
                    properties={
                        "basis": "deterministic_risk_scoring"
                    },
                )
            )

            # Risk factor -> supporting evidence
            for evidence_id in _extract_evidence_ids(
                factor
            ):
                evidence_node_id = (
                    f"evidence:{evidence_id}"
                )

                if graph.get_node(evidence_node_id):
                    graph.add_edge(
                        GraphEdge(
                            source_id=factor_node.node_id,
                            target_id=evidence_node_id,
                            relationship="SUPPORTED_BY",
                            source="sentinelmesh",
                            properties={
                                "basis": "risk_factor_evidence_reference"
                            },
                        )
                    )

    # =========================================================
    # 10. EVIDENCE
    # =========================================================

    for index, evidence in enumerate(
        fact_packet.get("evidence", [])
    ):
        evidence_id = evidence.get(
            "evidence_id",
            f"evidence-{index}",
        )

        evidence_node = GraphNode(
            node_id=f"evidence:{evidence_id}",
            node_type="evidence",
            source=evidence.get(
                "source",
                "sentinelmesh",
            ),
            properties=evidence,
        )

        graph.add_node(evidence_node)

        # Incident -> Evidence
        graph.add_edge(
            GraphEdge(
                source_id=incident_node.node_id,
                target_id=evidence_node.node_id,
                relationship="SUPPORTED_BY",
                source="sentinelmesh",
                properties={
                    "basis": "fact_packet_evidence"
                },
            )
        )

        # Evidence -> Detection / Behavior Detection
        _connect_evidence_to_sources(
            graph,
            evidence_node,
            evidence,
        )

    # =========================================================
    # 11. HOSTS
    # =========================================================

    entities = fact_packet.get(
        "entities",
        {},
    )

    for host in entities.get("hosts", []):
        host_value = _entity_value(host)

        if not host_value:
            continue

        host_node = GraphNode(
            node_id=f"host:{host_value}",
            node_type="host",
            source="sentinelmesh",
            properties={
                "hostname": host_value
            },
        )

        graph.add_node(host_node)

    # =========================================================
    # 12. USERS
    # =========================================================

    for user in entities.get("users", []):
        user_value = _entity_value(user)

        if not user_value:
            continue

        user_node = GraphNode(
            node_id=f"user:{user_value}",
            node_type="user",
            source="sentinelmesh",
            properties={
                "username": user_value
            },
        )

        graph.add_node(user_node)

    # =========================================================
    # 13. PROCESSES
    # =========================================================

    for process in entities.get("processes", []):
        process_value = _entity_value(process)

        if not process_value:
            continue

        process_node = GraphNode(
            node_id=f"process:{process_value}",
            node_type="process",
            source="sentinelmesh",
            properties={
                "process_name": process_value
            },
        )

        graph.add_node(process_node)

    # =========================================================
    # 14. IP ADDRESSES
    # =========================================================
    #
    # IPs are created ONLY when the Fact Packet already contains
    # them. The graph never invents an IP address.
    #
    # Fact Packet:
    #
    # "entities": {
    #     "ips": ["192.168.1.10"]
    # }
    #
    # becomes:
    #
    # ip:192.168.1.10
    #
    # =========================================================

    for ip in entities.get("ips", []):
        ip_value = _entity_value(ip)

        if not ip_value:
            continue

        ip_node = GraphNode(
            node_id=f"ip:{ip_value}",
            node_type="ip",
            source="sentinelmesh",
            properties={
                "ip": ip_value
            },
        )

        graph.add_node(ip_node)

    # =========================================================
    # 15. CONNECT INCIDENT ENTITIES
    # =========================================================

    _connect_incident_entities(
        graph,
        incident_node,
        entities,
    )

    return graph


# =============================================================
# ENTITY HELPERS
# =============================================================


def _entity_value(
    entity: Any,
) -> str | None:
    """
    Convert an entity value into a stable string.

    Supports both simple strings and dictionary-based
    entities without inventing missing values.
    """

    if isinstance(entity, str):
        value = entity.strip()

        if value:
            return value

        return None

    if isinstance(entity, dict):
        for key in (
            "value",
            "hostname",
            "username",
            "user",
            "process_name",
            "process",
            "ip",
            "ip_address",
        ):
            value = entity.get(key)

            if value is not None:
                value = str(value).strip()

                if value:
                    return value

    return None


def _mitre_techniques(
    mitre: Any,
) -> list[Dict[str, Any]]:
    """
    Return the canonical MITRE technique list.
    """

    return canonical_mitre_techniques(mitre)


# =============================================================
# DETECTION ENTITY CONNECTIONS
# =============================================================


def _connect_detection_entities(
    graph: IncidentGraph,
    detection_node: GraphNode,
    detection: Dict[str, Any],
) -> None:
    """
    Connect a Windows detection to entities explicitly present
    in the detection.
    """

    _connect_value_to_entity(
        graph,
        detection_node,
        detection.get("host"),
        "host",
        "OBSERVED_ON",
    )

    _connect_value_to_entity(
        graph,
        detection_node,
        detection.get("target_computer"),
        "host",
        "INVOLVES",
    )

    for field in (
        "target_username",
        "subject_username",
        "username",
        "user",
    ):
        _connect_value_to_entity(
            graph,
            detection_node,
            detection.get(field),
            "user",
            "INVOLVES",
        )

    for field in (
        "process_name",
        "process",
    ):
        _connect_value_to_entity(
            graph,
            detection_node,
            detection.get(field),
            "process",
            "INVOLVES",
        )

    for field in (
        "ip",
        "ip_address",
        "source_ip",
        "src_ip",
        "destination_ip",
        "dest_ip",
        "dst_ip",
        "remote_ip",
        "local_ip",
    ):
        _connect_value_to_entity(
            graph,
            detection_node,
            detection.get(field),
            "ip",
            "INVOLVES",
        )


# =============================================================
# BEHAVIOR TELEMETRY ENTITY CONNECTIONS
# =============================================================


def _connect_behavior_entities(
    graph: IncidentGraph,
    behavior_node: GraphNode,
    behavior: Dict[str, Any],
) -> None:
    """
    Connect behavior telemetry to explicitly observed entities.
    """

    _connect_value_to_entity(
        graph,
        behavior_node,
        behavior.get("host"),
        "host",
        "OBSERVED_ON",
    )

    _connect_value_to_entity(
        graph,
        behavior_node,
        behavior.get("user"),
        "user",
        "INVOLVES",
    )

    _connect_value_to_entity(
        graph,
        behavior_node,
        behavior.get("username"),
        "user",
        "INVOLVES",
    )

    _connect_value_to_entity(
        graph,
        behavior_node,
        behavior.get("process_name"),
        "process",
        "INVOLVES",
    )

    for field in (
        "ip",
        "ip_address",
        "source_ip",
        "src_ip",
        "destination_ip",
        "dest_ip",
        "dst_ip",
        "remote_ip",
        "local_ip",
    ):
        _connect_value_to_entity(
            graph,
            behavior_node,
            behavior.get(field),
            "ip",
            "INVOLVES",
        )


# =============================================================
# BEHAVIOR DETECTION ENTITY CONNECTIONS
# =============================================================


def _connect_behavior_detection_entities(
    graph: IncidentGraph,
    behavior_detection_node: GraphNode,
    behavior_detection: Dict[str, Any],
) -> None:
    """
    Connect a behavior detection to explicitly observed entities.
    """

    _connect_value_to_entity(
        graph,
        behavior_detection_node,
        behavior_detection.get("host"),
        "host",
        "OBSERVED_ON",
    )

    for field in (
        "username",
        "user",
        "subject_username",
    ):
        _connect_value_to_entity(
            graph,
            behavior_detection_node,
            behavior_detection.get(field),
            "user",
            "INVOLVES",
        )

    for field in (
        "process_name",
        "process",
    ):
        _connect_value_to_entity(
            graph,
            behavior_detection_node,
            behavior_detection.get(field),
            "process",
            "INVOLVES",
        )

    for field in (
        "ip",
        "ip_address",
        "source_ip",
        "src_ip",
        "destination_ip",
        "dest_ip",
        "dst_ip",
        "remote_ip",
        "local_ip",
    ):
        _connect_value_to_entity(
            graph,
            behavior_detection_node,
            behavior_detection.get(field),
            "ip",
            "INVOLVES",
        )


# =============================================================
# GENERIC ENTITY CONNECTION
# =============================================================


def _connect_value_to_entity(
    graph: IncidentGraph,
    source_node: GraphNode,
    value: Any,
    entity_type: str,
    relationship: str,
) -> None:
    """
    Connect a source node to an entity only when the entity
    already exists in the graph.
    """

    if value is None:
        return

    if isinstance(value, (list, tuple, set)):
        for item in value:
            _connect_value_to_entity(
                graph,
                source_node,
                item,
                entity_type,
                relationship,
            )

        return

    value = str(value).strip()

    if not value:
        return

    entity_node_id = f"{entity_type}:{value}"

    if not graph.get_node(entity_node_id):
        return

    graph.add_edge(
        GraphEdge(
            source_id=source_node.node_id,
            target_id=entity_node_id,
            relationship=relationship,
            source="sentinelmesh",
            properties={
                "basis": "explicit_source_field"
            },
        )
    )


# =============================================================
# INCIDENT -> ENTITY CONNECTIONS
# =============================================================


def _connect_incident_entities(
    graph: IncidentGraph,
    incident_node: GraphNode,
    entities: Dict[str, Any],
) -> None:
    """
    Connect the incident to entities explicitly represented in
    the Fact Packet.
    """

    for host in entities.get("hosts", []):
        _connect_value_to_entity(
            graph,
            incident_node,
            _entity_value(host),
            "host",
            "INVOLVES",
        )

    for user in entities.get("users", []):
        _connect_value_to_entity(
            graph,
            incident_node,
            _entity_value(user),
            "user",
            "INVOLVES",
        )

    for process in entities.get("processes", []):
        _connect_value_to_entity(
            graph,
            incident_node,
            _entity_value(process),
            "process",
            "INVOLVES",
        )

    for ip in entities.get("ips", []):
        _connect_value_to_entity(
            graph,
            incident_node,
            _entity_value(ip),
            "ip",
            "INVOLVES",
        )


# =============================================================
# EVIDENCE CONNECTIONS
# =============================================================


def _connect_evidence_to_sources(
    graph: IncidentGraph,
    evidence_node: GraphNode,
    evidence: Dict[str, Any],
) -> None:
    """
    Connect evidence to the exact detection, behavior detection,
    telemetry, or event referenced by the evidence record.
    """

    detection_id = evidence.get("detection_id")

    if detection_id:
        detection_node_id = (
            f"detection:{detection_id}"
        )

        if graph.get_node(detection_node_id):
            graph.add_edge(
                GraphEdge(
                    source_id=detection_node_id,
                    target_id=evidence_node.node_id,
                    relationship="SUPPORTED_BY",
                    source="sentinelmesh",
                    properties={
                        "basis": "evidence_detection_reference"
                    },
                )
            )

        behavior_detection_node_id = (
            f"behavior_detection:{detection_id}"
        )

        if graph.get_node(
            behavior_detection_node_id
        ):
            graph.add_edge(
                GraphEdge(
                    source_id=behavior_detection_node_id,
                    target_id=evidence_node.node_id,
                    relationship="SUPPORTED_BY",
                    source="sentinelmesh",
                    properties={
                        "basis": "evidence_behavior_detection_reference"
                    },
                )
            )

    source_record = evidence.get("source_record")

    if source_record is not None:
        event_node_id = f"event:{source_record}"

        if graph.get_node(event_node_id):
            graph.add_edge(
                GraphEdge(
                    source_id=event_node_id,
                    target_id=evidence_node.node_id,
                    relationship="SUPPORTED_BY",
                    source="sentinelmesh",
                    properties={
                        "basis": "evidence_event_reference"
                    },
                )
            )

    source_telemetry = evidence.get(
        "source_telemetry"
    )

    if source_telemetry:
        behavior_node_id = (
            f"behavior:{source_telemetry}"
        )

        if graph.get_node(behavior_node_id):
            graph.add_edge(
                GraphEdge(
                    source_id=behavior_node_id,
                    target_id=evidence_node.node_id,
                    relationship="SUPPORTED_BY",
                    source="sentinelmesh",
                    properties={
                        "basis": "evidence_telemetry_reference"
                    },
                )
            )


# =============================================================
# RISK FACTOR EVIDENCE IDS
# =============================================================


def _extract_evidence_ids(
    factor: Dict[str, Any],
) -> list[str]:
    """
    Extract explicit evidence IDs from a risk factor.
    """

    evidence_ids = factor.get("evidence_ids", [])

    if isinstance(evidence_ids, str):
        return [evidence_ids]

    if isinstance(evidence_ids, list):
        return [
            str(item)
            for item in evidence_ids
            if item
        ]

    return []
