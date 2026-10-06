from typing import Any, Dict, List

from .graph_models import GraphNode, IncidentGraph


def get_incident(
    graph: IncidentGraph,
) -> GraphNode | None:
    """
    Return the incident node.
    """

    incidents = graph.get_nodes_by_type("incident")

    if not incidents:
        return None

    return incidents[0]


def get_detections(
    graph: IncidentGraph,
) -> List[GraphNode]:
    """
    Return all security detections associated with the incident.
    """

    return graph.get_nodes_by_type("detection")


def get_behaviors(
    graph: IncidentGraph,
) -> List[GraphNode]:
    """
    Return all behavior telemetry nodes.
    """

    return graph.get_nodes_by_type("behavior_telemetry")


def get_mitre_techniques(
    graph: IncidentGraph,
) -> List[GraphNode]:
    """
    Return MITRE ATT&CK techniques mapped in the graph.
    """

    return graph.get_nodes_by_type("mitre_technique")


def get_threat_profiles(
    graph: IncidentGraph,
) -> List[GraphNode]:
    """
    Return threat profiles associated with the incident.
    """

    return graph.get_nodes_by_type("threat_profile")


def get_risk_factors(
    graph: IncidentGraph,
) -> List[GraphNode]:
    """
    Return deterministic risk factors.
    """

    return graph.get_nodes_by_type("risk_factor")


def get_evidence(
    graph: IncidentGraph,
) -> List[GraphNode]:
    """
    Return evidence nodes supporting the incident.
    """

    return graph.get_nodes_by_type("evidence")


def get_entities(
    graph: IncidentGraph,
) -> Dict[str, List[GraphNode]]:
    """
    Return entities grouped by type.
    """

    entity_types = [
    "host",
    "user",
    "process",
    "ip",
    ]   

    return {
        entity_type: graph.get_nodes_by_type(entity_type)
        for entity_type in entity_types
    }


def get_incident_overview(
    graph: IncidentGraph,
) -> Dict[str, Any]:
    """
    Build a structured overview for the future AI investigator.
    """

    incident = get_incident(graph)

    if incident is None:
        return {}

    return {
        "incident": incident.properties,
        "detections": [
            node.properties
            for node in get_detections(graph)
        ],
        "behaviors": [
            node.properties
            for node in get_behaviors(graph)
        ],
        "mitre": [
            node.properties
            for node in get_mitre_techniques(graph)
        ],
        "threat_profiles": [
            node.properties
            for node in get_threat_profiles(graph)
        ],
        "risk_factors": [
            node.properties
            for node in get_risk_factors(graph)
        ],
        "evidence": [
            node.properties
            for node in get_evidence(graph)
        ],
        "entities": {
            entity_type: [
                node.properties
                for node in nodes
            ]
            for entity_type, nodes in get_entities(graph).items()
        },
    }


def get_attack_sequence(
    graph: IncidentGraph,
) -> List[Dict[str, Any]]:
    """
    Return available timeline information in chronological order.

    The sequence is based only on timestamps present in graph nodes.
    """

    sequence = []

    for node in graph.nodes:
        timestamp = node.properties.get("timestamp")

        if timestamp:
            sequence.append(
                {
                    "timestamp": timestamp,
                    "node_id": node.node_id,
                    "node_type": node.node_type,
                    "description": node.properties.get(
                        "description"
                    )
                    or node.properties.get(
                        "rule_name"
                    )
                    or node.properties.get(
                        "behavior_type"
                    ),
                }
            )

    sequence.sort(
        key=lambda item: item["timestamp"]
    )

    return sequence