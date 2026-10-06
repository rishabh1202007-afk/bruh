from ..fact_packet.builder import build_fact_packet
from .graph_builder import build_incident_graph
from .graph_queries import (
    get_attack_sequence,
    get_detections,
    get_incident,
    get_mitre_techniques,
)


def main():
    incident = {
        "incident_id": "INC-TEST-001",
        "timestamp": "2026-09-28T10:00:00",
        "host": "TEST-HOST",
        "severity": "high",
        "incident_type": "correlated_suspicious_activity",
        "correlation_rule": "CM-001",
        "rule_name": (
            "Account Discovery followed by "
            "Credential Manager Activity"
        ),
    }

    detections = [
        {
            "detection_id": "SM-002",
            "rule_id": "SM-002",
            "rule_name": "User Account Enumeration",
            "severity": "low",
            "category": "account_discovery",
            "host": "TEST-HOST",
            "timestamp": "2026-09-28T09:58:00",
            "source_record": 1001,
        },
        {
            "detection_id": "SM-003",
            "rule_id": "SM-003",
            "rule_name": "Credential Manager Activity",
            "severity": "medium",
            "category": "credential_access",
            "host": "TEST-HOST",
            "timestamp": "2026-09-28T10:00:00",
            "source_record": 1002,
        },
    ]

    mitre = [
        {
            "technique_id": "T1087",
            "technique_name": "Account Discovery",
            "tactic": "Discovery",
            "source_detection": "SM-002",
            "mapping_basis": "Deterministic SentinelMesh mapping",
        },
        {
            "technique_id": "T1555.004",
            "technique_name": "Credentials from Password Stores",
            "tactic": "Credential Access",
            "source_detection": "SM-003",
            "mapping_basis": "Deterministic SentinelMesh mapping",
        },
    ]

    fact_packet = build_fact_packet(
        incident=incident,
        detections=detections,
        mitre=mitre,
    )

    graph = build_incident_graph(fact_packet)

    print("\n=== INCIDENT ===")
    print(get_incident(graph).properties)

    print("\n=== DETECTIONS ===")
    for detection in get_detections(graph):
        print(detection.properties)

    print("\n=== MITRE ===")
    for technique in get_mitre_techniques(graph):
        print(technique.properties)

    print("\n=== ATTACK SEQUENCE ===")
    for item in get_attack_sequence(graph):
        print(item)

    print("\n=== GRAPH COUNTS ===")
    print("Nodes:", len(graph.nodes))
    print("Edges:", len(graph.edges))


if __name__ == "__main__":
    main()