"""
Test the Fact Packet -> RAG Context Builder.

This test uses a representative SentinelMesh Fact Packet structure.
It does not modify the actual detection pipeline.
"""

from .fact_packet_context import (
    build_investigation_queries,
    build_rag_context,
)


def build_test_fact_packet():
    """
    Build a representative SentinelMesh Fact Packet.
    """

    return {
        "incident": {
            "incident_id": "INC-TEST-001",
            "timestamp": "2026-10-02T10:00:00",
            "host": "LAPTOP-SGNH3KHQ",
            "severity": "high",
            "incident_type": "correlated_suspicious_activity",
            "correlation_rule": "CM-001",
            "rule_name": (
                "Account Discovery followed by "
                "Credential Manager Activity"
            ),
            "status": "new",
        },

        "correlation": {
            "correlation_rule": "CM-001",
            "rule_name": (
                "Account Discovery followed by "
                "Credential Manager Activity"
            ),
            "time_window_seconds": 120,
        },

        "detections": [
            {
                "rule_id": "SM-002",
                "rule_name": "User Account Enumeration",
                "severity": "low",
                "category": "account_discovery",
                "event_id": 4798,
            },
            {
                "rule_id": "SM-003",
                "rule_name": "Credential Manager Activity",
                "severity": "medium",
                "category": "credential_access",
                "event_id": 5379,
            },
        ],

        "behaviors": [
            {
                "behavior_type": "browser_data_access",
                "severity": "high",
                "threat_profile": "GlassWorm",
                "description": (
                    "Synthetic browser data access indicator."
                ),
            }
        ],

        "behavior_detections": [
            {
                "detection_id": "BT-003-test",
                "rule_id": "BT-003",
                "rule_name": "Browser Data Access Indicator",
                "severity": "high",
                "category": "credential_access",
                "behavior_type": "browser_data_access",
                "source_telemetry": "telemetry-test-001",
            }
        ],

        "mitre": {
            "combined_techniques": [
                {
                    "technique_id": "T1087",
                    "technique_name": "Account Discovery",
                    "tactic": "Discovery",
                },
                {
                    "technique_id": "T1555.004",
                    "technique_name": (
                        "Credentials from Password Stores"
                    ),
                    "tactic": "Credential Access",
                },
            ]
        },

        "threat_profiles": [
            {
                "profile": "GlassWorm",
                "attribution_status": (
                    "behavioral_profile_match_only"
                ),
            }
        ],

        "risk": {
            "total_score": 72,
            "risk_level": "high",
            "factors": [
                {
                    "factor": "detection_severity",
                    "score": 12,
                    "reason": (
                        "High-severity correlated incident."
                    ),
                },
                {
                    "factor": "behavioral_evidence",
                    "score": 6,
                    "reason": (
                        "Observed behavioral evidence."
                    ),
                },
            ],
        },

        "evidence_gaps": [
            {
                "category": "process_context",
                "description": (
                    "Additional process context is required "
                    "to determine whether the activity matches "
                    "expected administrative behavior."
                ),
            }
        ],
    }


def main():
    """
    Run the Fact Packet -> RAG Context test.
    """

    fact_packet = build_test_fact_packet()

    print("=" * 70)
    print("FACT PACKET -> INVESTIGATION QUERIES")
    print("=" * 70)

    queries = build_investigation_queries(
        fact_packet
    )

    for index, query in enumerate(
        queries,
        start=1,
    ):
        print(
            f"{index}. {query}"
        )

    print()
    print("=" * 70)
    print("FACT PACKET -> RAG CONTEXT")
    print("=" * 70)

    context = build_rag_context(
        fact_packet,
        top_k=5,
    )

    print(
        "\nIncident:",
        context.incident_id,
    )

    print(
        "\nQueries generated:",
        len(context.queries),
    )

    print("\n--- SECURITY KNOWLEDGE ---")

    for item in context.security_knowledge:

        print(
            f"[{item.relevance}] "
            f"{item.title}"
        )

        print(
            f"    Ref: "
            f"{', '.join(item.evidence_refs)}"
        )

    print("\n--- SENTINELMESH KNOWLEDGE ---")

    for item in context.sentinelmesh_knowledge:

        print(
            f"[{item.relevance}] "
            f"{item.title}"
        )

        print(
            f"    Ref: "
            f"{', '.join(item.evidence_refs)}"
        )

    print("\n--- WARNINGS ---")

    if context.warnings:

        for warning in context.warnings:
            print(
                f"- {warning}"
            )

    else:

        print("None")

    print(
        "\nInsufficient evidence:",
        context.insufficient_evidence,
    )

    print("\n--- SERIALIZED CONTEXT ---")

    serialized = context.to_dict()

    print(
        "Keys:",
        list(serialized.keys()),
    )

    print(
        "\nTest completed successfully."
    )


if __name__ == "__main__":
    main()