from __future__ import annotations

from ..agent.investigation_service import (
    SentinelMeshInvestigationService,
)
from ..agent.structured_llm_investigator import (
    StructuredLLMInvestigator,
)


def build_live_incident():
    """
    Build a deterministic SentinelMesh incident in the same
    shape consumed by SentinelMeshInvestigationService.

    The service itself will construct:
        Incident
        -> Fact Packet
        -> Automatic RAG
        -> Structured LLM investigation
    """

    return {
        "incident_id": "INC-LIVE-STRUCTURED-001",
        "timestamp": "2026-09-24T10:15:00Z",
        "host": "LAPTOP-SGNH3KHQ",
        "severity": "high",
        "incident_type": "correlated_suspicious_activity",
        "correlation_rule": "CM-001",
        "rule_name": (
            "Account Discovery followed by "
            "Credential Manager Activity"
        ),
        "time_window_seconds": 120,
        "status": "new",

        "evidence": [
            {
                "evidence_id": "EV-001",
                "evidence_ref": "EV-001",
                "source": "windows_security",
                "description": (
                    "Windows Security event 4798"
                ),
                "event_id": 4798,
                "source_record": 1001,
                "detection_id": "SM-002",
                "rule_id": "SM-002",
                "rule_name": "User Account Enumeration",
                "severity": "low",
                "category": "account_discovery",
                "host": "LAPTOP-SGNH3KHQ",
                "timestamp": "2026-09-24T10:14:00Z",
            },
            {
                "evidence_id": "EV-002",
                "evidence_ref": "EV-002",
                "source": "windows_security",
                "description": (
                    "Windows Security event 5379"
                ),
                "event_id": 5379,
                "source_record": 1002,
                "detection_id": "SM-003",
                "rule_id": "SM-003",
                "rule_name": "Credential Manager Activity",
                "severity": "medium",
                "category": "credential_access",
                "host": "LAPTOP-SGNH3KHQ",
                "timestamp": "2026-09-24T10:15:00Z",
            },
            {
                "evidence_id": "EV-003",
                "evidence_ref": "EV-003",
                "source": "behavior_telemetry",
                "telemetry_id": "TEL-001",
                "synthetic": True,
                "threat_profile": "GlassWorm",
                "behavior_type": "browser_data_access",
                "severity": "high",
                "description": (
                    "Synthetic telemetry: browser data access "
                    "indicator."
                ),
                "host": "LAPTOP-SGNH3KHQ",
                "timestamp": "2026-09-24T10:15:10Z",
                "rule_id": "BT-003",
                "rule_name": (
                    "Browser Data Access Indicator"
                ),
                "category": "credential_access",
            },
        ],

        "mitre_context": {
            "combined_techniques": [
                {
                    "technique_id": "T1087",
                    "technique_name": "Account Discovery",
                    "tactic": "Discovery",
                    "source_detection": "SM-002",
                    "mapping_basis": (
                        "Deterministic SentinelMesh mapping"
                    ),
                },
                {
                    "technique_id": "T1555.004",
                    "technique_name": (
                        "Credentials from Password Stores"
                    ),
                    "tactic": "Credential Access",
                    "source_detection": "SM-003",
                    "mapping_basis": (
                        "Deterministic SentinelMesh mapping"
                    ),
                },
            ],
            "mapping_status": (
                "contextual_behavioral_mapping"
            ),
        },

        "threat_profiles": {
            "profiles": [
                "GlassWorm"
            ],
            "attribution_status": (
                "behavioral_profile_match_only"
            ),
        },

        "risk_scoring": {
            "model_version": "SentinelMesh-Risk-v3",
            "total_score": 60,
            "risk_level": "high",
            "scores": {},
            "factor_details": {},
        },
    }


def main():
    incident = build_live_incident()

    investigator = StructuredLLMInvestigator(
        model="qwen3:8b",
        temperature=0.0,
        max_output_tokens=1200,
    )

    service = SentinelMeshInvestigationService(
        investigator=investigator,
        rag_top_k=5,
    )

    # ---------------------------------------------------------
    # 1. Build Fact Packet through the real service
    # ---------------------------------------------------------

    fact_packet = service.build_fact_packet(
        incident
    )

    # ---------------------------------------------------------
    # 2. Verify automatic two-layer RAG
    # ---------------------------------------------------------

    rag_context = service.build_rag_context(
        fact_packet
    )

    print(
        "\n"
        "SENTINELMESH LIVE END-TO-END "
        "QWEN3 + AUTOMATIC RAG TEST"
    )

    print(
        "Incident:",
        incident["incident_id"],
    )

    print(
        "Model: qwen3:8b"
    )

    print(
        "Queries generated:",
        len(rag_context.queries),
    )

    print(
        "Security knowledge:",
        len(rag_context.security_knowledge),
    )

    print(
        "SentinelMesh knowledge:",
        len(rag_context.sentinelmesh_knowledge),
    )

    print(
        "\nRETRIEVED SECURITY:"
    )

    for item in rag_context.security_knowledge:
        print(
            f"- {item.title} | "
            f"refs={item.evidence_refs}"
        )

    print(
        "\nRETRIEVED SENTINELMESH:"
    )

    for item in rag_context.sentinelmesh_knowledge:
        print(
            f"- {item.title} | "
            f"refs={item.evidence_refs}"
        )

    # ---------------------------------------------------------
    # 3. Real service call
    #
    # IMPORTANT:
    # The service receives the INCIDENT.
    # It creates the Fact Packet and RAG internally.
    # ---------------------------------------------------------

    response = service.investigate(
        incident=incident,
        retrieval_context=None,
        analyst_question=(
            "Investigate the correlated activity using "
            "only the supplied Fact Packet and retrieved "
            "knowledge. Separate observed facts from "
            "security knowledge, preserve synthetic "
            "telemetry status, and identify evidence gaps "
            "and the next investigation steps."
        ),
    )

    # ---------------------------------------------------------
    # 4. Display structured result
    # ---------------------------------------------------------

    print(
        "\n"
        "=== STRUCTURED INVESTIGATION RESPONSE ==="
    )

    print(
        response.to_dict()
    )

    # ---------------------------------------------------------
    # 5. Final validation summary
    # ---------------------------------------------------------

    print(
        "\n"
        "=== RESULT ==="
    )

    print(
        "Status:",
        response.status,
    )

    print(
        "Grounded:",
        response.grounded,
    )

    print(
        "Insufficient evidence:",
        response.insufficient_evidence,
    )

    print(
        "Observed facts:",
        len(response.observed_facts),
    )

    print(
        "Knowledge context:",
        len(response.knowledge_context),
    )

    print(
        "Evidence gaps:",
        len(response.evidence_gaps),
    )

    print(
        "Next steps:",
        len(response.next_investigation_steps),
    )


if __name__ == "__main__":
    main()