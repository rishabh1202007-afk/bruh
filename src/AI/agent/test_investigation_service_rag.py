"""
Deterministic test for automatic RAG assembly in the
SentinelMesh investigation service.

This test does NOT call Ollama.

It verifies that:
1. A real Fact Packet is constructed.
2. Existing Fact Packet -> RAG Context code is used.
3. Both RAG knowledge layers are exposed.
4. The RAG context is converted to a dictionary.
5. A caller-supplied retrieval context is preserved.
6. The investigation service forwards the RAG context
   to the structured investigator.
"""

from __future__ import annotations

from typing import Any, Dict

from .investigation_service import (
    SentinelMeshInvestigationService,
)


class FakeInvestigator:
    """
    Minimal deterministic investigator used to verify
    service wiring without making an LLM call.
    """

    def __init__(self):
        self.last_fact_packet = None
        self.last_retrieval_context = None
        self.last_question = None

    def investigate(
        self,
        fact_packet: Dict[str, Any],
        retrieval_context: Dict[str, Any],
        analyst_question: str | None = None,
    ):
        self.last_fact_packet = fact_packet
        self.last_retrieval_context = (
            retrieval_context
        )
        self.last_question = (
            analyst_question
        )

        return {
            "status": "test",
            "incident_id": (
                fact_packet
                .get("incident", {})
                .get("incident_id")
            ),
        }


def build_test_incident() -> Dict[str, Any]:
    return {
        "incident_id": "INC-RAG-TEST-001",
        "timestamp": "2026-09-24T10:15:00Z",
        "host": "LAPTOP-SGNH3KHQ",
        "severity": "high",
        "incident_type": (
            "correlated_suspicious_activity"
        ),
        "correlation_rule": "CM-001",
        "rule_name": (
            "Account Discovery followed by "
            "Credential Manager Activity"
        ),
        "status": "new",
        "events": [
            {
                "event_id": 4798,
                "source_record": 1001,
                "host": "LAPTOP-SGNH3KHQ",
                "evidence_ref": "EV-001",
            },
            {
                "event_id": 5379,
                "source_record": 1002,
                "host": "LAPTOP-SGNH3KHQ",
                "evidence_ref": "EV-002",
            },
        ],
        "evidence": [
            {
                "evidence_id": "EV-001",
                "evidence_ref": "EV-001",
                "source": "windows_security",
                "description": (
                    "Windows Security event 4798"
                ),
            },
            {
                "evidence_id": "EV-002",
                "evidence_ref": "EV-002",
                "source": "windows_security",
                "description": (
                    "Windows Security event 5379"
                ),
            },
        ],
        "mitre_context": {
            "combined_techniques": [
                "T1087",
                "T1555.004",
            ]
        },
        "risk_scoring": {
            "model_version": (
                "SentinelMesh-Risk-v3"
            ),
            "total_score": 60,
            "risk_level": "high",
            "factor_details": {},
        },
        "enrichment": {
            "synthetic_evidence": False,
            "attribution_status": (
                "behavioral_profile_match_only"
            ),
        },
    }


def test_automatic_rag_assembly():
    fake_investigator = FakeInvestigator()

    service = SentinelMeshInvestigationService(
        investigator=fake_investigator,
        rag_top_k=5,
    )

    incident = build_test_incident()

    result = service.investigate(
        incident=incident,
        analyst_question=(
            "Explain the observed evidence."
        ),
    )

    assert result["status"] == "test"

    assert (
        fake_investigator.last_fact_packet
        is not None
    )

    assert (
        fake_investigator.last_retrieval_context
        is not None
    )

    rag = (
        fake_investigator
        .last_retrieval_context
    )

    assert isinstance(
        rag,
        dict,
    )

    assert (
        "security_knowledge"
        in rag
    )

    assert (
        "sentinelmesh_knowledge"
        in rag
    )

    assert (
        "queries"
        in rag
    )

    assert isinstance(
        rag["queries"],
        list,
    )

    assert len(
        rag["queries"]
    ) > 0

    assert len(
        rag["queries"]
    ) <= 12

    assert (
        fake_investigator.last_question
        == "Explain the observed evidence."
    )

    print(
        "Automatic RAG assembly: PASS"
    )

    print(
        "Queries generated:",
        len(rag["queries"]),
    )

    print(
        "Security knowledge:",
        len(
            rag["security_knowledge"]
        ),
    )

    print(
        "SentinelMesh knowledge:",
        len(
            rag["sentinelmesh_knowledge"]
        ),
    )


def test_supplied_rag_context_is_preserved():
    fake_investigator = FakeInvestigator()

    service = SentinelMeshInvestigationService(
        investigator=fake_investigator,
    )

    incident = build_test_incident()

    supplied_context = {
        "incident_id": (
            "INC-RAG-TEST-001"
        ),
        "queries": [
            "CUSTOM TEST QUERY"
        ],
        "security_knowledge": [],
        "sentinelmesh_knowledge": [],
        "warnings": [],
        "insufficient_evidence": False,
    }

    service.investigate(
        incident=incident,
        retrieval_context=supplied_context,
    )

    assert (
        fake_investigator.last_retrieval_context
        == supplied_context
    )

    print(
        "Supplied RAG context preservation: PASS"
    )


if __name__ == "__main__":
    print("=" * 50)
    print(
        "SENTINELMESH AUTOMATIC RAG "
        "ASSEMBLY TEST"
    )
    print("=" * 50)

    test_automatic_rag_assembly()
    test_supplied_rag_context_is_preserved()

    print()
    print(
        "ALL AUTOMATIC RAG TESTS PASSED"
    )