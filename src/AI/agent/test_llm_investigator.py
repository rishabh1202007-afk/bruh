from typing import Any, Dict

from ..llm.models import LLMRequest, LLMResponse
from ..llm.provider import LLMProvider
from .llm_investigator import LLMInvestigator


class MockLLMProvider(LLMProvider):
    """
    Deterministic provider used to test the investigation bridge
    without requiring an LLM.
    """

    provider_name = "mock"

    def __init__(self):
        self.last_request: LLMRequest | None = None

    def generate(
        self,
        request: LLMRequest,
    ) -> LLMResponse:
        self.last_request = request

        return LLMResponse(
            text=(
                "The supplied evidence shows account discovery "
                "followed by credential-related activity."
            ),
            model=request.model,
            provider=self.provider_name,
            metadata={
                "mock": True,
            },
        )


def build_test_fact_packet() -> Dict[str, Any]:
    """
    Build a small deterministic Fact Packet matching the
    SentinelMesh investigation structure.

    The packet contains raw Windows event data so that the
    Evidence Gap Engine recognizes the event as available
    investigation evidence.
    """

    return {
        "incident": {
            "incident_id": "INC-LLM-TEST-001",
            "severity": "high",
            "incident_type": "correlated_suspicious_activity",
        },

        "correlation": {
            "rule_id": "CM-001",
            "time_window_seconds": 120,
        },

        "events": [
            {
                "source_record": 1001,
                "timestamp": "2026-10-03T10:00:00",
                "event_id": 4798,
                "source": "windows_security",
                "host": "TEST-HOST",
                "event_type": "User Account Enumeration",
                "raw_data": [
                    "Synthetic test event for Windows Security Event ID 4798.",
                    "User account enumeration activity observed on TEST-HOST.",
                ],
            }
        ],

        "detections": [
            {
                "detection_id": "SM-002",
                "rule_id": "SM-002",
                "rule_name": "User Account Enumeration",
            }
        ],

        "behaviors": [],

        "behavior_detections": [],

        "mitre": [
            {
                "technique_id": "T1087",
                "technique_name": "Account Discovery",
            }
        ],

        "entities": {
            "hosts": [
                "TEST-HOST"
            ],
            "users": [],
            "processes": [],
            "ips": [],
        },

        "risk": {
            "score": 60,
            "level": "high",
        },

        "evidence": [
            {
                "evidence_id": "EV-001",
                "source": "windows_security",
                "reference": "record:1001",
            }
        ],

        "known_facts": [
            "SM-002 was observed.",
            "Windows Security event 4798 was observed.",
        ],

        "uncertainties": [],

        "evidence_gaps": [],
    }


def test_mock_provider_integration():
    """
    Verify that Fact Packet → Prompt Builder → Provider works.
    """

    provider = MockLLMProvider()

    investigator = LLMInvestigator(
        provider=provider,
        model="qwen3:8b",
    )

    fact_packet = build_test_fact_packet()

    response = investigator.investigate(
        fact_packet=fact_packet,
        retrieval_context=None,
        analyst_question=(
            "Summarize the observed activity using only "
            "the supplied evidence."
        ),
    )

    assert response.provider == "mock"
    assert response.model == "qwen3:8b"
    assert response.text.strip()

    assert provider.last_request is not None

    prompt = provider.last_request.user_prompt

    assert "INC-LLM-TEST-001" in prompt
    assert "SM-002" in prompt
    assert "T1087" in prompt
    assert "EV-001" in prompt

    print("Fact Packet → Prompt Builder: PASS")
    print("Prompt → LLM Provider: PASS")
    print("Incident ID preserved: PASS")
    print("Detection reference preserved: PASS")
    print("MITRE reference preserved: PASS")
    print("Evidence reference preserved: PASS")


def test_insufficient_evidence():
    """
    Verify that the LLM is not called when the Fact Packet
    contains no actual investigation evidence.
    """

    provider = MockLLMProvider()

    investigator = LLMInvestigator(
        provider=provider,
        model="qwen3:8b",
    )

    fact_packet = {
        "incident": {
            "incident_id": "INC-NO-EVIDENCE",
        }
    }

    response = investigator.investigate(
        fact_packet=fact_packet,
    )

    assert response.text == "Insufficient evidence"
    assert response.metadata["llm_called"] is False
    assert provider.last_request is None

    print("Insufficient evidence fallback: PASS")
    print("LLM correctly not called: PASS")


def main():
    print("=" * 70)
    print("SENTINELMESH LLM INVESTIGATOR TEST")
    print("=" * 70)

    test_mock_provider_integration()
    test_insufficient_evidence()

    print("\n" + "=" * 70)
    print("ALL LLM INVESTIGATOR TESTS PASSED")
    print("=" * 70)


if __name__ == "__main__":
    main()