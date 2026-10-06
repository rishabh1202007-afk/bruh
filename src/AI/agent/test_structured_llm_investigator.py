from typing import Any, Dict

from ..llm.models import LLMRequest, LLMResponse
from ..llm.provider import LLMProvider
from .llm_investigator import LLMInvestigator
from .structured_llm_investigator import (
    StructuredLLMInvestigator,
)
from .test_llm_investigator import (
    build_test_fact_packet,
)


class MockStructuredLLMProvider(LLMProvider):
    """
    Deterministic mock provider.

    This test does not require Ollama.
    """

    provider_name = "mock"

    def __init__(
        self,
        response_text: str,
    ):
        self.response_text = response_text
        self.called = False

    def generate(
        self,
        request: LLMRequest,
    ) -> LLMResponse:
        self.called = True

        return LLMResponse(
            text=self.response_text,
            model=request.model,
            provider=self.provider_name,
            request_id="mock-request-001",
            metadata={},
        )


def valid_response_json() -> str:
    return """
{
  "status": "investigating",
  "summary": "Detection SM-002 was observed.",
  "observed_facts": [
    {
      "claim": "Detection SM-002 was observed.",
      "evidence_refs": ["EV-001"],
      "source": "fact_packet"
    }
  ],
  "knowledge_context": [],
  "uncertainties": [
    "The supplied evidence does not establish attacker intent."
  ],
  "evidence_gaps": [
    "No additional behavioral evidence was supplied."
  ],
  "next_investigation_steps": [
    {
      "action": "Review the supplied Windows Security event.",
      "rationale": "The detection is directly associated with the supplied evidence.",
      "supporting_evidence_refs": ["EV-001"]
    }
  ],
  "safety_warnings": [],
  "grounded": true,
  "insufficient_evidence": false
}
"""


def invalid_reference_response_json() -> str:
    return """
{
  "status": "investigating",
  "summary": "Unsupported claim.",
  "observed_facts": [
    {
      "claim": "An unknown IP address was involved.",
      "evidence_refs": ["FAKE-EVIDENCE-999"],
      "source": "fact_packet"
    }
  ],
  "knowledge_context": [],
  "uncertainties": [],
  "evidence_gaps": [],
  "next_investigation_steps": [],
  "safety_warnings": [],
  "grounded": true,
  "insufficient_evidence": false
}
"""


def invalid_schema_response_json() -> str:
    return """
{
  "status": "investigating",
  "summary": "Invalid response."
}
"""


def test_valid_structured_response():
    fact_packet = build_test_fact_packet()

    provider = MockStructuredLLMProvider(
        valid_response_json()
    )

    investigator = StructuredLLMInvestigator(
        investigator=LLMInvestigator(
            provider=provider,
            model="qwen3:8b",
            temperature=0.0,
            max_output_tokens=500,
        )
    )

    response = investigator.investigate(
        fact_packet=fact_packet
    )

    assert provider.called is True
    assert response.incident_id == "INC-LLM-TEST-001"
    assert response.status == "investigating"
    assert response.grounded is True
    assert response.insufficient_evidence is False
    assert len(response.observed_facts) == 1
    assert (
        response.observed_facts[0]["evidence_refs"]
        == ["EV-001"]
    )

    print("Valid structured response: PASS")


def test_unsupported_reference_is_rejected():
    fact_packet = build_test_fact_packet()

    provider = MockStructuredLLMProvider(
        invalid_reference_response_json()
    )

    investigator = StructuredLLMInvestigator(
        investigator=LLMInvestigator(
            provider=provider,
            model="qwen3:8b",
            temperature=0.0,
            max_output_tokens=500,
        )
    )

    response = investigator.investigate(
        fact_packet=fact_packet
    )

    assert provider.called is True
    assert response.grounded is False
    assert response.status == "validation_failed"

    print(
        "Unsupported evidence reference rejected: PASS"
    )


def test_invalid_schema_is_rejected():
    fact_packet = build_test_fact_packet()

    provider = MockStructuredLLMProvider(
        invalid_schema_response_json()
    )

    investigator = StructuredLLMInvestigator(
        investigator=LLMInvestigator(
            provider=provider,
            model="qwen3:8b",
            temperature=0.0,
            max_output_tokens=500,
        )
    )

    response = investigator.investigate(
        fact_packet=fact_packet
    )

    assert provider.called is True
    assert response.grounded is False
    assert response.status == "validation_failed"

    print(
        "Invalid schema rejected: PASS"
    )


def test_insufficient_evidence():
    fact_packet: Dict[str, Any] = {
        "incident": {
            "incident_id": "INC-EMPTY-001"
        },
        "evidence": [],
        "events": [],
        "detections": [],
        "behaviors": [],
        "behavior_detections": [],
        "mitre": [],
    }

    provider = MockStructuredLLMProvider(
        valid_response_json()
    )

    investigator = StructuredLLMInvestigator(
        investigator=LLMInvestigator(
            provider=provider,
            model="qwen3:8b",
            temperature=0.0,
            max_output_tokens=500,
        )
    )

    response = investigator.investigate(
        fact_packet=fact_packet
    )

    assert provider.called is False
    assert response.status == "insufficient_evidence"
    assert response.insufficient_evidence is True
    assert response.summary == "Insufficient evidence"

    print(
        "Insufficient evidence fallback: PASS"
    )
    print(
        "LLM correctly not called: PASS"
    )


def main():
    print("=" * 70)
    print(
        "SENTINELMESH STRUCTURED LLM INVESTIGATOR TEST"
    )
    print("=" * 70)

    test_valid_structured_response()
    test_unsupported_reference_is_rejected()
    test_invalid_schema_is_rejected()
    test_insufficient_evidence()

    print("\n" + "=" * 70)
    print(
        "ALL STRUCTURED LLM INVESTIGATOR TESTS PASSED"
    )
    print("=" * 70)


if __name__ == "__main__":
    main()