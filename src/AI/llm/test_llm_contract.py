from .models import LLMRequest, LLMResponse
from .provider import LLMProvider
from .prompt_builder import (
    SYSTEM_PROMPT,
    build_investigation_prompt,
)


class MockLLMProvider(LLMProvider):
    """
    Deterministic provider used only for contract testing.

    This test does NOT call Azure or any external API.
    """

    def generate(
        self,
        request: LLMRequest,
    ) -> LLMResponse:

        assert request.system_prompt
        assert request.user_prompt
        assert request.model

        return LLMResponse(
            text=(
                "Insufficient evidence."
            ),
            model=request.model,
            provider="mock",
            request_id="mock-request-001",
        )


def main():

    fact_packet = {
        "incident": {
            "incident_id": "INC-TEST-001",
            "severity": "high",
        },
        "detections": [
            {
                "detection_id": "SM-002",
                "rule_name": "User Account Enumeration",
            }
        ],
        "evidence": [
            {
                "evidence_id": "EV-001",
                "source": "windows_security",
            }
        ],
    }

    retrieval_context = {
        "security_knowledge": [
            {
                "title": "Account Discovery",
                "knowledge_refs": [
                    "SEC-ACCOUNT-DISCOVERY"
                ],
            }
        ],
        "sentinelmesh_knowledge": [
            {
                "title": "SM-002 User Account Enumeration",
                "knowledge_refs": [
                    "SM-RULE-002"
                ],
            }
        ],
    }

    # ---------------------------------------------------------
    # Prompt construction
    # ---------------------------------------------------------

    user_prompt = build_investigation_prompt(
        fact_packet=fact_packet,
        retrieval_context=retrieval_context,
        analyst_question=(
            "What evidence supports this incident?"
        ),
    )

    assert SYSTEM_PROMPT
    assert "INC-TEST-001" in user_prompt
    assert "SM-002" in user_prompt
    assert "EV-001" in user_prompt
    assert "SEC-ACCOUNT-DISCOVERY" in user_prompt
    assert "SM-RULE-002" in user_prompt

    print(
        "Prompt construction: PASS"
    )

    # ---------------------------------------------------------
    # Provider contract
    # ---------------------------------------------------------

    request = LLMRequest(
        system_prompt=SYSTEM_PROMPT,
        user_prompt=user_prompt,
        model="test-model",
    )

    provider = MockLLMProvider()

    response = provider.generate(
        request
    )

    assert isinstance(
        response,
        LLMResponse,
    )

    assert response.provider == "mock"
    assert response.model == "test-model"
    assert response.text == (
        "Insufficient evidence."
    )

    print(
        "LLM provider contract: PASS"
    )

    # ---------------------------------------------------------
    # No secrets in prompt
    # ---------------------------------------------------------

    forbidden = [
        "AZURE_OPENAI_API_KEY",
        "api_key=",
        "Authorization: Bearer",
    ]

    for value in forbidden:
        assert value not in user_prompt

    print(
        "Prompt secret isolation: PASS"
    )

    print(
        "ALL LLM CONTRACT TESTS PASSED"
    )


if __name__ == "__main__":
    main()