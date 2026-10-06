from typing import Any, Dict

from ..fact_packet.builder import canonical_mitre_techniques
from ..llm.models import LLMRequest, LLMResponse
from ..llm.ollama_provider import OllamaProvider
from ..llm.provider import LLMProvider
from ..llm.prompt_builder import build_investigation_prompt


class LLMInvestigator:
    """
    LLM-backed investigation layer for SentinelMesh.

    This component does not perform detection, correlation, risk scoring,
    MITRE mapping, or attribution.

    Those decisions remain deterministic SentinelMesh functions.

    The LLM receives:
        - canonical Fact Packet
        - retrieved RAG context
        - optional analyst question

    The LLM is only responsible for explaining and navigating the
    supplied investigation context.
    """

    def __init__(
        self,
        provider: LLMProvider | None = None,
        model: str = "qwen3:8b",
        temperature: float = 0.0,
        max_output_tokens: int = 1200,
    ):
        self.provider = provider or OllamaProvider(
            default_model=model
        )

        self.model = model
        self.temperature = temperature
        self.max_output_tokens = max_output_tokens

    @staticmethod
    def _has_evidence(
        fact_packet: Dict[str, Any],
    ) -> bool:
        """
        Determine whether the Fact Packet contains investigation evidence.

        The incident ID itself is not considered evidence.
        """

        evidence_sections = (
            "evidence",
            "events",
            "detections",
            "behaviors",
            "behavior_detections",
            "mitre",
        )

        for section in evidence_sections:
            value = fact_packet.get(section)

            if section == "mitre":
                if canonical_mitre_techniques(value):
                    return True
                continue

            if isinstance(value, list) and value:
                return True

            if isinstance(value, dict) and value:
                return True

        return False

    @staticmethod
    def _incident_id(
        fact_packet: Dict[str, Any],
    ) -> str:
        """
        Extract the incident ID without treating it as evidence.
        """

        incident = fact_packet.get("incident", {})

        if isinstance(incident, dict):
            return str(
                incident.get(
                    "incident_id",
                    "UNKNOWN",
                )
            )

        return "UNKNOWN"

    def investigate(
        self,
        fact_packet: Dict[str, Any],
        retrieval_context: Any = None,
        analyst_question: str | None = None,
        request_metadata: Dict[str, Any] | None = None,
    ) -> LLMResponse:
        """
        Generate an evidence-grounded investigation response.

        request_metadata is used for provider-level controls such as
        structured JSON schemas. It does not alter the investigation
        evidence or Fact Packet.
        """

        incident_id = self._incident_id(fact_packet)

        if not self._has_evidence(fact_packet):
            return LLMResponse(
                text="Insufficient evidence",
                model=self.model,
                provider=self.provider.provider_name,
                metadata={
                    "incident_id": incident_id,
                    "status": "insufficient_evidence",
                    "llm_called": False,
                },
            )

        prompt = build_investigation_prompt(
            fact_packet=fact_packet,
            retrieval_context=retrieval_context,
            analyst_question=analyst_question,
        )

        metadata: Dict[str, Any] = {
            "incident_id": incident_id,
            "component": "llm_investigator",
        }

        if request_metadata:
            metadata.update(request_metadata)

        request = LLMRequest(
            system_prompt=(
                "You are the SentinelMesh Security Investigation "
                "Assistant. Follow the supplied investigation prompt "
                "exactly. The Fact Packet and retrieved context are the "
                "only authoritative sources for this investigation."
            ),
            user_prompt=prompt,
            model=self.model,
            temperature=self.temperature,
            max_output_tokens=self.max_output_tokens,
            metadata=metadata,
        )

        response = self.provider.generate(request)

        response.metadata.update(
            {
                "incident_id": incident_id,
                "status": "generated",
                "llm_called": True,
            }
        )

        return response


def investigate_with_ollama(
    fact_packet: Dict[str, Any],
    retrieval_context: Any = None,
    analyst_question: str | None = None,
) -> LLMResponse:
    """
    Convenience function using the local Ollama Qwen3 8B model.
    """

    investigator = LLMInvestigator(
        provider=OllamaProvider(
            default_model="qwen3:8b"
        )
    )

    return investigator.investigate(
        fact_packet=fact_packet,
        retrieval_context=retrieval_context,
        analyst_question=analyst_question,
    )


__all__ = [
    "LLMInvestigator",
    "investigate_with_ollama",
]