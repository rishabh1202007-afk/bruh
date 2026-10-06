from typing import Any, Dict, List, Set
from .investigation_agent import InvestigationResponse
from .llm_investigator import LLMInvestigator

class BaseStructuredLLMInvestigator:
    def __init__(
        self,
        investigator: LLMInvestigator | None = None,
        model: str = "qwen3:8b",
        temperature: float = 0.0,
        max_output_tokens: int = 1200,
        structured_response_instruction: str = "",
        required_fields: Set[str] = set(),
        allowed_statuses: Set[str] = set(),
    ):
        self.investigator = investigator or LLMInvestigator(
            model=model,
            temperature=temperature,
            max_output_tokens=max_output_tokens,
        )
        self.structured_response_instruction = structured_response_instruction
        self.required_fields = required_fields
        self.allowed_statuses = allowed_statuses
