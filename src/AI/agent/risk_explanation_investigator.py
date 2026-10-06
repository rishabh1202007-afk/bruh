import json
from typing import Any, Dict
from .schemas import RISK_EXPLANATION_SCHEMA
from .llm_investigator import LLMInvestigator

class RiskExplanationInvestigator:
    def __init__(self, investigator: LLMInvestigator | None = None, model: str = "qwen3:8b"):
        self.investigator = investigator or LLMInvestigator(model=model, temperature=0.0)

    def investigate(self, fact_packet: Dict[str, Any], prompt: str) -> Dict[str, Any]:
        # Perform investigation
        response = self.investigator.investigate(
            fact_packet=fact_packet,
            analyst_question="Strict JSON following this schema: " + json.dumps(RISK_EXPLANATION_SCHEMA) + "\n\n" + prompt
        )
        
        # Parse and return
        return json.loads(response.text)
