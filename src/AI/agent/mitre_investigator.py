import json
from typing import Any, Dict
from .llm_investigator import LLMInvestigator
from .schemas import MITRE_INVESTIGATION_SCHEMA
# Import from the correct top-level package
from src.AI.fact_packet.builder import canonical_mitre_techniques

class MITREInvestigator:
    def __init__(self, investigator: LLMInvestigator | None = None, model: str = "qwen3:8b"):
        self.investigator = investigator or LLMInvestigator(model=model, temperature=0.0)

    def investigate(self, fact_packet: Dict[str, Any], prompt: str) -> Dict[str, Any]:
        deterministic_techniques = canonical_mitre_techniques(fact_packet.get("mitre", {}))

        if not deterministic_techniques:
            return {
                "status": "insufficient_evidence",
                "observed_techniques": [],
                "knowledge_context": [],
                "evidence_gaps": ["No deterministic MITRE techniques found in fact packet."],
                "attribution_status": "none",
                "synthetic_telemetry": False,
                "warnings": [],
                "next_investigation_steps": []
            }

        # Perform investigation
        response = self.investigator.investigate(
            fact_packet=fact_packet,
            analyst_question="Strict JSON following this schema: " + json.dumps(MITRE_INVESTIGATION_SCHEMA) + "\n\n" + prompt
        )

        result = json.loads(response.text)

        # Anti-invention safety check
        deterministic_ids = {t["technique_id"] for t in deterministic_techniques}
        validated_techniques = []
        for t in result.get("observed_techniques", []):
            if t["technique_id"] in deterministic_ids:
                validated_techniques.append(t)
        result["observed_techniques"] = validated_techniques

        return result
