"""
LLM-based risk explanation generation component.
"""
import json
from typing import Any, Dict
from dataclasses import asdict
from .models import InvestigationResponse
from .risk_explanation import explain_risk_score
from .risk_explanation_investigator import RiskExplanationInvestigator
from .guardrails import inspect_untrusted_content

class LLMRiskExplainer:
    def __init__(self, investigator: RiskExplanationInvestigator):
        self.investigator = investigator

    def generate(self, fact_packet: Dict[str, Any]) -> Dict[str, Any]:
        """Generate grounded NL explanation."""

        risk_expl = explain_risk_score(fact_packet)
        if not risk_expl or risk_expl.insufficient_evidence:
            return {
                "status": "insufficient_evidence",
                "summary": "Insufficient evidence for risk explanation.",
                "deterministic_explanation": risk_expl.to_dict() if risk_expl else None
            }

        # 2. Guardrails (Prompt Injection / Untrusted content)
        warnings = inspect_untrusted_content(fact_packet)
        if warnings:
            return {
                "status": "blocked",
                "summary": "Safety guardrails blocked risk explanation.",
                "safety_warnings": warnings,
                "deterministic_explanation": risk_expl.to_dict()
            }

        # 3. Controlled Prompt
        prompt = f"""
        Provide a concise, analyst-facing natural language explanation of this risk assessment.

        AUTHORITATIVE DETERMINISTIC RISK:
        {json.dumps(risk_expl.to_dict(), indent=2)}

        RULES:
        1. Base explanation STRICTLY on Fact Packet evidence references.
        2. Do NOT change risk score/level.
        """

        # Generate using our new investigator
        try:
            response = self.investigator.investigate(
                fact_packet=fact_packet,
                prompt=prompt
            )
        except Exception:
             return {
                "status": "insufficient_evidence",
                "summary": "LLM failed, using deterministic explanation.",
                "deterministic_explanation": risk_expl.to_dict()
            }

        return response
