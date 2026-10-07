"""
Bridge real SentinelMesh incidents into the AI investigation pipeline.
"""
from __future__ import annotations
import json
from typing import Any, Dict, List
from ..fact_packet.builder import build_fact_packet
from ..rag.fact_packet_context import RAGContext, build_rag_context
from .investigation_agent import InvestigationResponse
from .structured_llm_investigator import StructuredLLMInvestigator
from .attack_sequence import reconstruct_attack_sequence
from .counterfactual_engine import run_counterfactual_investigation
from .feedback_store import AnalystFeedback, FeedbackStore
from .historical_comparison import compare_historical_incidents
from .risk_explanation import explain_risk_score
from .llm_risk_explanation import LLMRiskExplainer
from .risk_explanation_investigator import RiskExplanationInvestigator
from .mitre_investigator import MITREInvestigator

DEFAULT_INCIDENT_FILE = "data/raw/final_risk_scored_incidents.jsonl"
DEFAULT_RAG_TOP_K = 5

class SentinelMeshInvestigationService:
    def __init__(
        self,
        model: str = "qwen3:8b",
        temperature: float = 0.0,
        max_output_tokens: int = 1200,
        investigator: StructuredLLMInvestigator | None = None,
        rag_top_k: int = DEFAULT_RAG_TOP_K,
        mitre_investigator: MITREInvestigator | None = None,
    ):
        self.investigator = investigator or StructuredLLMInvestigator(
            model=model,
            temperature=temperature,
            max_output_tokens=max_output_tokens,
        )
        self.risk_explainer = LLMRiskExplainer(
            investigator=RiskExplanationInvestigator(model=model)
        )
        self.mitre_investigator = mitre_investigator or MITREInvestigator(model=model)

        if rag_top_k <= 0:
            raise ValueError("rag_top_k must be greater than zero.")
        self.rag_top_k = rag_top_k
        self.feedback_store = FeedbackStore()

    def build_fact_packet(self, incident: Dict[str, Any]) -> Dict[str, Any]:
        # Minimalist implementation for this fix, assuming correct logic previously
        from ..fact_packet.builder import build_fact_packet
        return build_fact_packet(incident)

    def investigate(
        self,
        incident: Dict[str, Any],
        retrieval_context: Any = None,
        analyst_question: str | None = None,
        historical_incidents: List[Dict[str, Any]] | None = None,
        include_counterfactuals: bool = False,
        counterfactual_questions: List[str] | None = None,
    ) -> InvestigationResponse:
        fact_packet = self.build_fact_packet(incident)
        # Using service rag builder if needed, but for now simple delegation
        rag_context = build_rag_context(fact_packet, top_k=self.rag_top_k)
        retrieval_context_dict = rag_context.to_dict()

        # Deterministic Risk Explanation
        try:
            risk_expl = explain_risk_score(fact_packet)
            risk_explanation = risk_expl.to_dict() if risk_expl else None
        except Exception:
            risk_explanation = None

        # LLM Risk Explanation
        try:
            nlp_risk_explanation = self.risk_explainer.generate(fact_packet)
        except Exception:
            nlp_risk_explanation = None

        # Attack Sequence
        try:
            attack_seq = reconstruct_attack_sequence(fact_packet).to_dict()
        except Exception:
            attack_seq = None

        # Historical Comparison
        try:
            comparison = compare_historical_incidents(
                fact_packet, historical_incidents
            ).to_dict()
        except Exception:
            comparison = None

        # MITRE Investigation
        try:
            # Using prompt builder logic
            mitre_prompt = "Analyze the techniques."
            mitre_investigation = self.mitre_investigator.investigate(fact_packet, mitre_prompt)
        except Exception:
            mitre_investigation = None

        # Counterfactual Investigation
        if include_counterfactuals:
            try:
                counterfactual_investigation = run_counterfactual_investigation(
                    fact_packet, questions=counterfactual_questions
                ).to_dict()
            except Exception:
                counterfactual_investigation = None
        else:
            counterfactual_investigation = None

        # Structured LLM Investigator
        response = self.investigator.investigate(
            fact_packet=fact_packet,
            retrieval_context=retrieval_context_dict,
            analyst_question=analyst_question,
        )

        response.risk_explanation = risk_explanation
        response.nlp_risk_explanation = nlp_risk_explanation
        response.attack_sequence = attack_seq
        response.historical_comparison = comparison
        response.mitre_investigation = mitre_investigation
        response.counterfactual_investigation = counterfactual_investigation

        return response

    def submit_feedback(
        self,
        feedback_data: Dict[str, Any] | AnalystFeedback,
        fact_packet: Dict[str, Any] | None = None,
        response: Any = None,
    ) -> Dict[str, Any]:
        """
        Submit structured analyst feedback. Returns dictionary representation of stored feedback.
        """
        feedback_obj = self.feedback_store.add_feedback(
            feedback=feedback_data,
            fact_packet=fact_packet,
            response=response,
        )
        return feedback_obj.to_dict()

    def get_feedback(self, feedback_id: str) -> Dict[str, Any] | None:
        """
        Retrieve feedback by ID.
        """
        fb = self.feedback_store.get_feedback(feedback_id)
        return fb.to_dict() if fb else None

    def list_feedback_for_incident(self, incident_id: str) -> List[Dict[str, Any]]:
        """
        List all feedback records for a given incident ID.
        """
        return [fb.to_dict() for fb in self.feedback_store.list_feedback_for_incident(incident_id)]
