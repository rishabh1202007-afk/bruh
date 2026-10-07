from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class EvidenceClaim:
    """
    A factual statement derived from the SentinelMesh Fact Packet.

    Every factual claim should be traceable to one or more
    evidence references.
    """

    claim: str
    evidence_refs: List[str] = field(default_factory=list)
    source: str = "fact_packet"


@dataclass
class KnowledgeContext:
    """
    Security knowledge retrieved from the RAG knowledge base.
    """

    statement: str
    knowledge_refs: List[str] = field(default_factory=list)
    source: str = "rag"


@dataclass
class InvestigationStep:
    """
    A recommended investigation action.

    This is a recommendation for the analyst, not a claim that
    the action has already been performed.
    """

    action: str
    rationale: str = ""
    priority: str = "medium"
    supporting_evidence_refs: List[str] = field(default_factory=list)
    mitre_refs: List[str] = field(default_factory=list)
    evidence_gap_refs: List[str] = field(default_factory=list)


@dataclass
class CounterfactualScenario:
    """
    An evidence-grounded analytical scenario exploring hypothetical changes.
    Does not modify the actual incident or risk score.
    """

    scenario_id: str
    scenario_type: str
    question: str
    baseline_assessment: Dict[str, Any]
    hypothetical_change: Dict[str, Any]
    affected_evidence: List[str] = field(default_factory=list)
    expected_effect: str = ""
    evidence_required: List[str] = field(default_factory=list)
    conclusions_that_remain_valid: List[str] = field(default_factory=list)
    conclusions_that_would_become_uncertain: List[str] = field(default_factory=list)
    risk_impact: Dict[str, Any] = field(default_factory=dict)
    confidence: str = "medium"
    evidence_refs: List[str] = field(default_factory=list)
    gap_refs: List[str] = field(default_factory=list)
    mitre_refs: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)
    status: str = "valid"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CounterfactualInvestigationResult:
    """
    Structured outcome of counterfactual scenario analysis.
    """

    incident_id: str
    status: str = "complete"
    scenarios: List[CounterfactualScenario] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)
    grounded: bool = True
    insufficient_evidence: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AnalystFeedback:
    """
    Structured analyst feedback on an AI investigation response.
    Does not modify deterministic security rules, risk scores, or evidence.
    """

    feedback_id: str
    incident_id: str
    target_component: str
    feedback_type: str
    analyst_id: Optional[str] = None
    timestamp: Optional[str] = None
    rating: Optional[int] = None
    comment: Optional[str] = None
    referenced_response_field: Optional[str] = None
    evidence_refs: List[str] = field(default_factory=list)
    recommendation_refs: List[str] = field(default_factory=list)
    historical_comparison_refs: List[str] = field(default_factory=list)
    counterfactual_refs: List[str] = field(default_factory=list)
    model_version: Optional[str] = None
    created_at: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class InvestigationResponse:
    """
    Structured output from the SentinelMesh AI investigation agent.
    """

    incident_id: str
    status: str
    summary: str

    observed_facts: List[EvidenceClaim] = field(
        default_factory=list
    )

    knowledge_context: List[KnowledgeContext] = field(
        default_factory=list
    )

    uncertainties: List[str] = field(
        default_factory=list
    )

    evidence_gaps: List[str] = field(
        default_factory=list
    )

    next_investigation_steps: List[InvestigationStep] = field(
        default_factory=list
    )

    safety_warnings: List[str] = field(
        default_factory=list
    )

    grounded: bool = True

    insufficient_evidence: bool = False

    visibility_score: int | None = None

    historical_comparison: Dict[str, Any] | None = None

    attack_sequence: Dict[str, Any] | None = None

    risk_explanation: Dict[str, Any] | None = None

    nlp_risk_explanation: Dict[str, Any] | None = None
    mitre_investigation: Dict[str, Any] | None = None

    counterfactual_investigation: Dict[str, Any] | None = None
    feedback_metadata: Dict[str, Any] | None = None

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the response into a JSON-serializable dictionary.
        """

        return asdict(self)


__all__ = [
    "EvidenceClaim",
    "KnowledgeContext",
    "InvestigationStep",
    "CounterfactualScenario",
    "CounterfactualInvestigationResult",
    "AnalystFeedback",
    "InvestigationResponse",
]
