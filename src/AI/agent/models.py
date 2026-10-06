from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List


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
    supporting_evidence_refs: List[str] = field(default_factory=list)


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

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the response into a JSON-serializable dictionary.
        """

        return asdict(self)


__all__ = [
    "EvidenceClaim",
    "KnowledgeContext",
    "InvestigationStep",
    "InvestigationResponse",
]