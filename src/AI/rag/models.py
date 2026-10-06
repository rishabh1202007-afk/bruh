"""
Data models used by the SentinelMesh AI RAG layer.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class RetrievedEvidence:
    """
    One piece of retrieved knowledge.

    This is knowledge/context retrieved from the RAG knowledge base.
    It is NOT incident evidence by itself.
    """

    source: str
    title: str
    content: str
    relevance: float = 0.0
    evidence_refs: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RetrievalResult:
    """
    Complete result returned by the SentinelMesh retriever.
    """

    query: str

    security_knowledge: List[RetrievedEvidence] = field(
        default_factory=list
    )

    sentinelmesh_knowledge: List[RetrievedEvidence] = field(
        default_factory=list
    )

    warnings: List[str] = field(
        default_factory=list
    )

    insufficient_evidence: bool = False

    def all_evidence(self) -> List[RetrievedEvidence]:
        """
        Return all retrieved knowledge documents.
        """

        return (
            self.security_knowledge
            + self.sentinelmesh_knowledge
        )