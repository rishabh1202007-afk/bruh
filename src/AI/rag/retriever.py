"""
Deterministic retrieval engine for SentinelMesh AI.

The retriever searches two separate knowledge sources:

1. General security knowledge
2. SentinelMesh-specific knowledge

This layer does not use an LLM and does not make security
conclusions.
"""

import re
from typing import Iterable, List

from .knowledge_base import (
    KnowledgeDocument,
    get_security_knowledge,
    get_sentinelmesh_knowledge,
)

from .models import (
    RetrievedEvidence,
    RetrievalResult,
)


STOP_WORDS = {
    "a",
    "an",
    "and",
    "are",
    "as",
    "at",
    "be",
    "by",
    "for",
    "from",
    "in",
    "is",
    "of",
    "on",
    "or",
    "the",
    "to",
    "with",
    "what",
    "why",
    "how",
    "this",
    "that",
    "about",
    "activity",
    "event",
}


def _normalize(text: str) -> List[str]:
    """
    Convert text into searchable tokens.
    """

    if not text:
        return []

    text = str(text).lower()

    tokens = re.findall(
        r"[a-z0-9]+(?:[-.][a-z0-9]+)*",
        text,
    )

    return [
        token
        for token in tokens
        if token not in STOP_WORDS
    ]


def _document_text(
    document: KnowledgeDocument,
) -> str:
    """
    Build the searchable representation of a document.
    """

    metadata_text = " ".join(
        str(value)
        for value in document.metadata.values()
    )

    return " ".join(
        [
            document.document_id,
            document.title,
            document.content,
            document.source_type,
            metadata_text,
        ]
    )


def _is_identifier(token: str) -> bool:
    """
    Return True for SentinelMesh and MITRE-style identifiers.
    """

    patterns = [
        r"^SM-\d+$",
        r"^BT-\d+$",
        r"^CM-\d+$",
        r"^SEC-[A-Z0-9-]+$",
        r"^T\d+(?:\.\d+)?$",
    ]

    return any(
        re.fullmatch(pattern, token, re.IGNORECASE)
        for pattern in patterns
    )


def _score_document(
    query_tokens: Iterable[str],
    document: KnowledgeDocument,
) -> float:
    """
    Calculate deterministic token-overlap relevance.

    Identifier matches receive higher weight because identifiers such
    as SM-002, BT-003, CM-001 and T1555.004 are strong signals.
    """

    query_tokens = list(query_tokens)

    if not query_tokens:
        return 0.0

    document_tokens = set(
        _normalize(
            _document_text(document)
        )
    )

    if not document_tokens:
        return 0.0

    score = 0.0

    for token in query_tokens:

        if token not in document_tokens:
            continue

        if _is_identifier(token):
            score += 3.0
        else:
            score += 1.0

    return score / len(query_tokens)


def _rank_documents(
    query: str,
    documents: Iterable[KnowledgeDocument],
    top_k: int,
) -> List[RetrievedEvidence]:
    """
    Rank knowledge documents for a query.
    """

    query_tokens = _normalize(query)

    scored_documents = []

    for document in documents:

        score = _score_document(
            query_tokens,
            document,
        )

        if score <= 0:
            continue

        scored_documents.append(
            (
                score,
                document,
            )
        )

    # Deterministic ordering.
    scored_documents.sort(
        key=lambda item: (
            -item[0],
            item[1].document_id,
        )
    )

    results: List[RetrievedEvidence] = []

    for score, document in scored_documents[:top_k]:

        results.append(
            RetrievedEvidence(
                source=document.source_type,
                title=document.title,
                content=document.content,
                relevance=round(score, 4),
                evidence_refs=[
                    document.document_id
                ],
                metadata=dict(document.metadata),
            )
        )

    return results


def retrieve(
    query: str,
    top_k: int = 5,
) -> RetrievalResult:
    """
    Retrieve relevant knowledge from both knowledge bases.

    Parameters
    ----------
    query:
        Search or investigation query.

    top_k:
        Maximum number of documents returned from each knowledge source.

    Returns
    -------
    RetrievalResult
        Structured retrieval result containing provenance.
    """

    if not query or not query.strip():

        return RetrievalResult(
            query=query,
            security_knowledge=[],
            sentinelmesh_knowledge=[],
            warnings=[
                "Retrieval query is empty."
            ],
            insufficient_evidence=True,
        )

    if top_k <= 0:

        return RetrievalResult(
            query=query,
            security_knowledge=[],
            sentinelmesh_knowledge=[],
            warnings=[
                "top_k must be greater than zero."
            ],
            insufficient_evidence=True,
        )

    security_documents = (
        get_security_knowledge()
    )

    sentinelmesh_documents = (
        get_sentinelmesh_knowledge()
    )

    security_results = _rank_documents(
        query=query,
        documents=security_documents,
        top_k=top_k,
    )

    sentinelmesh_results = _rank_documents(
        query=query,
        documents=sentinelmesh_documents,
        top_k=top_k,
    )

    warnings: List[str] = []

    if not security_results:
        warnings.append(
            "No matching general security knowledge was retrieved."
        )

    if not sentinelmesh_results:
        warnings.append(
            "No matching SentinelMesh-specific knowledge was retrieved."
        )

    insufficient_evidence = (
        not security_results
        and not sentinelmesh_results
    )

    return RetrievalResult(
        query=query,
        security_knowledge=security_results,
        sentinelmesh_knowledge=sentinelmesh_results,
        warnings=warnings,
        insufficient_evidence=insufficient_evidence,
    )


__all__ = [
    "retrieve",
]