"""
Fact Packet -> RAG Context Builder for SentinelMesh.

This module connects the deterministic SentinelMesh investigation
pipeline to the RAG layer.

The Fact Packet is the source of incident facts.

Retrieved knowledge is contextual information only and must not be
treated as incident evidence.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, Iterable, List, Set, Tuple

from ..fact_packet.builder import canonical_mitre_techniques
from .models import RetrievedEvidence, RetrievalResult
from .retriever import retrieve


MAX_QUERIES = 12
DEFAULT_TOP_K = 5


@dataclass
class RAGContext:
    """
    Evidence-grounded retrieval context prepared from a Fact Packet.
    """

    incident_id: str

    queries: List[str] = field(
        default_factory=list
    )

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

    def all_knowledge(self) -> List[RetrievedEvidence]:
        """
        Return all retrieved knowledge.
        """

        return (
            self.security_knowledge
            + self.sentinelmesh_knowledge
        )

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the RAG context into a JSON-serializable dictionary.
        """

        return {
            "incident_id": self.incident_id,
            "queries": list(self.queries),
            "security_knowledge": [
                asdict(item)
                for item in self.security_knowledge
            ],
            "sentinelmesh_knowledge": [
                asdict(item)
                for item in self.sentinelmesh_knowledge
            ],
            "warnings": list(self.warnings),
            "insufficient_evidence": (
                self.insufficient_evidence
            ),
        }


def _as_list(value: Any) -> List[Any]:
    """
    Safely convert a value into a list.
    """

    if value is None:
        return []

    if isinstance(value, list):
        return value

    if isinstance(value, tuple):
        return list(value)

    return [value]


def _string(value: Any) -> str:
    """
    Safely convert a value into a searchable string.
    """

    if value is None:
        return ""

    if isinstance(value, bool):
        return str(value).lower()

    return str(value).strip()


def _add_query(
    queries: List[str],
    seen: Set[str],
    query: str,
) -> None:
    """
    Add a normalized query while preserving insertion order.
    """

    query = " ".join(
        _string(query).split()
    ).strip()

    if not query:
        return

    key = query.lower()

    if key in seen:
        return

    if len(queries) >= MAX_QUERIES:
        return

    queries.append(query)
    seen.add(key)


def _extract_incident_queries(
    fact_packet: Dict[str, Any],
    queries: List[str],
    seen: Set[str],
) -> None:
    """
    Extract high-level incident and correlation queries.
    """

    incident = fact_packet.get(
        "incident",
        {},
    )

    if isinstance(incident, dict):

        incident_type = _string(
            incident.get("incident_type")
        )

        severity = _string(
            incident.get("severity")
        )

        correlation_rule = _string(
            incident.get("correlation_rule")
        )

        rule_name = _string(
            incident.get("rule_name")
        )

        if correlation_rule and rule_name:

            _add_query(
                queries,
                seen,
                f"{correlation_rule} {rule_name}",
            )

        elif correlation_rule:

            _add_query(
                queries,
                seen,
                correlation_rule,
            )

        if incident_type:

            _add_query(
                queries,
                seen,
                incident_type,
            )

        if severity and incident_type:

            _add_query(
                queries,
                seen,
                f"{severity} {incident_type}",
            )

    correlation = fact_packet.get(
        "correlation",
        {},
    )

    if isinstance(correlation, dict):

        correlation_rule = _string(
            correlation.get("correlation_rule")
        )

        rule_name = _string(
            correlation.get("rule_name")
        )

        if correlation_rule and rule_name:

            _add_query(
                queries,
                seen,
                f"{correlation_rule} {rule_name}",
            )

        elif correlation_rule:

            _add_query(
                queries,
                seen,
                correlation_rule,
            )


def _extract_detection_queries(
    fact_packet: Dict[str, Any],
    queries: List[str],
    seen: Set[str],
) -> None:
    """
    Extract SentinelMesh detection information.
    """

    detections = _as_list(
        fact_packet.get("detections")
    )

    for detection in detections:

        if not isinstance(detection, dict):
            continue

        rule_id = _string(
            detection.get("rule_id")
        )

        rule_name = _string(
            detection.get("rule_name")
        )

        category = _string(
            detection.get("category")
        )

        event_id = _string(
            detection.get("event_id")
        )

        query_parts = [
            value
            for value in [
                rule_id,
                rule_name,
                category,
                event_id,
            ]
            if value
        ]

        if query_parts:

            _add_query(
                queries,
                seen,
                " ".join(query_parts),
            )


def _extract_behavior_queries(
    fact_packet: Dict[str, Any],
    queries: List[str],
    seen: Set[str],
) -> None:
    """
    Extract behavior and behavioral-detection information.
    """

    behaviors = _as_list(
        fact_packet.get("behaviors")
    )

    for behavior in behaviors:

        if not isinstance(behavior, dict):
            continue

        behavior_type = _string(
            behavior.get("behavior_type")
        )

        threat_profile = _string(
            behavior.get("threat_profile")
        )

        description = _string(
            behavior.get("description")
        )

        query_parts = [
            value
            for value in [
                behavior_type,
                threat_profile,
                description,
            ]
            if value
        ]

        if query_parts:

            _add_query(
                queries,
                seen,
                " ".join(query_parts),
            )

    behavior_detections = _as_list(
        fact_packet.get("behavior_detections")
    )

    for detection in behavior_detections:

        if not isinstance(detection, dict):
            continue

        rule_id = _string(
            detection.get("rule_id")
        )

        rule_name = _string(
            detection.get("rule_name")
        )

        category = _string(
            detection.get("category")
        )

        behavior_type = _string(
            detection.get("behavior_type")
        )

        query_parts = [
            value
            for value in [
                rule_id,
                rule_name,
                behavior_type,
                category,
            ]
            if value
        ]

        if query_parts:

            _add_query(
                queries,
                seen,
                " ".join(query_parts),
            )


def _extract_mitre_queries(
    fact_packet: Dict[str, Any],
    queries: List[str],
    seen: Set[str],
) -> None:
    """
    Extract MITRE ATT&CK information.

    MITRE identifiers are retrieval signals only.
    Their presence does not prove malicious activity.
    """

    mitre = fact_packet.get(
        "mitre",
        {},
    )

    techniques = canonical_mitre_techniques(mitre)

    technique_ids: List[str] = []

    for technique in techniques:

        if isinstance(technique, dict):

            technique_id = _string(
                technique.get("technique_id")
            )

            technique_name = _string(
                technique.get("technique_name")
            )

            tactic = _string(
                technique.get("tactic")
            )

            query_parts = [
                value
                for value in [
                    technique_id,
                    technique_name,
                    tactic,
                ]
                if value
            ]

            if query_parts:

                _add_query(
                    queries,
                    seen,
                    " ".join(query_parts),
                )

            if technique_id:
                technique_ids.append(
                    technique_id
                )

        else:

            technique_id = _string(
                technique
            )

            if technique_id:
                technique_ids.append(
                    technique_id
                )

    if technique_ids:

        _add_query(
            queries,
            seen,
            "MITRE " + " ".join(technique_ids),
        )


def _extract_threat_profile_queries(
    fact_packet: Dict[str, Any],
    queries: List[str],
    seen: Set[str],
) -> None:
    """
    Extract threat-profile context.

    Profile names are retrieval context only.
    """

    profiles = _as_list(
        fact_packet.get("threat_profiles")
    )

    for profile in profiles:

        if not isinstance(profile, dict):
            continue

        profile_name = _string(
            profile.get("profile")
        )

        if not profile_name:

            profile_name = _string(
                profile.get("name")
            )

        attribution_status = _string(
            profile.get("attribution_status")
        )

        if profile_name:

            _add_query(
                queries,
                seen,
                f"threat profile {profile_name}",
            )

        if attribution_status:

            _add_query(
                queries,
                seen,
                attribution_status,
            )


def _extract_risk_queries(
    fact_packet: Dict[str, Any],
    queries: List[str],
    seen: Set[str],
) -> None:
    """
    Extract risk-factor context.

    Risk scores are SentinelMesh scoring output and are not
    themselves proof of malicious activity.
    """

    risk = fact_packet.get(
        "risk",
        {},
    )

    if not isinstance(risk, dict):
        return

    factors = _as_list(
        risk.get("factors")
    )

    for factor in factors:

        if not isinstance(factor, dict):
            continue

        factor_name = _string(
            factor.get("factor")
        )

        reason = _string(
            factor.get("reason")
        )

        if factor_name and reason:

            _add_query(
                queries,
                seen,
                f"{factor_name} {reason}",
            )

        elif factor_name:

            _add_query(
                queries,
                seen,
                factor_name,
            )


def _extract_evidence_gap_queries(
    fact_packet: Dict[str, Any],
    queries: List[str],
    seen: Set[str],
) -> None:
    """
    Convert known evidence gaps into retrieval questions.
    """

    evidence_gaps = _as_list(
        fact_packet.get("evidence_gaps")
    )

    for gap in evidence_gaps:

        if isinstance(gap, dict):

            description = _string(
                gap.get("description")
            )

            category = _string(
                gap.get("category")
            )

            query_parts = [
                value
                for value in [
                    category,
                    description,
                ]
                if value
            ]

        else:

            query_parts = [
                _string(gap)
            ]

        query_parts = [
            value
            for value in query_parts
            if value
        ]

        if query_parts:

            _add_query(
                queries,
                seen,
                "evidence gap " + " ".join(query_parts),
            )


def build_investigation_queries(
    fact_packet: Dict[str, Any],
) -> List[str]:
    """
    Build bounded deterministic retrieval queries from a Fact Packet.
    """

    if not isinstance(fact_packet, dict):
        return []

    queries: List[str] = []
    seen: Set[str] = set()

    _extract_incident_queries(
        fact_packet,
        queries,
        seen,
    )

    _extract_detection_queries(
        fact_packet,
        queries,
        seen,
    )

    _extract_behavior_queries(
        fact_packet,
        queries,
        seen,
    )

    _extract_mitre_queries(
        fact_packet,
        queries,
        seen,
    )

    _extract_threat_profile_queries(
        fact_packet,
        queries,
        seen,
    )

    _extract_risk_queries(
        fact_packet,
        queries,
        seen,
    )

    _extract_evidence_gap_queries(
        fact_packet,
        queries,
        seen,
    )

    return queries[:MAX_QUERIES]


def _merge_results(
    results: Iterable[RetrievalResult],
) -> Tuple[
    List[RetrievedEvidence],
    List[RetrievedEvidence],
]:
    """
    Merge retrieval results while removing duplicate documents.

    Partial retrieval misses are intentionally ignored here.

    A warning should describe a problem with the complete retrieval
    operation, not the fact that one individual query had no match.
    """

    security_by_ref: Dict[
        str,
        RetrievedEvidence,
    ] = {}

    sentinelmesh_by_ref: Dict[
        str,
        RetrievedEvidence,
    ] = {}

    for result in results:

        for evidence in result.security_knowledge:

            key = (
                evidence.evidence_refs[0]
                if evidence.evidence_refs
                else evidence.title
            )

            existing = security_by_ref.get(key)

            if (
                existing is None
                or evidence.relevance > existing.relevance
            ):
                security_by_ref[key] = evidence

        for evidence in result.sentinelmesh_knowledge:

            key = (
                evidence.evidence_refs[0]
                if evidence.evidence_refs
                else evidence.title
            )

            existing = sentinelmesh_by_ref.get(key)

            if (
                existing is None
                or evidence.relevance > existing.relevance
            ):
                sentinelmesh_by_ref[key] = evidence

    security_results = sorted(
        security_by_ref.values(),
        key=lambda item: (
            -item.relevance,
            item.title,
        ),
    )

    sentinelmesh_results = sorted(
        sentinelmesh_by_ref.values(),
        key=lambda item: (
            -item.relevance,
            item.title,
        ),
    )

    return (
        security_results,
        sentinelmesh_results,
    )


def build_rag_context(
    fact_packet: Dict[str, Any],
    top_k: int = DEFAULT_TOP_K,
) -> RAGContext:
    """
    Build RAG context from an actual SentinelMesh Fact Packet.

    Retrieved knowledge is contextual knowledge only.
    Incident facts remain in the Fact Packet.
    """

    if not isinstance(fact_packet, dict):

        return RAGContext(
            incident_id="",
            queries=[],
            warnings=[
                "Fact Packet must be a dictionary."
            ],
            insufficient_evidence=True,
        )

    incident = fact_packet.get(
        "incident",
        {},
    )

    if isinstance(incident, dict):

        incident_id = _string(
            incident.get("incident_id")
        )

    else:

        incident_id = ""

    queries = build_investigation_queries(
        fact_packet
    )

    if not queries:

        return RAGContext(
            incident_id=incident_id,
            queries=[],
            warnings=[
                "No investigation queries could be extracted "
                "from the Fact Packet."
            ],
            insufficient_evidence=True,
        )

    retrieval_results: List[RetrievalResult] = []

    for query in queries:

        retrieval_results.append(
            retrieve(
                query=query,
                top_k=top_k,
            )
        )

    (
        security_knowledge,
        sentinelmesh_knowledge,
    ) = _merge_results(
        retrieval_results
    )

    warnings: List[str] = []

    if not security_knowledge:

        warnings.append(
            "No general security knowledge was retrieved "
            "for the supplied Fact Packet."
        )

    if not sentinelmesh_knowledge:

        warnings.append(
            "No SentinelMesh-specific knowledge was retrieved "
            "for the supplied Fact Packet."
        )

    insufficient_evidence = (
        not security_knowledge
        and not sentinelmesh_knowledge
    )

    if insufficient_evidence:

        warnings.append(
            "No relevant RAG knowledge was retrieved "
            "for the supplied Fact Packet."
        )

    return RAGContext(
        incident_id=incident_id,
        queries=queries,
        security_knowledge=security_knowledge,
        sentinelmesh_knowledge=sentinelmesh_knowledge,
        warnings=warnings,
        insufficient_evidence=insufficient_evidence,
    )


__all__ = [
    "RAGContext",
    "build_investigation_queries",
    "build_rag_context",
]