from __future__ import annotations

import importlib
import re
from typing import Any, Dict, List, Set

from ..fact_packet.builder import canonical_mitre_techniques
from .guardrails import (
    run_guardrails,
    validate_response_grounding,
)

from .models import (
    EvidenceClaim,
    InvestigationResponse,
    InvestigationStep,
    KnowledgeContext,
)


STOPWORDS = {
    "the",
    "a",
    "an",
    "and",
    "or",
    "to",
    "of",
    "on",
    "in",
    "for",
    "with",
    "from",
    "by",
    "is",
    "was",
    "were",
    "this",
    "that",
    "as",
    "it",
    "at",
    "within",
    "same",
    "only",
    "used",
    "does",
}


def _tokens(value: Any) -> Set[str]:
    """
    Convert text into deterministic retrieval tokens.
    """

    if value is None:
        return set()

    text = str(value).lower()

    return {
        token
        for token in re.findall(
            r"[a-z0-9_.-]+",
            text,
        )
        if (
            len(token) > 1
            and token not in STOPWORDS
        )
    }


def _field(
    item: Any,
    name: str,
    default: Any = None,
) -> Any:
    """
    Read a field from either a dictionary or an object.
    """

    if isinstance(item, dict):
        return item.get(
            name,
            default,
        )

    return getattr(
        item,
        name,
        default,
    )


def _evidence_ref(
    item: Dict[str, Any],
    fallback: str,
) -> str:
    """
    Get the most traceable evidence identifier available.
    """

    return str(
        item.get("evidence_id")
        or item.get("detection_id")
        or item.get("source_record")
        or item.get("telemetry_id")
        or fallback
    )


def _available_evidence_refs(
    fact_packet: Dict[str, Any],
) -> Set[str]:
    """
    Build the set of actual evidence references available to
    the investigation agent.

    The incident ID itself is deliberately NOT treated as
    evidence. An incident can exist without containing enough
    evidence for investigation.
    """

    refs: Set[str] = set()

    sections = (
        "evidence",
        "detections",
        "events",
        "behaviors",
        "behavior_detections",
    )

    for section in sections:

        items = fact_packet.get(
            section,
            [],
        ) or []

        for index, item in enumerate(items):

            if not isinstance(item, dict):
                continue

            refs.add(
                _evidence_ref(
                    item,
                    f"{section}[{index}]",
                )
            )

    return refs


def _has_investigable_evidence(
    fact_packet: Dict[str, Any],
) -> bool:
    """
    Determine whether the Fact Packet contains actual security
    evidence.

    An incident identifier alone is not considered evidence.
    """

    evidence_sections = (
        "evidence",
        "detections",
        "events",
        "behaviors",
        "behavior_detections",
    )

    for section in evidence_sections:

        items = fact_packet.get(
            section,
            [],
        ) or []

        if isinstance(
            items,
            list,
        ) and items:

            return True

        if isinstance(
            items,
            dict,
        ) and items:

            return True

    if canonical_mitre_techniques(
        fact_packet.get("mitre")
    ):
        return True

    return False


def _observed_facts(
    fact_packet: Dict[str, Any],
) -> List[EvidenceClaim]:
    """
    Convert deterministic Fact Packet information into
    evidence-backed factual claims.
    """

    claims: List[EvidenceClaim] = []

    incident = fact_packet.get(
        "incident",
        {},
    ) or {}

    incident_id = incident.get(
        "incident_id"
    )

    correlation = fact_packet.get(
        "correlation",
        {},
    ) or {}

    rule_id = correlation.get(
        "rule_id"
    )

    if rule_id:

        refs = [
            _evidence_ref(
                detection,
                f"detections[{index}]",
            )
            for index, detection in enumerate(
                fact_packet.get(
                    "detections",
                    [],
                )
                or []
            )
            if isinstance(
                detection,
                dict,
            )
        ]

        if refs:

            claims.append(
                EvidenceClaim(
                    claim=(
                        f"The incident was correlated by "
                        f"rule {rule_id} within a "
                        f"{correlation.get('time_window_seconds', 'configured')} "
                        "second window."
                    ),
                    evidence_refs=refs,
                )
            )

    for index, detection in enumerate(
        fact_packet.get(
            "detections",
            [],
        )
        or []
    ):

        if not isinstance(
            detection,
            dict,
        ):
            continue

        detection_id = (
            detection.get(
                "detection_id"
            )
            or detection.get(
                "rule_id"
            )
        )

        if not detection_id:
            continue

        name = (
            detection.get(
                "rule_name"
            )
            or detection_id
        )

        severity = detection.get(
            "severity"
        )

        suffix = (
            f" with severity {severity}"
            if severity
            else ""
        )

        claims.append(
            EvidenceClaim(
                claim=(
                    f"Detection {detection_id} "
                    f"({name}) is present{suffix}."
                ),
                evidence_refs=[
                    _evidence_ref(
                        detection,
                        f"detections[{index}]",
                    )
                ],
            )
        )

    for index, behavior in enumerate(
        fact_packet.get(
            "behaviors",
            [],
        )
        or []
    ):

        if not isinstance(
            behavior,
            dict,
        ):
            continue

        behavior_id = (
            behavior.get(
                "telemetry_id"
            )
            or behavior.get(
                "detection_id"
            )
            or f"behaviors[{index}]"
        )

        behavior_type = behavior.get(
            "behavior_type",
            "behavior telemetry",
        )

        synthetic = behavior.get(
            "synthetic"
        )

        claim = (
            f"Behavior telemetry {behavior_id} "
            f"records {behavior_type}."
        )

        if synthetic is True:

            claim += (
                " The telemetry is explicitly "
                "marked synthetic."
            )

        claims.append(
            EvidenceClaim(
                claim=claim,
                evidence_refs=[
                    _evidence_ref(
                        behavior,
                        f"behaviors[{index}]",
                    )
                ],
            )
        )

    for index, behavior_detection in enumerate(
        fact_packet.get(
            "behavior_detections",
            [],
        )
        or []
    ):

        if not isinstance(
            behavior_detection,
            dict,
        ):
            continue

        detection_id = (
            behavior_detection.get(
                "detection_id"
            )
            or behavior_detection.get(
                "rule_id"
            )
            or f"behavior_detections[{index}]"
        )

        rule_name = (
            behavior_detection.get(
                "rule_name"
            )
            or detection_id
        )

        claims.append(
            EvidenceClaim(
                claim=(
                    f"Behavior detection {detection_id} "
                    f"({rule_name}) is present."
                ),
                evidence_refs=[
                    _evidence_ref(
                        behavior_detection,
                        f"behavior_detections[{index}]",
                    )
                ],
            )
        )

    for technique in canonical_mitre_techniques(
        fact_packet.get("mitre")
    ):

        if not isinstance(
            technique,
            dict,
        ):
            continue

        technique_id = technique.get(
            "technique_id"
        )

        if not technique_id:
            continue

        source_detection = technique.get(
            "source_detection"
        )

        refs = (
            [str(source_detection)]
            if source_detection
            else []
        )

        if not refs:

            continue

        claims.append(
            EvidenceClaim(
                claim=(
                    f"MITRE technique {technique_id} "
                    f"({technique.get('technique_name', 'mapped technique')}) "
                    "is present in the deterministic MITRE "
                    "context."
                ),
                evidence_refs=refs,
            )
        )

    return claims


def _fact_packet_query_terms(
    fact_packet: Dict[str, Any],
) -> str:
    """
    Build a deterministic retrieval query from the Fact Packet.
    """

    parts: List[str] = []

    incident = fact_packet.get(
        "incident",
        {},
    ) or {}

    correlation = fact_packet.get(
        "correlation",
        {},
    ) or {}

    parts.extend(
        str(
            incident.get(
                key,
                "",
            )
        )
        for key in (
            "incident_type",
            "rule_name",
            "severity",
        )
    )

    parts.extend(
        str(
            correlation.get(
                key,
                "",
            )
        )
        for key in (
            "rule_id",
            "rule_name",
        )
    )

    for section in (
        "detections",
        "behaviors",
        "behavior_detections",
        "threat_profiles",
    ):

        for item in (
            fact_packet.get(
                section,
                [],
            )
            or []
        ):

            if isinstance(
                item,
                dict,
            ):

                parts.extend(
                    str(value)
                    for value in item.values()
                    if isinstance(
                        value,
                        (
                            str,
                            int,
                            float,
                        ),
                    )
                )

            elif isinstance(
                item,
                str,
            ):

                parts.append(item)

    for technique in canonical_mitre_techniques(
        fact_packet.get("mitre")
    ):
        parts.extend(
            str(value)
            for value in technique.values()
            if isinstance(
                value,
                (
                    str,
                    int,
                    float,
                ),
            )
        )

    return " ".join(
        part
        for part in parts
        if part
    )


def _retrieve_knowledge(
    fact_packet: Dict[str, Any],
    top_k: int,
) -> List[KnowledgeContext]:
    """
    Retrieve context from the existing SentinelMesh two-layer
    knowledge base.

    This remains deterministic and does not use an LLM.
    """

    try:

        knowledge_base = importlib.import_module(
            "..rag.knowledge_base",
            package=__package__,
        )

    except Exception:

        return []

    query_tokens = _tokens(
        _fact_packet_query_terms(
            fact_packet
        )
    )

    candidates = []

    knowledge_sources = (
        (
            "get_security_knowledge",
            "security_knowledge",
        ),
        (
            "get_sentinelmesh_knowledge",
            "sentinelmesh_knowledge",
        ),
    )

    for function_name, source_name in knowledge_sources:

        function = getattr(
            knowledge_base,
            function_name,
            None,
        )

        if not callable(function):
            continue

        try:

            documents = function()

        except TypeError:

            try:

                documents = function("")

            except Exception:

                continue

        except Exception:

            continue

        for document in (
            documents or []
        ):

            title = str(
                _field(
                    document,
                    "title",
                    "",
                )
            )

            content = str(
                _field(
                    document,
                    "content",
                    "",
                )
            )

            reference = str(
                _field(
                    document,
                    "document_id",
                    None,
                )
                or _field(
                    document,
                    "doc_id",
                    None,
                )
                or _field(
                    document,
                    "id",
                    None,
                )
                or title
            )

            score = len(
                query_tokens
                & _tokens(
                    f"{title} {content}"
                )
            )

            if score > 0:

                candidates.append(
                    (
                        float(score),
                        source_name,
                        (
                            reference,
                            title,
                        ),
                    )
                )

    candidates.sort(
        key=lambda item: (
            -item[0],
            item[1],
            item[2][0],
        )
    )

    results: List[KnowledgeContext] = []

    seen: Set[str] = set()

    for _, source, (
        reference,
        title,
    ) in candidates:

        if reference in seen:
            continue

        seen.add(reference)

        results.append(
            KnowledgeContext(
                statement=(
                    title
                    or reference
                ),
                knowledge_refs=[
                    reference
                ],
                source=source,
            )
        )

        if len(results) >= top_k:
            break

    return results


class InvestigationAgent:
    """
    Evidence-grounded investigation assistant for SentinelMesh.

    The agent does not create detections, incidents, MITRE mappings,
    or risk scores. Those remain deterministic SentinelMesh outputs.
    """

    def __init__(
        self,
        top_k: int = 5,
    ) -> None:

        if top_k < 1:
            raise ValueError(
                "top_k must be at least 1"
            )

        self.top_k = top_k

    def investigate(
        self,
        fact_packet: Dict[str, Any],
    ) -> InvestigationResponse:
        """
        Investigate one canonical SentinelMesh Fact Packet.
        """

        if not isinstance(
            fact_packet,
            dict,
        ):
            raise TypeError(
                "fact_packet must be a dictionary"
            )

        guardrail_result = run_guardrails(
            fact_packet
        )

        incident = fact_packet.get(
            "incident",
            {},
        ) or {}

        incident_id = str(
            incident.get(
                "incident_id"
            )
            or "UNKNOWN"
        )

        if not guardrail_result[
            "safe_to_investigate"
        ]:

            return InvestigationResponse(
                incident_id=incident_id,
                status="blocked",
                summary="Insufficient evidence",
                uncertainties=[
                    "The Fact Packet failed a required safety validation."
                ],
                safety_warnings=guardrail_result[
                    "warnings"
                ],
                grounded=True,
                insufficient_evidence=True,
            )

        # ---------------------------------------------------------
        # IMPORTANT:
        # An incident ID, incident type, severity, or correlation
        # rule by itself is NOT enough evidence for investigation.
        #
        # The AI must have actual telemetry/detection/evidence
        # records before producing grounded factual claims.
        # ---------------------------------------------------------

        if not _has_investigable_evidence(
            fact_packet
        ):

            return InvestigationResponse(
                incident_id=incident_id,
                status="insufficient_evidence",
                summary="Insufficient evidence",
                observed_facts=[],
                knowledge_context=[],
                uncertainties=[
                    (
                        "The Fact Packet contains an incident "
                        "identifier but no underlying security "
                        "evidence."
                    )
                ],
                evidence_gaps=[
                    (
                        "No detections, events, behavior telemetry, "
                        "behavior detections, MITRE mappings, or "
                        "explicit evidence records are available."
                    )
                ],
                next_investigation_steps=[],
                safety_warnings=guardrail_result[
                    "warnings"
                ],
                grounded=True,
                insufficient_evidence=True,
            )

        observed = _observed_facts(
            fact_packet
        )

        available_refs = (
            _available_evidence_refs(
                fact_packet
            )
        )

        observed = [
            claim
            for claim in observed
            if all(
                reference in available_refs
                for reference in claim.evidence_refs
            )
        ]

        knowledge = _retrieve_knowledge(
            fact_packet,
            self.top_k,
        )

        gaps = self._build_evidence_gaps(
            fact_packet
        )

        uncertainties = self._build_uncertainties(
            fact_packet
        )

        steps = self._build_next_steps(
            fact_packet
        )

        if not observed:

            summary = "Insufficient evidence"
            insufficient = True
            status = "insufficient_evidence"

        else:

            summary = self._build_summary(
                fact_packet,
                observed,
            )

            insufficient = False
            status = "grounded"

        response = InvestigationResponse(
            incident_id=incident_id,
            status=status,
            summary=summary,
            observed_facts=observed,
            knowledge_context=knowledge,
            uncertainties=uncertainties,
            evidence_gaps=gaps,
            next_investigation_steps=steps,
            safety_warnings=guardrail_result[
                "warnings"
            ],
            grounded=True,
            insufficient_evidence=insufficient,
        )

        grounding_warnings = (
            validate_response_grounding(
                response.to_dict(),
                available_refs,
            )
        )

        if grounding_warnings:

            response.safety_warnings.extend(
                grounding_warnings
            )

            response.observed_facts = []

            response.summary = (
                "Insufficient evidence"
            )

            response.status = (
                "insufficient_evidence"
            )

            response.insufficient_evidence = True

        return response

    def _build_summary(
        self,
        fact_packet: Dict[str, Any],
        observed: List[EvidenceClaim],
    ) -> str:
        """
        Build a summary only from deterministic Fact Packet data.
        """

        incident = fact_packet.get(
            "incident",
            {},
        ) or {}

        detections = fact_packet.get(
            "detections",
            [],
        ) or []

        behaviors = fact_packet.get(
            "behaviors",
            [],
        ) or []

        severity = incident.get(
            "severity",
            "unspecified",
        )

        parts = [
            (
                f"Incident {incident.get('incident_id', 'UNKNOWN')} "
                f"contains {len(detections)} security detection(s)"
            )
        ]

        if behaviors:

            parts.append(
                f"and {len(behaviors)} "
                "behavior telemetry record(s)"
            )

        parts.append(
            f"with deterministic incident severity {severity}."
        )

        if incident.get(
            "incident_type"
        ):

            parts.append(
                f"Incident type: "
                f"{incident['incident_type']}."
            )

        return " ".join(parts)

    def _build_uncertainties(
        self,
        fact_packet: Dict[str, Any],
    ) -> List[str]:
        """
        Preserve important uncertainty from the security pipeline.
        """

        uncertainties: List[str] = []

        for profile in (
            fact_packet.get(
                "threat_profiles",
                [],
            )
            or []
        ):

            if (
                isinstance(
                    profile,
                    dict,
                )
                and profile.get(
                    "attribution_status"
                )
                == "behavioral_profile_match_only"
            ):

                uncertainties.append(
                    "Threat-profile alignment is behavioral "
                    "context only; it does not confirm "
                    "malware-family attribution."
                )

        if any(
            isinstance(
                item,
                dict,
            )
            and item.get(
                "synthetic"
            )
            is True
            for item in (
                fact_packet.get(
                    "behaviors",
                    [],
                )
                or []
            )
        ):

            uncertainties.append(
                "Some behavior telemetry is synthetic "
                "and must not be represented as confirmed "
                "real-world activity."
            )

        return uncertainties

    def _build_evidence_gaps(
        self,
        fact_packet: Dict[str, Any],
    ) -> List[str]:
        """
        Identify useful investigation data that is missing.
        """

        gaps: List[str] = []

        if not fact_packet.get(
            "events"
        ):

            gaps.append(
                "Source events are not present "
                "in the Fact Packet."
            )

        entities = fact_packet.get(
            "entities",
            {},
        ) or {}

        if not entities.get(
            "users"
        ):

            gaps.append(
                "No user entity is available "
                "for attribution analysis."
            )

        if not entities.get(
            "processes"
        ):

            gaps.append(
                "No process entity is available "
                "for process-level investigation."
            )

        if not entities.get(
            "ips"
        ):

            gaps.append(
                "No IP entity is available "
                "for network correlation."
            )

        return gaps

    def _build_next_steps(
        self,
        fact_packet: Dict[str, Any],
    ) -> List[InvestigationStep]:
        """
        Generate investigation recommendations.

        These are recommendations only and are never represented
        as completed actions.
        """

        detection_refs = [
            _evidence_ref(
                item,
                f"detections[{index}]",
            )
            for index, item in enumerate(
                fact_packet.get(
                    "detections",
                    [],
                )
                or []
            )
            if isinstance(
                item,
                dict,
            )
        ]

        steps = [
            InvestigationStep(
                action=(
                    "Review the source Windows Security "
                    "events surrounding the correlated detections."
                ),
                rationale=(
                    "The Fact Packet contains correlated "
                    "detections but may not contain the "
                    "full surrounding event context."
                ),
                supporting_evidence_refs=detection_refs,
            ),
            InvestigationStep(
                action=(
                    "Validate whether the observed activity "
                    "matches expected administrative behavior."
                ),
                rationale=(
                    "The deterministic correlation signal "
                    "requires analyst context before a "
                    "malicious conclusion is made."
                ),
                supporting_evidence_refs=detection_refs,
            ),
        ]

        if fact_packet.get(
            "behaviors"
        ):

            behavior_refs = [
                _evidence_ref(
                    item,
                    f"behaviors[{index}]",
                )
                for index, item in enumerate(
                    fact_packet.get(
                        "behaviors",
                        [],
                    )
                    or []
                )
                if isinstance(
                    item,
                    dict,
                )
            ]

            steps.append(
                InvestigationStep(
                    action=(
                        "Inspect the process and host "
                        "context associated with the "
                        "behavior telemetry."
                    ),
                    rationale=(
                        "Behavior telemetry provides "
                        "indicators but does not independently "
                        "establish attribution."
                    ),
                    supporting_evidence_refs=behavior_refs,
                )
            )

        return steps


def investigate(
    fact_packet: Dict[str, Any],
    top_k: int = 5,
) -> InvestigationResponse:
    """
    Convenience function for the SentinelMesh AI investigation API.
    """

    return InvestigationAgent(
        top_k=top_k
    ).investigate(
        fact_packet
    )


__all__ = [
    "InvestigationAgent",
    "investigate",
]