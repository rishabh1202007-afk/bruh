"""
Deterministic evidence validator for SentinelMesh AI investigation responses.

This module does not use an LLM. It validates that AI investigation claims
remain traceable to evidence and retrieved knowledge already present in the
SentinelMesh investigation context.
"""

from typing import Any, Dict, Iterable, List, Set


FACT_PACKET_EVIDENCE_SECTIONS = (
    "evidence",
    "detections",
    "events",
    "behaviors",
    "behavior_detections",
)


def _as_list(value: Any) -> List[Any]:
    return value if isinstance(value, list) else []


def _string_set(values: Iterable[Any]) -> Set[str]:
    if isinstance(values, (str, bytes)):
        values = [values]

    return {
        str(value)
        for value in values
        if value is not None and str(value)
    }


def _collect_fact_packet_refs(
    fact_packet: Dict[str, Any],
) -> Set[str]:
    """
    Collect every legitimate evidence reference that an AI response
    is allowed to cite from the Fact Packet.

    References may come from:
    - explicit evidence identifiers
    - detection/event/telemetry identifiers
    - source records
    - references explicitly attached to an item
    """

    refs: Set[str] = set()

    for section_name in FACT_PACKET_EVIDENCE_SECTIONS:
        for item in _as_list(fact_packet.get(section_name)):
            if not isinstance(item, dict):
                continue

            # ---------------------------------------------------------
            # Direct identifiers
            # ---------------------------------------------------------

            for key in (
                "evidence_id",
                "evidence_ref",
                "detection_id",
                "event_id",
                "telemetry_id",
                "behavior_detection_id",
                "id",
                "source_record",
                "source_detection",
                "source_telemetry",
            ):
                value = item.get(key)

                if value is not None and str(value):
                    refs.add(str(value))

            # ---------------------------------------------------------
            # Explicit reference collections
            # ---------------------------------------------------------

            for key in (
                "evidence_refs",
                "supporting_evidence_refs",
            ):
                refs.update(
                    _string_set(
                        item.get(key, [])
                    )
                )

    return refs


def _collect_knowledge_refs(
    retrieval_context: Dict[str, Any],
) -> Set[str]:
    """
    Collect every legitimate reference belonging to retrieved knowledge.

    RAG documents use `evidence_refs` as their provenance/reference field.
    For backward compatibility, this validator also accepts `knowledge_refs`
    and a singular `ref`.

    Important:
    These references are knowledge provenance, NOT incident evidence.
    """

    refs: Set[str] = set()

    for section_name in (
        "security_knowledge",
        "sentinelmesh_knowledge",
    ):
        for item in _as_list(
            retrieval_context.get(section_name)
        ):
            if not isinstance(item, dict):
                continue

            # ---------------------------------------------------------
            # Current SentinelMesh RAG provenance field
            # ---------------------------------------------------------

            refs.update(
                _string_set(
                    item.get("evidence_refs", [])
                )
            )

            # ---------------------------------------------------------
            # Backward-compatible knowledge reference field
            # ---------------------------------------------------------

            refs.update(
                _string_set(
                    item.get("knowledge_refs", [])
                )
            )

            # ---------------------------------------------------------
            # Backward-compatible singular reference
            # ---------------------------------------------------------

            ref = item.get("ref")

            if ref is not None and str(ref):
                refs.add(str(ref))

    return refs


def _claim_items(
    response: Dict[str, Any],
    field: str,
) -> List[Dict[str, Any]]:
    items = []

    for item in _as_list(response.get(field)):
        if isinstance(item, dict):
            items.append(item)

    return items


def validate_investigation_response(
    response: Dict[str, Any],
    fact_packet: Dict[str, Any],
    retrieval_context: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    """
    Validate claim-to-evidence traceability without using an LLM.
    """

    retrieval_context = retrieval_context or {}

    fact_refs = _collect_fact_packet_refs(
        fact_packet
    )

    knowledge_refs = _collect_knowledge_refs(
        retrieval_context
    )

    errors: List[str] = []
    warnings: List[str] = []
    unsupported_claims: List[Dict[str, Any]] = []

    checked_claims = 0

    # ---------------------------------------------------------
    # Validate observed facts
    # ---------------------------------------------------------

    for claim in _claim_items(
        response,
        "observed_facts",
    ):
        checked_claims += 1

        claim_text = str(
            claim.get("claim", "")
        ).strip()

        refs = _string_set(
            claim.get("evidence_refs", [])
        )

        if not claim_text:
            errors.append(
                "An observed fact contains an empty claim."
            )
            continue

        if not refs:
            unsupported_claims.append(
                {
                    "claim": claim_text,
                    "reason": (
                        "No evidence references were supplied."
                    ),
                }
            )
            continue

        missing = sorted(
            refs - fact_refs
        )

        if missing:
            unsupported_claims.append(
                {
                    "claim": claim_text,
                    "reason": (
                        "Evidence reference(s) are not "
                        "present in the Fact Packet."
                    ),
                    "missing_refs": missing,
                }
            )

    # ---------------------------------------------------------
    # Validate retrieved knowledge
    # ---------------------------------------------------------

    for context in _claim_items(
        response,
        "knowledge_context",
    ):
        checked_claims += 1

        statement = str(
            context.get("statement", "")
        ).strip()

        refs = _string_set(
            context.get("knowledge_refs", [])
        )

        if not statement:
            errors.append(
                "A knowledge context item contains "
                "an empty statement."
            )
            continue

        if not refs:
            unsupported_claims.append(
                {
                    "claim": statement,
                    "reason": (
                        "No knowledge references were supplied."
                    ),
                }
            )
            continue

        missing = sorted(
            refs - knowledge_refs
        )

        if missing:
            unsupported_claims.append(
                {
                    "claim": statement,
                    "reason": (
                        "Knowledge reference(s) are not "
                        "present in retrieved context."
                    ),
                    "missing_refs": missing,
                }
            )

    # ---------------------------------------------------------
    # Validate insufficient-evidence state
    # ---------------------------------------------------------

    if (
        response.get("insufficient_evidence")
        and response.get("status")
        != "insufficient_evidence"
    ):
        errors.append(
            "Response marks insufficient evidence "
            "but does not use the insufficient_evidence status."
        )

    # ---------------------------------------------------------
    # Validate grounded flag
    # ---------------------------------------------------------

    if (
        response.get("grounded") is True
        and unsupported_claims
    ):
        errors.append(
            "Response is marked grounded but contains "
            "unsupported or untraceable claims."
        )

    # ---------------------------------------------------------
    # Warning when nothing was actually validated
    # ---------------------------------------------------------

    if (
        not checked_claims
        and not response.get("insufficient_evidence")
    ):
        warnings.append(
            "No evidence-backed claims were supplied "
            "for validation."
        )

    grounded = (
        not errors
        and not unsupported_claims
    )

    return {
        "valid": grounded,
        "grounded": grounded,
        "checked_claims": checked_claims,
        "fact_packet_reference_count": len(
            fact_refs
        ),
        "knowledge_reference_count": len(
            knowledge_refs
        ),
        "unsupported_claims": unsupported_claims,
        "errors": errors,
        "warnings": warnings,
    }


def assert_valid_investigation_response(
    response: Dict[str, Any],
    fact_packet: Dict[str, Any],
    retrieval_context: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    """
    Validate and raise AssertionError when grounding is violated.
    """

    result = validate_investigation_response(
        response=response,
        fact_packet=fact_packet,
        retrieval_context=retrieval_context,
    )

    if not result["valid"]:
        reasons = list(result["errors"])

        reasons.extend(
            item["reason"]
            for item in result["unsupported_claims"]
        )

        raise AssertionError(
            "Investigation response failed evidence validation: "
            + "; ".join(reasons)
        )

    return result


__all__ = [
    "validate_investigation_response",
    "assert_valid_investigation_response",
]