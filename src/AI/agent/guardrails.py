import re
from typing import Any, Dict, Iterable, List, Set, Tuple


PROMPT_INJECTION_PATTERNS = [
    r"ignore\s+(?:all\s+)?previous\s+instructions",
    r"ignore\s+(?:the\s+)?system\s+prompt",
    r"disregard\s+(?:all\s+)?previous\s+instructions",
    r"forget\s+(?:all\s+)?previous\s+instructions",
    r"you\s+are\s+now",
    r"act\s+as\s+(?:the\s+)?system",
    r"reveal\s+(?:the\s+)?system\s+prompt",
    r"reveal\s+(?:your\s+)?instructions",
    r"override\s+(?:the\s+)?instructions",
    r"follow\s+these\s+instructions\s+instead",
]


UNTRUSTED_TEXT_FIELDS = {
    "description",
    "raw_data",
    "raw_event",
    "message",
    "strings",
    "content",
    "text",
    "notes",
}


def detect_prompt_injection(value: Any) -> bool:
    """
    Detect common prompt-injection patterns.

    Event/log text is treated as untrusted data. Detection of a
    suspicious phrase does not itself mean the security event is
    malicious.
    """

    if not isinstance(value, str):
        return False

    for pattern in PROMPT_INJECTION_PATTERNS:
        if re.search(pattern, value, flags=re.IGNORECASE):
            return True

    return False


def _iter_untrusted_text(
    value: Any,
    path: str = "",
) -> Iterable[Tuple[str, str]]:
    """
    Recursively find text fields that should be treated as
    untrusted input.
    """

    if isinstance(value, dict):

        for key, child in value.items():

            child_path = (
                f"{path}.{key}"
                if path
                else str(key)
            )

            if (
                isinstance(child, str)
                and (
                    key in UNTRUSTED_TEXT_FIELDS
                    or len(child) > 500
                )
            ):
                yield child_path, child

            else:
                yield from _iter_untrusted_text(
                    child,
                    child_path,
                )

    elif isinstance(value, list):

        for index, child in enumerate(value):

            child_path = f"{path}[{index}]"

            yield from _iter_untrusted_text(
                child,
                child_path,
            )


def inspect_untrusted_content(
    fact_packet: Dict[str, Any],
) -> List[str]:
    """
    Inspect event/log text for prompt-injection-like content.
    """

    warnings: List[str] = []

    for path, text in _iter_untrusted_text(fact_packet):

        if detect_prompt_injection(text):

            warnings.append(
                "Prompt-injection-like text detected in "
                f"untrusted field: {path}"
            )

    return warnings


def validate_synthetic_telemetry(
    fact_packet: Dict[str, Any],
) -> List[str]:
    """
    Ensure synthetic endpoint behavior cannot silently become
    represented as confirmed real telemetry.
    """

    warnings: List[str] = []

    sections = (
        "behaviors",
        "behavior_detections",
        "evidence",
    )

    for section in sections:

        items = fact_packet.get(
            section,
            [],
        ) or []

        for index, item in enumerate(items):

            if not isinstance(item, dict):
                continue

            synthetic = item.get("synthetic")

            source = str(
                item.get(
                    "source",
                    "",
                )
            ).lower()

            if (
                section in {
                    "behaviors",
                    "behavior_detections",
                }
                and source
                in {
                    "endpoint_behavior",
                    "behavior_telemetry",
                }
                and synthetic is not True
            ):

                warnings.append(
                    "Synthetic endpoint behavior at "
                    f"{section}[{index}] is missing "
                    "synthetic=true and must not be presented "
                    "as confirmed real telemetry."
                )

            if (
                synthetic is True
                and item.get("attribution_status")
                not in (
                    None,
                    "behavioral_profile_match_only",
                )
            ):

                warnings.append(
                    "Synthetic telemetry at "
                    f"{section}[{index}] has an unsafe "
                    "attribution status."
                )

    return warnings


def validate_attribution_status(
    fact_packet: Dict[str, Any],
) -> List[str]:
    """
    Validate threat-profile attribution language.
    """

    warnings: List[str] = []

    for profile in (
        fact_packet.get(
            "threat_profiles",
            [],
        )
        or []
    ):

        if not isinstance(profile, dict):
            continue

        status = profile.get(
            "attribution_status"
        )

        if status in {
            "confirmed",
            "malware_confirmed",
        }:

            warnings.append(
                "Threat-profile attribution is stronger than "
                "the SentinelMesh behavioral-profile evidence "
                "model supports and must not be independently "
                "converted into a confirmed malware attribution."
            )

    return warnings


def validate_fact_claim(
    claim: str,
    evidence_refs: List[str],
    available_refs: Set[str],
) -> Tuple[bool, str]:
    """
    Ensure a factual claim only references available evidence.
    """

    if not claim or not claim.strip():

        return (
            False,
            "Empty factual claim.",
        )

    missing = [
        reference
        for reference in evidence_refs
        if reference not in available_refs
    ]

    if missing:

        return (
            False,
            "Claim references unavailable evidence: "
            f"{missing}",
        )

    return True, ""


def validate_response_grounding(
    response: Dict[str, Any],
    available_refs: Set[str],
) -> List[str]:
    """
    Validate evidence references contained in an AI response.
    """

    warnings: List[str] = []

    for claim in (
        response.get(
            "observed_facts",
            [],
        )
        or []
    ):

        if not isinstance(claim, dict):
            continue

        claim_text = claim.get(
            "claim",
            "",
        )

        evidence_refs = claim.get(
            "evidence_refs",
            [],
        )

        valid, reason = validate_fact_claim(
            claim_text,
            evidence_refs,
            available_refs,
        )

        if not valid:
            warnings.append(reason)

    return warnings


def run_guardrails(
    fact_packet: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Run all pre-investigation safety checks.

    Prompt-injection-like text generates a warning because event
    text is untrusted data. It does not automatically block the
    investigation.

    Safety violations involving synthetic telemetry or unsafe
    attribution can block the investigation.
    """

    warnings: List[str] = []

    warnings.extend(
        inspect_untrusted_content(
            fact_packet
        )
    )

    warnings.extend(
        validate_synthetic_telemetry(
            fact_packet
        )
    )

    warnings.extend(
        validate_attribution_status(
            fact_packet
        )
    )

    blocking = any(
        (
            "must not be presented" in warning
            or
            "must not independently convert"
            in warning
        )
        for warning in warnings
    )

    return {
        "safe_to_investigate": not blocking,
        "warnings": warnings,
    }


__all__ = [
    "PROMPT_INJECTION_PATTERNS",
    "detect_prompt_injection",
    "inspect_untrusted_content",
    "validate_synthetic_telemetry",
    "validate_attribution_status",
    "validate_fact_claim",
    "validate_response_grounding",
    "run_guardrails",
]