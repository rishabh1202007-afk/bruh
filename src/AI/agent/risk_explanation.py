"""
Deterministic explanation of an existing SentinelMesh risk score.

This module never recalculates risk. It explains the risk object already
present in a canonical Fact Packet and preserves its evidence limitations.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Set

from ..fact_packet.builder import canonical_mitre_techniques
from .evidence_gap_engine import analyze_evidence_gaps


FACTOR_ORDER = (
    "detection_severity",
    "behavioral_evidence",
    "correlation_strength",
    "mitre_context",
    "threat_profile_alignment",
    "persistence_privilege",
    "network_activity",
    "repetition",
)


@dataclass
class RiskExplanation:
    incident_id: str
    status: str
    risk_score: int | float | None
    risk_level: str | None
    model_version: str | None
    top_contributing_factors: List[Dict[str, Any]] = field(
        default_factory=list
    )
    factor_explanations: List[Dict[str, Any]] = field(
        default_factory=list
    )
    supporting_evidence_refs: List[str] = field(
        default_factory=list
    )
    observed_risk_signals: List[str] = field(
        default_factory=list
    )
    limitations: List[str] = field(default_factory=list)
    attribution_warning: str | None = None
    grounded: bool = True
    insufficient_evidence: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _incident_id(fact_packet: Dict[str, Any]) -> str:
    incident = fact_packet.get("incident", {})
    if not isinstance(incident, dict):
        return ""
    value = incident.get("incident_id")
    return str(value).strip() if value else ""


def _items(fact_packet: Dict[str, Any], section: str) -> List[Dict[str, Any]]:
    value = fact_packet.get(section, [])
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _refs(item: Dict[str, Any]) -> Set[str]:
    refs: Set[str] = set()
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

    for key in ("evidence_refs", "supporting_evidence_refs"):
        value = item.get(key, [])
        if isinstance(value, str):
            refs.add(value)
        elif isinstance(value, list):
            refs.update(
                str(ref)
                for ref in value
                if ref is not None and str(ref)
            )

    return refs


def _reference_groups(fact_packet: Dict[str, Any]) -> Dict[str, Set[str]]:
    detections = set().union(
        *(_refs(item) for item in _items(fact_packet, "detections"))
    )
    behavior_items = _items(fact_packet, "behaviors")
    behavior_detections = _items(fact_packet, "behavior_detections")
    behaviors = set().union(
        *(_refs(item) for item in behavior_items),
        *(_refs(item) for item in behavior_detections),
    )
    events = set().union(
        *(_refs(item) for item in _items(fact_packet, "events"))
    )
    evidence = set().union(
        *(_refs(item) for item in _items(fact_packet, "evidence"))
    )
    mitre = set()
    for technique in canonical_mitre_techniques(
        fact_packet.get("mitre")
    ):
        mitre.update(_refs(technique))

    all_refs = detections | behaviors | events | evidence | mitre
    return {
        "detections": detections,
        "behaviors": behaviors,
        "events": events,
        "evidence": evidence,
        "mitre": mitre,
        "all": all_refs,
    }


def _factor_refs(
    factor_name: str,
    groups: Dict[str, Set[str]],
) -> Set[str]:
    if factor_name == "detection_severity":
        return groups["detections"] | groups["events"] | groups["evidence"]
    if factor_name == "behavioral_evidence":
        return groups["behaviors"]
    if factor_name == "correlation_strength":
        return groups["detections"] | groups["events"] | groups["evidence"]
    if factor_name == "mitre_context":
        return groups["mitre"] | groups["detections"] | groups["behaviors"]
    if factor_name in {
        "threat_profile_alignment",
        "persistence_privilege",
        "network_activity",
    }:
        return groups["behaviors"] | groups["evidence"]
    if factor_name == "repetition":
        return groups["all"]
    return groups["all"]


def _factor_items(risk: Dict[str, Any]) -> List[Dict[str, Any]]:
    factors = risk.get("factors")
    if isinstance(factors, list):
        return [item for item in factors if isinstance(item, dict)]

    details = risk.get("factor_details")
    if not isinstance(details, dict):
        return []

    return [
        {
            "name": name,
            "score": value.get("score"),
            "maximum": value.get("maximum"),
            "evidence": value.get("evidence", []),
            "reason": value.get("reason"),
        }
        for name, value in details.items()
        if isinstance(value, dict)
    ]


def _factor_sort_key(item: Dict[str, Any]) -> tuple[float, int, str]:
    name = str(item.get("name", ""))
    try:
        score = float(item.get("score") or 0)
    except (TypeError, ValueError):
        score = 0.0

    try:
        order = FACTOR_ORDER.index(name)
    except ValueError:
        order = len(FACTOR_ORDER)

    return (-score, order, name)


def _attribution_warning(fact_packet: Dict[str, Any]) -> str | None:
    profiles = _items(fact_packet, "threat_profiles")
    for profile in profiles:
        if profile.get("attribution_status") == (
            "behavioral_profile_match_only"
        ):
            return (
                "Threat-profile alignment is behavioral context only and "
                "does not confirm malware-family attribution."
            )

    return None


def explain_risk_score(
    fact_packet: Dict[str, Any],
) -> RiskExplanation:
    """
    Explain the existing Fact Packet risk object without recalculating it.
    """

    if not isinstance(fact_packet, dict):
        return RiskExplanation(
            incident_id="",
            status="insufficient_evidence",
            risk_score=None,
            risk_level=None,
            model_version=None,
            limitations=["Fact Packet must be a dictionary."],
            grounded=True,
            insufficient_evidence=True,
        )

    risk = fact_packet.get("risk", {})
    if not isinstance(risk, dict) or risk.get("total_score") is None:
        return RiskExplanation(
            incident_id=_incident_id(fact_packet),
            status="insufficient_evidence",
            risk_score=None,
            risk_level=None,
            model_version=None,
            limitations=[
                "Insufficient evidence: no deterministic risk score is "
                "available in the Fact Packet."
            ],
            grounded=True,
            insufficient_evidence=True,
        )

    factor_items = _factor_items(risk)
    if not factor_items:
        return RiskExplanation(
            incident_id=_incident_id(fact_packet),
            status="insufficient_evidence",
            risk_score=risk.get("total_score"),
            risk_level=risk.get("risk_level"),
            model_version=risk.get("model_version"),
            limitations=[
                "Insufficient evidence: deterministic risk factor details "
                "are unavailable."
            ],
            grounded=True,
            insufficient_evidence=True,
        )

    groups = _reference_groups(fact_packet)
    explanations: List[Dict[str, Any]] = []
    all_supporting_refs: Set[str] = set()
    signals: List[str] = []
    limitations: List[str] = []

    for item in sorted(factor_items, key=_factor_sort_key):
        name = str(item.get("name", ""))
        refs = sorted(_factor_refs(name, groups))
        score = item.get("score")
        maximum = item.get("maximum")
        reason = item.get("reason")
        evidence = item.get("evidence", [])

        explanation = {
            "factor": name,
            "contribution": score,
            "maximum": maximum,
            "reason": reason,
            "evidence": list(evidence) if isinstance(evidence, list) else [],
            "supporting_evidence_refs": refs,
            "observed": bool(score),
        }
        explanations.append(explanation)
        all_supporting_refs.update(refs)

        if score:
            signals.append(
                f"{name} contributed {score} point(s)."
            )
            if not refs:
                limitations.append(
                    f"Factor {name} has a contribution but no traceable "
                    "Fact Packet evidence reference was available."
                )

    gap_analysis = analyze_evidence_gaps(fact_packet)
    if gap_analysis.gaps:
        limitations.extend(
            "Evidence visibility limitation: " + gap.description
            for gap in gap_analysis.gaps
        )

    synthetic = any(
        item.get("synthetic") is True
        for item in (
            _items(fact_packet, "behaviors")
            + _items(fact_packet, "behavior_detections")
            + _items(fact_packet, "evidence")
        )
    )
    if synthetic:
        limitations.append(
            "Synthetic telemetry contributed context only and must not "
            "be treated as confirmed real-world malicious activity."
        )

    limitations = list(dict.fromkeys(limitations))
    nonzero = [item for item in explanations if item.get("observed")]

    return RiskExplanation(
        incident_id=_incident_id(fact_packet),
        status="explained",
        risk_score=risk.get("total_score"),
        risk_level=risk.get("risk_level"),
        model_version=risk.get("model_version"),
        top_contributing_factors=nonzero,
        factor_explanations=explanations,
        supporting_evidence_refs=sorted(all_supporting_refs),
        observed_risk_signals=signals,
        limitations=limitations,
        attribution_warning=_attribution_warning(fact_packet),
        grounded=True,
        insufficient_evidence=False,
    )


__all__ = ["RiskExplanation", "explain_risk_score"]
