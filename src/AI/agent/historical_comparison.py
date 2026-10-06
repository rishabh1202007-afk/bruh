"""
Deterministic, evidence-grounded historical incident comparison.

This module compares supplied Fact Packets only. It does not load persistence,
create historical incidents, infer attribution, or use an LLM.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, Iterable, List, Set

from ..fact_packet.builder import canonical_mitre_techniques


@dataclass
class HistoricalIncidentComparison:
    current_incident_id: str
    historical_incident_id: str
    similarity_score: float
    similarity_level: str
    similarity_factors: List[Dict[str, Any]] = field(
        default_factory=list
    )
    shared_behaviors: List[str] = field(default_factory=list)
    shared_detections: List[str] = field(default_factory=list)
    shared_mitre_techniques: List[str] = field(default_factory=list)
    shared_threat_profiles: List[str] = field(default_factory=list)
    shared_evidence_characteristics: List[str] = field(
        default_factory=list
    )
    differences: List[Dict[str, Any]] = field(default_factory=list)
    evidence_refs: Dict[str, List[str]] = field(
        default_factory=lambda: {
            "current": [],
            "historical": [],
        }
    )
    limitations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class HistoricalComparisonResult:
    status: str
    current_incident_id: str
    comparisons: List[HistoricalIncidentComparison] = field(
        default_factory=list
    )
    limitations: List[str] = field(default_factory=list)
    insufficient_evidence: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "current_incident_id": self.current_incident_id,
            "comparisons": [
                comparison.to_dict()
                for comparison in self.comparisons
            ],
            "limitations": list(self.limitations),
            "insufficient_evidence": self.insufficient_evidence,
        }


@dataclass
class _FeatureEvidence:
    values: Set[str] = field(default_factory=set)
    refs_by_value: Dict[str, Set[str]] = field(default_factory=dict)

    def add(
        self,
        value: Any,
        refs: Iterable[Any],
    ) -> None:
        if value is None:
            return

        normalized = str(value).strip()
        if not normalized:
            return

        self.values.add(normalized)
        self.refs_by_value.setdefault(normalized, set()).update(
            str(reference)
            for reference in refs
            if reference is not None and str(reference)
        )

    def refs_for(self, values: Iterable[str]) -> Set[str]:
        refs: Set[str] = set()
        for value in values:
            refs.update(self.refs_by_value.get(value, set()))
        return refs


def _as_dict_list(value: Any) -> List[Dict[str, Any]]:
    if not isinstance(value, list):
        return []

    return [
        item
        for item in value
        if isinstance(item, dict)
    ]


def _incident_id(fact_packet: Dict[str, Any]) -> str:
    incident = fact_packet.get("incident", {})
    if not isinstance(incident, dict):
        return ""

    value = incident.get("incident_id")
    return str(value).strip() if value else ""


def _item_refs(item: Dict[str, Any]) -> Set[str]:
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

    for key in (
        "evidence_refs",
        "supporting_evidence_refs",
    ):
        value = item.get(key, [])
        if isinstance(value, str):
            refs.add(value)
        elif isinstance(value, list):
            refs.update(
                str(reference)
                for reference in value
                if reference is not None and str(reference)
            )

    return refs


def _add_item_feature(
    feature: _FeatureEvidence,
    value: Any,
    item: Dict[str, Any],
) -> None:
    feature.add(value, _item_refs(item))


def _feature_sets(
    fact_packet: Dict[str, Any],
) -> Dict[str, _FeatureEvidence]:
    detections = _FeatureEvidence()
    behaviors = _FeatureEvidence()
    techniques = _FeatureEvidence()
    profiles = _FeatureEvidence()
    evidence_types = _FeatureEvidence()
    sequences = _FeatureEvidence()

    detection_items = _as_dict_list(
        fact_packet.get("detections")
    )
    behavior_detection_items = _as_dict_list(
        fact_packet.get("behavior_detections")
    )
    behavior_items = _as_dict_list(
        fact_packet.get("behaviors")
    )
    evidence_items = _as_dict_list(
        fact_packet.get("evidence")
    )

    timeline_items: List[Dict[str, Any]] = []

    for item in detection_items:
        value = (
            item.get("rule_id")
            or item.get("detection_id")
            or item.get("rule_name")
        )
        _add_item_feature(detections, value, item)
        timeline_items.append(item)

    for item in behavior_detection_items:
        value = (
            item.get("behavior_type")
            or item.get("rule_id")
            or item.get("detection_id")
        )
        _add_item_feature(detections, value, item)
        if item.get("behavior_type"):
            _add_item_feature(
                behaviors,
                item.get("behavior_type"),
                item,
            )
        timeline_items.append(item)

    for item in behavior_items:
        _add_item_feature(
            behaviors,
            item.get("behavior_type"),
            item,
        )
        if item.get("synthetic") is True:
            _add_item_feature(
                evidence_types,
                "synthetic",
                item,
            )
        profile = item.get("threat_profile")
        if profile:
            _add_item_feature(profiles, profile, item)
        timeline_items.append(item)

    for item in evidence_items:
        source = item.get("source")
        if source:
            _add_item_feature(evidence_types, source, item)
        if item.get("synthetic") is True:
            _add_item_feature(evidence_types, "synthetic", item)

    for profile in _as_dict_list(
        fact_packet.get("threat_profiles")
    ):
        profile_name = (
            profile.get("profile_name")
            or profile.get("profile")
            or profile.get("name")
        )
        _add_item_feature(profiles, profile_name, profile)

    for technique in canonical_mitre_techniques(
        fact_packet.get("mitre")
    ):
        _add_item_feature(
            techniques,
            technique.get("technique_id"),
            technique,
        )

    timeline_items.sort(
        key=lambda item: str(item.get("timestamp", ""))
    )
    for item in timeline_items:
        value = (
            item.get("rule_id")
            or item.get("behavior_type")
            or item.get("detection_id")
        )
        _add_item_feature(sequences, value, item)

    return {
        "detections": detections,
        "behaviors": behaviors,
        "mitre_techniques": techniques,
        "threat_profiles": profiles,
        "evidence_types": evidence_types,
        "attack_sequence": sequences,
    }


def _has_evidence(features: Dict[str, _FeatureEvidence]) -> bool:
    return any(feature.values for feature in features.values())


def _jaccard(
    current: Set[str],
    historical: Set[str],
) -> float:
    union = current | historical
    if not union:
        return 0.0
    return len(current & historical) / len(union)


def _refs_for_values(
    feature: _FeatureEvidence,
    values: Set[str],
) -> List[str]:
    return sorted(feature.refs_for(values))


def _factor(
    name: str,
    weight: int,
    current: _FeatureEvidence,
    historical: _FeatureEvidence,
) -> Dict[str, Any]:
    shared = current.values & historical.values
    current_only = current.values - historical.values
    historical_only = historical.values - current.values
    overlap = _jaccard(current.values, historical.values)
    contribution = round(weight * overlap, 2)

    return {
        "factor": name,
        "weight": weight,
        "score": contribution,
        "overlap": round(overlap, 4),
        "shared_values": sorted(shared),
        "current_only": sorted(current_only),
        "historical_only": sorted(historical_only),
        "current_evidence_refs": _refs_for_values(
            current,
            shared,
        ),
        "historical_evidence_refs": _refs_for_values(
            historical,
            shared,
        ),
        "explanation": (
            f"{len(shared)} shared value(s) across a union of "
            f"{len(current.values | historical.values)}; "
            f"weighted contribution {contribution}/{weight}."
        ),
    }


def _difference_summary(
    name: str,
    current: _FeatureEvidence,
    historical: _FeatureEvidence,
) -> Dict[str, Any]:
    return {
        "category": name,
        "current_only": sorted(current.values - historical.values),
        "historical_only": sorted(historical.values - current.values),
    }


def _limitations(
    current: Dict[str, _FeatureEvidence],
    historical: Dict[str, _FeatureEvidence],
) -> List[str]:
    limitations: List[str] = []

    if "synthetic" in current["evidence_types"].values or (
        "synthetic" in historical["evidence_types"].values
    ):
        limitations.append(
            "Synthetic telemetry is included as a comparison characteristic "
            "only and does not confirm real-world malicious activity."
        )

    if current["threat_profiles"].values or historical[
        "threat_profiles"
    ].values:
        limitations.append(
            "Threat-profile overlap is behavioral context only and does not "
            "establish malware attribution."
        )

    for name, label in (
        ("detections", "detections"),
        ("behaviors", "behaviors"),
        ("mitre_techniques", "MITRE techniques"),
        ("evidence_types", "evidence types"),
    ):
        if not current[name].values or not historical[name].values:
            limitations.append(
                f"One incident lacks comparable {label} representation."
            )

    return limitations


def _comparison(
    current_packet: Dict[str, Any],
    historical_packet: Dict[str, Any],
) -> HistoricalIncidentComparison:
    current_id = _incident_id(current_packet)
    historical_id = _incident_id(historical_packet)
    current = _feature_sets(current_packet)
    historical = _feature_sets(historical_packet)

    factor_specs = (
        ("detection_overlap", 25, "detections"),
        ("behavior_overlap", 20, "behaviors"),
        ("mitre_overlap", 20, "mitre_techniques"),
        ("threat_profile_overlap", 15, "threat_profiles"),
        ("attack_sequence_similarity", 10, "attack_sequence"),
        ("evidence_type_overlap", 10, "evidence_types"),
    )

    factors = [
        _factor(
            name,
            weight,
            current[feature_name],
            historical[feature_name],
        )
        for name, weight, feature_name in factor_specs
    ]

    similarity_score = round(
        sum(float(factor["score"]) for factor in factors),
        2,
    )

    if similarity_score >= 70:
        similarity_level = "strong"
    elif similarity_score >= 40:
        similarity_level = "moderate"
    elif similarity_score > 0:
        similarity_level = "weak"
    else:
        similarity_level = "none"

    shared_evidence_characteristics = sorted(
        current["evidence_types"].values
        & historical["evidence_types"].values
    )

    evidence_refs = {
        "current": sorted(
            ref
            for feature in current.values()
            for refs in feature.refs_by_value.values()
            for ref in refs
        ),
        "historical": sorted(
            ref
            for feature in historical.values()
            for refs in feature.refs_by_value.values()
            for ref in refs
        ),
    }

    return HistoricalIncidentComparison(
        current_incident_id=current_id,
        historical_incident_id=historical_id,
        similarity_score=similarity_score,
        similarity_level=similarity_level,
        similarity_factors=factors,
        shared_behaviors=sorted(
            current["behaviors"].values
            & historical["behaviors"].values
        ),
        shared_detections=sorted(
            current["detections"].values
            & historical["detections"].values
        ),
        shared_mitre_techniques=sorted(
            current["mitre_techniques"].values
            & historical["mitre_techniques"].values
        ),
        shared_threat_profiles=sorted(
            current["threat_profiles"].values
            & historical["threat_profiles"].values
        ),
        shared_evidence_characteristics=(
            shared_evidence_characteristics
        ),
        differences=[
            _difference_summary(
                feature_name,
                current[feature_name],
                historical[feature_name],
            )
            for feature_name in (
                "detections",
                "behaviors",
                "mitre_techniques",
                "threat_profiles",
                "evidence_types",
            )
        ],
        evidence_refs=evidence_refs,
        limitations=_limitations(current, historical),
    )


def compare_historical_incidents(
    current_fact_packet: Dict[str, Any],
    historical_fact_packets: Iterable[Dict[str, Any]] | None,
) -> HistoricalComparisonResult:
    """
    Compare one current Fact Packet against supplied historical Fact Packets.

    No persistence is accessed. Invalid or insufficient historical packets are
    reported as limitations rather than being fabricated or inferred.
    """

    current_id = _incident_id(current_fact_packet)
    current_features = _feature_sets(current_fact_packet)
    limitations: List[str] = []

    if not current_id or not _has_evidence(current_features):
        return HistoricalComparisonResult(
            status="insufficient_evidence",
            current_incident_id=current_id,
            limitations=[
                "The current incident lacks a usable identifier or "
                "comparable evidence representation."
            ],
            insufficient_evidence=True,
        )

    if historical_fact_packets is None:
        return HistoricalComparisonResult(
            status="no_meaningful_match",
            current_incident_id=current_id,
            limitations=[
                "No historical incident representations were supplied."
            ],
        )

    historical_fact_packets = list(
        historical_fact_packets
    )

    if not historical_fact_packets:
        return HistoricalComparisonResult(
            status="no_meaningful_match",
            current_incident_id=current_id,
            limitations=[
                "No historical incident representations were supplied."
            ],
        )

    comparisons: List[HistoricalIncidentComparison] = []
    usable_history = 0

    for historical_packet in historical_fact_packets:
        if not isinstance(historical_packet, dict):
            limitations.append(
                "A supplied historical incident was not a Fact Packet."
            )
            continue

        historical_id = _incident_id(historical_packet)
        if not historical_id:
            limitations.append(
                "A supplied historical incident lacks an incident identifier."
            )
            continue

        if historical_id == current_id:
            limitations.append(
                f"Historical incident {historical_id} was skipped because "
                "it is the current incident."
            )
            continue

        historical_features = _feature_sets(historical_packet)
        if not _has_evidence(historical_features):
            limitations.append(
                f"Historical incident {historical_id} lacks comparable "
                "evidence representation."
            )
            continue

        usable_history += 1
        comparisons.append(
            _comparison(
                current_fact_packet,
                historical_packet,
            )
        )

    if not comparisons:
        if usable_history == 0 and limitations:
            return HistoricalComparisonResult(
                status="insufficient_evidence",
                current_incident_id=current_id,
                limitations=limitations,
                insufficient_evidence=True,
            )

        return HistoricalComparisonResult(
            status="no_meaningful_match",
            current_incident_id=current_id,
            limitations=limitations,
        )

    comparisons.sort(
        key=lambda comparison: (
            -comparison.similarity_score,
            comparison.historical_incident_id,
        )
    )

    if comparisons[0].similarity_level == "none":
        status = "no_meaningful_match"
    else:
        status = "match_found"

    return HistoricalComparisonResult(
        status=status,
        current_incident_id=current_id,
        comparisons=comparisons,
        limitations=limitations,
        insufficient_evidence=False,
    )


__all__ = [
    "HistoricalIncidentComparison",
    "HistoricalComparisonResult",
    "compare_historical_incidents",
]
