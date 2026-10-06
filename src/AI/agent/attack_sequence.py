"""
Deterministic attack-sequence reconstruction for SentinelMesh.

This module orders only evidence already represented in a Fact Packet or
Incident Intelligence Graph. It does not infer missing attacker actions.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Set

from ..fact_packet.builder import canonical_mitre_techniques
from ..graph.graph_queries import get_attack_sequence


SEQUENCE_NODE_TYPES = {
    "event",
    "detection",
    "behavior_telemetry",
    "behavior_detection",
}


@dataclass
class AttackSequenceStep:
    order: int
    step_id: str
    step_type: str
    timestamp: str | None
    description: str
    source_reference: str | None = None
    detection_reference: str | None = None
    behavior_reference: str | None = None
    mitre_technique: str | None = None
    tactic: str | None = None
    host: str | None = None
    evidence_refs: List[str] = field(default_factory=list)
    synthetic: bool = False
    grounded: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AttackSequenceResult:
    incident_id: str
    status: str
    steps: List[AttackSequenceStep] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)
    grounded: bool = True
    insufficient_evidence: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "status": self.status,
            "steps": [step.to_dict() for step in self.steps],
            "limitations": list(self.limitations),
            "grounded": self.grounded,
            "insufficient_evidence": self.insufficient_evidence,
        }


def _incident_id(fact_packet: Dict[str, Any]) -> str:
    incident = fact_packet.get("incident", {})
    if not isinstance(incident, dict):
        return ""
    value = incident.get("incident_id")
    return str(value).strip() if value else ""


def _as_dict_list(value: Any) -> List[Dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _refs(item: Dict[str, Any]) -> List[str]:
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

    return sorted(refs)


def _timestamp_key(value: Any) -> tuple[int, str]:
    if not value:
        return (1, "")

    text = str(value)
    try:
        parsed = datetime.fromisoformat(
            text.replace("Z", "+00:00")
        )
        return (0, parsed.isoformat())
    except ValueError:
        return (0, text)


def _source_reference(item: Dict[str, Any]) -> str | None:
    for key in (
        "source_record",
        "event_id",
        "detection_id",
        "telemetry_id",
        "behavior_detection_id",
    ):
        value = item.get(key)
        if value is not None and str(value):
            return str(value)
    return None


def _node_candidates(graph: Any) -> tuple[List[Dict[str, Any]], Dict[str, int]]:
    if graph is None or not hasattr(graph, "nodes"):
        return [], {}

    graph_order: Dict[str, int] = {}
    try:
        for index, item in enumerate(get_attack_sequence(graph)):
            node_id = item.get("node_id")
            if node_id:
                graph_order.setdefault(node_id, index)
    except (AttributeError, TypeError, ValueError):
        graph_order = {}

    candidates = []
    for node in graph.nodes:
        if node.node_type not in SEQUENCE_NODE_TYPES:
            continue
        properties = dict(node.properties)
        properties["_node_id"] = node.node_id
        properties["_node_type"] = node.node_type
        candidates.append(properties)

    return candidates, graph_order


def _packet_candidates(
    fact_packet: Dict[str, Any],
) -> List[Dict[str, Any]]:
    candidates: List[Dict[str, Any]] = []

    for section, step_type in (
        ("events", "event"),
        ("detections", "detection"),
        ("behaviors", "behavior_telemetry"),
        ("behavior_detections", "behavior_detection"),
    ):
        for index, item in enumerate(
            _as_dict_list(fact_packet.get(section))
        ):
            candidate = dict(item)
            candidate["_node_id"] = (
                f"{step_type}:{_source_reference(item) or index}"
            )
            candidate["_node_type"] = step_type
            candidate["_section_index"] = index
            candidates.append(candidate)

    return candidates


def _mitre_by_source(
    fact_packet: Dict[str, Any],
) -> Dict[str, Dict[str, Any]]:
    result: Dict[str, Dict[str, Any]] = {}
    for technique in canonical_mitre_techniques(
        fact_packet.get("mitre")
    ):
        source = technique.get("source_detection")
        technique_id = technique.get("technique_id")
        if source and technique_id:
            result[str(source)] = technique
    return result


def _step_from_candidate(
    candidate: Dict[str, Any],
    order: int,
    mitre_by_source: Dict[str, Dict[str, Any]],
) -> AttackSequenceStep:
    step_type = str(candidate.get("_node_type", "evidence"))
    source_reference = _source_reference(candidate)
    detection_reference = None
    behavior_reference = None

    if step_type in {"detection", "behavior_detection"}:
        detection_reference = source_reference
    if step_type == "behavior_telemetry":
        behavior_reference = source_reference

    technique = None
    for source_key in (
        source_reference,
        candidate.get("detection_id"),
        candidate.get("rule_id"),
    ):
        if source_key:
            technique = mitre_by_source.get(str(source_key))
            if technique:
                break

    description = (
        candidate.get("description")
        or candidate.get("rule_name")
        or candidate.get("event_type")
        or candidate.get("behavior_type")
        or step_type
    )

    return AttackSequenceStep(
        order=order,
        step_id=str(candidate.get("_node_id", f"step:{order}")),
        step_type=step_type,
        timestamp=(
            str(candidate["timestamp"])
            if candidate.get("timestamp") is not None
            else None
        ),
        description=str(description),
        source_reference=source_reference,
        detection_reference=detection_reference,
        behavior_reference=behavior_reference,
        mitre_technique=(
            str(technique.get("technique_id"))
            if technique
            else None
        ),
        tactic=(
            str(technique.get("tactic"))
            if technique and technique.get("tactic")
            else None
        ),
        host=(
            str(candidate["host"])
            if candidate.get("host") is not None
            else None
        ),
        evidence_refs=_refs(candidate),
        synthetic=candidate.get("synthetic") is True,
        grounded=True,
    )


def reconstruct_attack_sequence(
    fact_packet: Dict[str, Any],
    graph: Any = None,
) -> AttackSequenceResult:
    """
    Reconstruct an observed sequence from Fact Packet or graph evidence.

    Timestamps are primary ordering keys. Existing graph query order and
    stable source references provide deterministic tie-breakers.
    """

    if not isinstance(fact_packet, dict):
        return AttackSequenceResult(
            incident_id="",
            status="insufficient_evidence",
            limitations=["Fact Packet is not a dictionary."],
            insufficient_evidence=True,
        )

    incident_id = _incident_id(fact_packet)
    if not incident_id:
        return AttackSequenceResult(
            incident_id="",
            status="insufficient_evidence",
            limitations=[
                "The Fact Packet does not contain an incident identifier."
            ],
            insufficient_evidence=True,
        )

    graph_candidates, graph_order = _node_candidates(graph)
    candidates = graph_candidates or _packet_candidates(fact_packet)
    if not candidates:
        return AttackSequenceResult(
            incident_id=incident_id,
            status="insufficient_evidence",
            limitations=[
                "No timestamped or relationship-backed evidence steps "
                "are available."
            ],
            insufficient_evidence=True,
        )

    mitre_by_source = _mitre_by_source(fact_packet)

    indexed_candidates = list(enumerate(candidates))
    indexed_candidates.sort(
        key=lambda pair: (
            _timestamp_key(pair[1].get("timestamp")),
            graph_order.get(pair[1].get("_node_id", ""), 10**9),
            str(
                _source_reference(pair[1])
                or pair[1].get("_node_id", "")
            ),
            pair[0],
        )
    )

    steps = [
        _step_from_candidate(
            candidate,
            order,
            mitre_by_source,
        )
        for order, (_, candidate) in enumerate(
            indexed_candidates,
            start=1,
        )
    ]

    limitations: List[str] = []
    timestamped_steps = [step for step in steps if step.timestamp]
    synthetic_steps = [step for step in steps if step.synthetic]

    if not timestamped_steps:
        status = (
            "no_meaningful_sequence"
            if len(steps) == 1
            else "partial_sequence"
        )
        limitations.append(
            "Available evidence steps do not contain timestamps; ordering "
            "uses deterministic source references only."
        )
    elif len(timestamped_steps) < len(steps):
        status = "partial_sequence"
        limitations.append(
            "Some evidence steps lack timestamps and cannot be precisely "
            "placed in time."
        )
    elif len(steps) == 1:
        status = "partial_sequence"
        limitations.append(
            "Only one observed evidence step is available; no multi-step "
            "sequence can be established."
        )
    else:
        status = "complete_sequence"

    if synthetic_steps:
        limitations.append(
            "Synthetic behavior telemetry is included as a simulated "
            "behavioral signal and does not establish real-world malicious "
            "execution."
        )

    if any(step.mitre_technique for step in steps):
        limitations.append(
            "MITRE mappings describe behavior represented by telemetry and "
            "do not prove malware attribution or malicious intent."
        )

    return AttackSequenceResult(
        incident_id=incident_id,
        status=status,
        steps=steps,
        limitations=list(dict.fromkeys(limitations)),
        grounded=True,
        insufficient_evidence=False,
    )


__all__ = [
    "AttackSequenceStep",
    "AttackSequenceResult",
    "reconstruct_attack_sequence",
]
