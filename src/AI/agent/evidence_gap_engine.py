from dataclasses import dataclass
from typing import Any, Dict, List, Set


@dataclass(frozen=True)
class EvidenceGap:
    gap_id: str
    category: str
    description: str
    why_it_matters: str
    priority: str
    blocking: bool
    supporting_refs: List[str]


@dataclass(frozen=True)
class EvidenceGapAnalysis:
    gaps: List[EvidenceGap]
    visibility_score: int
    sufficient_for_investigation: bool

    def to_dict(self) -> Dict[str, Any]:
        return {
            "gaps": [
                {
                    "gap_id": g.gap_id,
                    "category": g.category,
                    "description": g.description,
                    "why_it_matters": g.why_it_matters,
                    "priority": g.priority,
                    "blocking": g.blocking,
                    "supporting_refs": list(g.supporting_refs),
                }
                for g in self.gaps
            ],
            "visibility_score": self.visibility_score,
            "sufficient_for_investigation": self.sufficient_for_investigation,
        }

    def gap_messages(self) -> List[str]:
        return [g.description for g in self.gaps]


class EvidenceGapEngine:
    REF_KEYS = (
        "evidence_id", "detection_id", "event_id", "telemetry_id",
        "behavior_detection_id", "id", "source_record",
        "source_detection", "source_telemetry",
    )

    def _items(self, packet: Dict[str, Any], section: str) -> List[Dict[str, Any]]:
        value = packet.get(section, [])
        return [x for x in value if isinstance(x, dict)] if isinstance(value, list) else []

    def _refs(self, packet: Dict[str, Any]) -> Set[str]:
        refs: Set[str] = set()
        for section in ("evidence", "detections", "events", "behaviors", "behavior_detections"):
            for item in self._items(packet, section):
                for key in self.REF_KEYS:
                    if item.get(key) is not None and str(item.get(key)):
                        refs.add(str(item[key]))
                for key in ("evidence_refs", "supporting_evidence_refs"):
                    value = item.get(key, [])
                    if isinstance(value, str):
                        refs.add(value)
                    elif isinstance(value, list):
                        refs.update(str(v) for v in value if v is not None and str(v))
        return refs

    def analyze(self, fact_packet: Dict[str, Any]) -> EvidenceGapAnalysis:
        packet = fact_packet if isinstance(fact_packet, dict) else {}
        refs = self._refs(packet)
        events = self._items(packet, "events")
        behaviors = self._items(packet, "behaviors")
        detections = self._items(packet, "detections") + self._items(packet, "behavior_detections")
        evidence = self._items(packet, "evidence")
        gaps: List[EvidenceGap] = []

        raw_event_context = any(bool(e.get("raw_data")) for e in events + evidence)
        if not raw_event_context and (events or any("SM-" in r for r in refs) or detections):
            gaps.append(EvidenceGap("GAP-RAW-WINDOWS", "raw_windows_event", "Raw Windows event records are not present in the supplied evidence.", "Raw event fields are needed to verify what the Windows detection actually observed.", "critical", True, sorted(refs)))

        behavior_context = bool(behaviors) or any("telemetry" in r.lower() for r in refs)
        if not behavior_context and self._items(packet, "behavior_detections"):
            gaps.append(EvidenceGap("GAP-BEHAVIOR-TELEMETRY", "behavior_telemetry", "Behavior detections are present without the underlying behavior telemetry records.", "Without the source telemetry, the behavioral signal cannot be independently inspected.", "high", True, sorted(refs)))

        text = " ".join(str(x.get(k, "")) for x in detections + behaviors + evidence for k in ("description", "behavior_type", "rule_name", "incident_type", "process_name", "command_line")).lower()
        if any(t in text for t in ("execution", "process", "script", "command", "persistence")) and not any(k in text for k in ("process_name", "process", "image", "command_line")):
            gaps.append(EvidenceGap("GAP-PROCESS-CONTEXT", "process_context", "Process execution context is not present for process-related activity.", "Process identity and execution context are needed to distinguish benign activity from suspicious execution.", "medium", False, sorted(refs)))
        if any(t in text for t in ("network", "command_and_control", "command and control", "c2", "outbound", "connection")) and not packet.get("entities", {}).get("ips"):
            gaps.append(EvidenceGap("GAP-NETWORK-CONTEXT", "network_context", "Network context is not present for network-related activity.", "Network destinations and connection context are needed to investigate command-and-control or outbound activity.", "high", True, sorted(refs)))
        if any(t in text for t in ("account", "user", "credential", "logon", "privilege")) and not packet.get("entities", {}).get("users"):
            gaps.append(EvidenceGap("GAP-USER-CONTEXT", "user_context", "User context is not present for account or credential-related activity.", "User identity and logon context help distinguish administrative activity from suspicious account behavior.", "medium", False, sorted(refs)))
        if any(b.get("synthetic") is True for b in behaviors):
            gaps.append(EvidenceGap("GAP-SYNTHETIC-CONTEXT", "synthetic_telemetry", "Some behavior telemetry is synthetic and cannot be treated as confirmed real-world activity.", "Synthetic signals are useful for correlation and testing but must remain explicitly non-confirmatory.", "low", False, sorted(refs)))

        penalties = {"critical": 35, "high": 20, "medium": 10, "low": 5}
        score = max(0, 100 - sum(penalties[g.priority] for g in gaps))
        sufficient = not any(g.blocking for g in gaps)
        return EvidenceGapAnalysis(gaps, score, sufficient)


def analyze_evidence_gaps(fact_packet: Dict[str, Any]) -> EvidenceGapAnalysis:
    return EvidenceGapEngine().analyze(fact_packet)
