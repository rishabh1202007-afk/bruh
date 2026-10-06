"""
Bridge real SentinelMesh incidents into the AI investigation pipeline.

This module deliberately does not perform detection, correlation, MITRE mapping,
or risk scoring. It consumes the deterministic incident produced by SentinelMesh,
constructs the canonical Fact Packet, automatically assembles the existing
two-layer RAG context, and hands both to the structured AI investigator.

Important:
- Deterministic SentinelMesh output remains the source of truth.
- Synthetic telemetry remains explicitly synthetic.
- Behavioral profile alignment is never converted into malware attribution.
- Missing telemetry is represented as an evidence gap.
- Retrieved RAG knowledge is context only, never incident evidence.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

from ..fact_packet.builder import build_fact_packet
from ..rag.fact_packet_context import (
    RAGContext,
    build_rag_context,
)
from .investigation_agent import InvestigationResponse
from .structured_llm_investigator import (
    StructuredLLMInvestigator,
)


DEFAULT_INCIDENT_FILE = (
    "data/raw/final_risk_scored_incidents.jsonl"
)

DEFAULT_RAG_TOP_K = 5


class SentinelMeshInvestigationService:
    def __init__(
        self,
        model: str = "qwen3:8b",
        temperature: float = 0.0,
        max_output_tokens: int = 1200,
        investigator: StructuredLLMInvestigator | None = None,
        rag_top_k: int = DEFAULT_RAG_TOP_K,
    ):
        self.investigator = investigator or StructuredLLMInvestigator(
            model=model,
            temperature=temperature,
            max_output_tokens=max_output_tokens,
        )

        if rag_top_k <= 0:
            raise ValueError(
                "rag_top_k must be greater than zero."
            )

        self.rag_top_k = rag_top_k

    @staticmethod
    def build_fact_packet(
        incident: Dict[str, Any],
    ) -> Dict[str, Any]:
        evidence = _as_dict_list(
            incident.get("evidence")
        )

        normalized_evidence: List[Dict[str, Any]] = []
        detections: List[Dict[str, Any]] = []
        behaviors: List[Dict[str, Any]] = []
        behavior_detections: List[Dict[str, Any]] = []

        for item in evidence:
            evidence_record = dict(item)
            source = item.get("source")

            if source == "windows_security":
                detections.append(
                    dict(evidence_record)
                )

            elif source == "behavior_telemetry":
                telemetry_id = evidence_record.get(
                    "telemetry_id"
                )

                # Raw telemetry is identified by telemetry_id.
                # Detection-shaped records must not be copied into
                # behaviors just because their source is
                # behavior_telemetry.
                if telemetry_id:
                    behavior = _behavior_from_evidence(
                        evidence_record
                    )
                    behaviors.append(behavior)

                    evidence_record.setdefault(
                        "source_telemetry",
                        telemetry_id,
                    )

                behavior_detection = (
                    _behavior_detection_from_evidence(
                        evidence_record
                    )
                )

                if behavior_detection:
                    behavior_detections.append(
                        behavior_detection
                    )

                    evidence_record.setdefault(
                        "detection_id",
                        behavior_detection[
                            "detection_id"
                        ],
                    )

                    if behavior_detection.get(
                        "source_telemetry"
                    ):
                        evidence_record.setdefault(
                            "source_telemetry",
                            behavior_detection[
                                "source_telemetry"
                            ],
                        )

            normalized_evidence.append(
                evidence_record
            )

        mitre_context = incident.get(
            "mitre_context",
            {},
        )

        if not isinstance(
            mitre_context,
            dict,
        ):
            mitre_context = {}

        mitre = _as_dict_list(
            mitre_context.get(
                "combined_techniques"
            )
        )

        packet = build_fact_packet(
            incident=incident,
            detections=detections,
            behaviors=behaviors,
            behavior_detections=behavior_detections,
            mitre=mitre,
            risk=incident.get(
                "risk_scoring",
                {},
            ),
            evidence=normalized_evidence,
        )

        _add_source_visibility_gaps(
            packet,
            incident,
        )

        _add_safety_context(
            packet,
            incident,
        )

        return packet

    def build_rag_context(
        self,
        fact_packet: Dict[str, Any],
    ) -> RAGContext:
        """
        Build the existing deterministic two-layer RAG context.

        This does not create a new retriever. It delegates to the existing
        Fact Packet -> RAG Context builder so the same query generation,
        retrieval, provenance, and insufficient-evidence behavior are used
        everywhere.
        """

        return build_rag_context(
            fact_packet=fact_packet,
            top_k=self.rag_top_k,
        )

    @staticmethod
    def _normalize_retrieval_context(
        retrieval_context: Any,
    ) -> Dict[str, Any]:
        """
        Convert supported RAG context objects into the dictionary form
        expected by the prompt builder and deterministic evidence validator.
        """

        if isinstance(
            retrieval_context,
            RAGContext,
        ):
            return retrieval_context.to_dict()

        if isinstance(
            retrieval_context,
            dict,
        ):
            return retrieval_context

        if (
            retrieval_context is not None
            and hasattr(
                retrieval_context,
                "to_dict",
            )
        ):
            normalized = (
                retrieval_context.to_dict()
            )

            if isinstance(
                normalized,
                dict,
            ):
                return normalized

        raise TypeError(
            "retrieval_context must be a dictionary "
            "or an object providing to_dict()."
        )

    def prepare_investigation_context(
        self,
        incident: Dict[str, Any],
        retrieval_context: Any = None,
    ) -> tuple[
        Dict[str, Any],
        Dict[str, Any],
    ]:
        """
        Build the canonical Fact Packet and the RAG context used for AI.

        If no retrieval context is supplied, the existing deterministic RAG
        pipeline is assembled automatically from the Fact Packet.
        """

        fact_packet = self.build_fact_packet(
            incident
        )

        if retrieval_context is None:
            rag_context = self.build_rag_context(
                fact_packet
            )

            retrieval_context_dict = (
                rag_context.to_dict()
            )

        else:
            retrieval_context_dict = (
                self._normalize_retrieval_context(
                    retrieval_context
                )
            )

        return (
            fact_packet,
            retrieval_context_dict,
        )

    def investigate(
        self,
        incident: Dict[str, Any],
        retrieval_context: Any = None,
        analyst_question: str | None = None,
    ) -> InvestigationResponse:

        (
            fact_packet,
            retrieval_context_dict,
        ) = self.prepare_investigation_context(
            incident=incident,
            retrieval_context=retrieval_context,
        )

        return self.investigator.investigate(
            fact_packet=fact_packet,
            retrieval_context=retrieval_context_dict,
            analyst_question=analyst_question,
        )

    def investigate_from_jsonl(
        self,
        incident_id: str,
        path: str = DEFAULT_INCIDENT_FILE,
        retrieval_context: Any = None,
        analyst_question: str | None = None,
    ) -> InvestigationResponse:

        incident = load_incident_from_jsonl(
            path=path,
            incident_id=incident_id,
        )

        return self.investigate(
            incident=incident,
            retrieval_context=retrieval_context,
            analyst_question=analyst_question,
        )


def load_incident_from_jsonl(
    path: str,
    incident_id: str,
) -> Dict[str, Any]:

    file_path = Path(path)

    if not file_path.exists():
        raise FileNotFoundError(
            f"Incident JSONL file not found: {file_path}"
        )

    with file_path.open(
        "r",
        encoding="utf-8",
    ) as handle:

        for line_number, line in enumerate(
            handle,
            start=1,
        ):
            line = line.strip()

            if not line:
                continue

            try:
                record = json.loads(
                    line
                )

            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"Invalid JSON on line "
                    f"{line_number}: {exc}"
                ) from exc

            if not isinstance(
                record,
                dict,
            ):
                continue

            if (
                record.get("incident_id")
                == incident_id
            ):
                return record

    raise KeyError(
        f"Incident '{incident_id}' was not found "
        f"in {file_path}."
    )


def _as_dict_list(
    value: Any,
) -> List[Dict[str, Any]]:

    if not isinstance(
        value,
        list,
    ):
        return []

    return [
        dict(item)
        for item in value
        if isinstance(
            item,
            dict,
        )
    ]


def _behavior_from_evidence(
    item: Dict[str, Any],
) -> Dict[str, Any]:

    behavior = dict(item)
    telemetry_id = behavior.get("telemetry_id")

    if telemetry_id:
        behavior["telemetry_id"] = telemetry_id

    return behavior


def _behavior_detection_from_evidence(
    item: Dict[str, Any],
) -> Dict[str, Any] | None:

    rule_id = item.get("rule_id")
    rule_name = item.get("rule_name")
    telemetry_id = (
        item.get("telemetry_id")
        or item.get("source_telemetry")
    )

    if not (
        rule_id
        or rule_name
        or item.get("detection_id")
        or item.get("behavior_detection_id")
    ):
        return None

    detection = dict(item)

    detection_id = (
        detection.get("detection_id")
        or detection.get("behavior_detection_id")
    )

    if not detection_id and rule_id and telemetry_id:
        detection_id = f"{rule_id}-{telemetry_id}"

    if not detection_id and rule_id:
        detection_id = str(rule_id)

    if not detection_id:
        return None

    detection["detection_id"] = detection_id

    if telemetry_id:
        detection["source_telemetry"] = telemetry_id

    return detection


def _add_source_visibility_gaps(
    packet: Dict[str, Any],
    incident: Dict[str, Any],
) -> None:

    gaps = list(
        packet.get(
            "evidence_gaps",
            [],
        )
    )

    evidence = _as_dict_list(
        incident.get("evidence")
    )

    events = incident.get(
        "events",
        [],
    )

    behavior_detections = packet.get(
        "behavior_detections",
        [],
    )

    raw_behaviors = [
        item
        for item in packet.get("behaviors", [])
        if isinstance(item, dict)
        and item.get("telemetry_id")
    ]

    behavior_evidence = [
        item
        for item in evidence
        if item.get("source")
        == "behavior_telemetry"
    ]

    if (
        evidence
        and not isinstance(
            events,
            list,
        )
    ):
        gaps.append(
            "The supplied incident does not include "
            "a usable raw event collection."
        )

    if (
        evidence
        and not packet.get("events")
    ):
        gaps.append(
            "The incident evidence does not include "
            "raw event records."
        )

    if (
        (
            behavior_evidence
            or behavior_detections
        )
        and not raw_behaviors
    ):
        gaps.append(
            "The incident contains behavior detections "
            "but not raw behavior telemetry records."
        )

    packet["evidence_gaps"] = (
        _deduplicate(gaps)
    )


def _add_safety_context(
    packet: Dict[str, Any],
    incident: Dict[str, Any],
) -> None:

    uncertainties = list(
        packet.get(
            "uncertainties",
            [],
        )
    )

    enrichment = incident.get(
        "enrichment",
        {},
    )

    if not isinstance(
        enrichment,
        dict,
    ):
        enrichment = {}

    if (
        enrichment.get(
            "synthetic_evidence"
        )
        is True
    ):
        uncertainties.append(
            "The incident enrichment marks supporting "
            "behavior telemetry as synthetic. Synthetic "
            "telemetry must not be presented as confirmed "
            "real-world malicious activity."
        )

    attribution_status = (
        enrichment.get(
            "attribution_status"
        )
    )

    if attribution_status:
        uncertainties.append(
            "Attribution status supplied by SentinelMesh: "
            f"{attribution_status}."
        )

    analyst_interpretation = (
        enrichment.get(
            "analyst_interpretation"
        )
    )

    if analyst_interpretation:
        uncertainties.append(
            "SentinelMesh analyst interpretation: "
            f"{analyst_interpretation}"
        )

    packet["uncertainties"] = (
        _deduplicate(
            uncertainties
        )
    )


def _deduplicate(
    values: Any,
) -> List[str]:

    seen = set()
    result: List[str] = []

    if not isinstance(
        values,
        list,
    ):
        return result

    for value in values:

        if not isinstance(
            value,
            str,
        ):
            continue

        if value in seen:
            continue

        seen.add(value)
        result.append(value)

    return result


def investigate_incident_with_ollama(
    incident: Dict[str, Any],
    retrieval_context: Any = None,
    analyst_question: str | None = None,
) -> InvestigationResponse:

    service = SentinelMeshInvestigationService(
        model="qwen3:8b",
        temperature=0.0,
        max_output_tokens=1200,
    )

    return service.investigate(
        incident=incident,
        retrieval_context=retrieval_context,
        analyst_question=analyst_question,
    )


__all__ = [
    "DEFAULT_INCIDENT_FILE",
    "DEFAULT_RAG_TOP_K",
    "SentinelMeshInvestigationService",
    "load_incident_from_jsonl",
    "investigate_incident_with_ollama",
]
