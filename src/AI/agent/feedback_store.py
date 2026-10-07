"""
Analyst Feedback Loop storage and validation component for SentinelMesh.

Provides structured analyst feedback collection and validation.
CRITICAL SAFETY CONSTRAINTS:
1. Feedback does NOT modify the deterministic security engine.
2. Feedback does NOT alter risk scores, rules, MITRE mappings, evidence, or attribution.
3. Feedback is stored as auditable metadata signals for future evaluation.
4. Input validation rejects invalid types, missing fields, non-existent references, and prompt injection attempts.
"""

from __future__ import annotations

import datetime
import threading
import uuid
from typing import Any, Dict, List, Optional, Set

from .guardrails import detect_prompt_injection
from .models import AnalystFeedback, InvestigationResponse

VALID_FEEDBACK_TYPES: Set[str] = {
    "helpful",
    "not_helpful",
    "correct",
    "incorrect",
    "missing_evidence",
    "incorrect_priority",
    "incorrect_explanation",
    "incorrect_recommendation",
    "incorrect_mitre_interpretation",
    "attribution_concern",
    "other",
}

VALID_TARGET_COMPONENTS: Set[str] = {
    "summary",
    "investigation_summary",
    "observed_facts",
    "risk_explanation",
    "natural_language_explanation",
    "nlp_risk_explanation",
    "evidence_gaps",
    "attack_sequence",
    "historical_comparison",
    "mitre_investigation",
    "recommendation",
    "next_investigation_steps",
    "counterfactual_scenario",
    "counterfactual_investigation",
}


def _extract_fact_packet_refs(fact_packet: Dict[str, Any]) -> Set[str]:
    refs: Set[str] = set()
    for section in ("evidence", "detections", "events", "behaviors", "behavior_detections"):
        items = fact_packet.get(section, [])
        if isinstance(items, list):
            for item in items:
                if isinstance(item, dict):
                    for k in ("evidence_id", "detection_id", "event_id", "telemetry_id", "behavior_detection_id", "id", "source_record"):
                        v = item.get(k)
                        if v and isinstance(v, str):
                            refs.add(v)
    return refs


def _extract_recommendation_refs(response: Any) -> Set[str]:
    refs: Set[str] = set()
    if isinstance(response, InvestigationResponse):
        for step in response.next_investigation_steps:
            if hasattr(step, "action") and step.action:
                refs.add(step.action)
    elif isinstance(response, dict):
        steps = response.get("next_investigation_steps", [])
        if isinstance(steps, list):
            for step in steps:
                if isinstance(step, dict) and step.get("action"):
                    refs.add(step["action"])
    return refs


def _extract_counterfactual_refs(response: Any) -> Set[str]:
    refs: Set[str] = set()
    cf = None
    if isinstance(response, InvestigationResponse):
        cf = response.counterfactual_investigation
    elif isinstance(response, dict):
        cf = response.get("counterfactual_investigation")

    if isinstance(cf, dict):
        scenarios = cf.get("scenarios", [])
        if isinstance(scenarios, list):
            for sc in scenarios:
                if isinstance(sc, dict) and sc.get("scenario_id"):
                    refs.add(sc["scenario_id"])
    return refs


class FeedbackValidationError(ValueError):
    """Raised when analyst feedback fails validation checks."""
    pass


def validate_feedback(
    feedback: AnalystFeedback | Dict[str, Any],
    fact_packet: Dict[str, Any] | None = None,
    response: Any = None,
) -> AnalystFeedback:
    """
    Validate analyst feedback against SentinelMesh schema and grounding constraints.
    """
    if isinstance(feedback, dict):
        fb_dict = feedback
        fb_obj = AnalystFeedback(
            feedback_id=str(fb_dict.get("feedback_id") or uuid.uuid4().hex),
            incident_id=str(fb_dict.get("incident_id") or ""),
            target_component=str(fb_dict.get("target_component") or ""),
            feedback_type=str(fb_dict.get("feedback_type") or ""),
            analyst_id=fb_dict.get("analyst_id"),
            timestamp=fb_dict.get("timestamp"),
            rating=fb_dict.get("rating"),
            comment=fb_dict.get("comment"),
            referenced_response_field=fb_dict.get("referenced_response_field"),
            evidence_refs=list(fb_dict.get("evidence_refs") or []),
            recommendation_refs=list(fb_dict.get("recommendation_refs") or []),
            historical_comparison_refs=list(fb_dict.get("historical_comparison_refs") or []),
            counterfactual_refs=list(fb_dict.get("counterfactual_refs") or []),
            model_version=fb_dict.get("model_version"),
            created_at=fb_dict.get("created_at"),
        )
    elif isinstance(feedback, AnalystFeedback):
        fb_obj = feedback
    else:
        raise FeedbackValidationError("Feedback must be a dict or AnalystFeedback instance.")

    # 1. Incident ID required
    if not fb_obj.incident_id or not fb_obj.incident_id.strip():
        raise FeedbackValidationError("incident_id is required and cannot be empty.")

    # 2. Match fact packet incident ID if supplied
    if fact_packet:
        inc = fact_packet.get("incident", {})
        if isinstance(inc, dict) and inc.get("incident_id"):
            if str(inc["incident_id"]) != fb_obj.incident_id:
                raise FeedbackValidationError(
                    f"Feedback incident_id '{fb_obj.incident_id}' does not match fact packet '{inc['incident_id']}'."
                )

    # 3. Validate feedback_type
    if fb_obj.feedback_type not in VALID_FEEDBACK_TYPES:
        raise FeedbackValidationError(
            f"Invalid feedback_type '{fb_obj.feedback_type}'. Allowed types: {sorted(list(VALID_FEEDBACK_TYPES))}"
        )

    # 4. Validate target_component
    if fb_obj.target_component not in VALID_TARGET_COMPONENTS:
        raise FeedbackValidationError(
            f"Invalid target_component '{fb_obj.target_component}'. Allowed components: {sorted(list(VALID_TARGET_COMPONENTS))}"
        )

    # 5. Validate referenced_response_field if provided
    if fb_obj.referenced_response_field:
        allowed_fields = set(InvestigationResponse.__dataclass_fields__.keys())
        if fb_obj.referenced_response_field not in allowed_fields:
            raise FeedbackValidationError(
                f"Referenced response field '{fb_obj.referenced_response_field}' does not exist on InvestigationResponse."
            )

    # 6. Validate evidence_refs against fact packet
    if fact_packet and fb_obj.evidence_refs:
        available_refs = _extract_fact_packet_refs(fact_packet)
        invalid_refs = [r for r in fb_obj.evidence_refs if r not in available_refs]
        if invalid_refs:
            raise FeedbackValidationError(
                f"Referenced evidence ID(s) {invalid_refs} do not exist in the incident Fact Packet."
            )

    # 7. Validate recommendation_refs against response
    if response and fb_obj.recommendation_refs:
        avail_recs = _extract_recommendation_refs(response)
        invalid_recs = [r for r in fb_obj.recommendation_refs if r not in avail_recs]
        if invalid_recs:
            raise FeedbackValidationError(
                f"Referenced recommendation action(s) {invalid_recs} do not exist in the investigation response."
            )

    # 8. Validate counterfactual_refs against response
    if response and fb_obj.counterfactual_refs:
        avail_cfs = _extract_counterfactual_refs(response)
        invalid_cfs = [r for r in fb_obj.counterfactual_refs if r not in avail_cfs]
        if invalid_cfs:
            raise FeedbackValidationError(
                f"Referenced counterfactual scenario ID(s) {invalid_cfs} do not exist in the investigation response."
            )

    # 9. Prompt injection check on comment and text fields
    for text_field in (fb_obj.comment, fb_obj.target_component, fb_obj.feedback_type):
        if text_field and detect_prompt_injection(text_field):
            raise FeedbackValidationError("Feedback submission rejected: prompt injection pattern detected in input text.")

    # Populate timestamps if missing
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    if not fb_obj.timestamp:
        fb_obj.timestamp = now_iso
    if not fb_obj.created_at:
        fb_obj.created_at = now_iso

    return fb_obj


class FeedbackStore:
    """
    In-memory storage abstraction for Analyst Feedback records.
    Thread-safe and persistent for session lifecycle.
    """

    def __init__(self) -> None:
        self._store: Dict[str, AnalystFeedback] = {}
        self._lock = threading.Lock()

    def add_feedback(
        self,
        feedback: AnalystFeedback | Dict[str, Any],
        fact_packet: Dict[str, Any] | None = None,
        response: Any = None,
    ) -> AnalystFeedback:

        validated = validate_feedback(feedback, fact_packet=fact_packet, response=response)

        with self._lock:
            self._store[validated.feedback_id] = validated

        return validated

    def get_feedback(self, feedback_id: str) -> AnalystFeedback | None:
        with self._lock:
            return self._store.get(feedback_id)

    def list_feedback(self) -> List[AnalystFeedback]:
        with self._lock:
            return list(self._store.values())

    def list_feedback_for_incident(self, incident_id: str) -> List[AnalystFeedback]:
        with self._lock:
            return [fb for fb in self._store.values() if fb.incident_id == incident_id]

    def list_feedback_by_target(self, target_component: str) -> List[AnalystFeedback]:
        with self._lock:
            return [fb for fb in self._store.values() if fb.target_component == target_component]

    def clear(self) -> None:
        with self._lock:
            self._store.clear()
