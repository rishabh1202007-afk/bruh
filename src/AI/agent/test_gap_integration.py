import json
import sys

sys.path.insert(0, "/tmp/sm_ai_test")

from AI.agent.structured_llm_investigator import (
    StructuredLLMInvestigator,
)
from AI.llm.models import LLMResponse


class FakeInvestigator:
    def __init__(self, response):
        self.response = response
        self.last_kwargs = None

    def investigate(self, **kwargs):
        self.last_kwargs = kwargs

        return LLMResponse(
            text=json.dumps(self.response),
            model="test-model",
            provider="fake",
            request_id="fake-request-001",
            metadata={},
        )


def base_response(status="investigating"):
    return {
        "status": status,
        "summary": "Model summary",
        "observed_facts": [],
        "knowledge_context": [],
        "uncertainties": [],
        "evidence_gaps": [],
        "next_investigation_steps": [],
        "safety_warnings": [],
        "grounded": True,
        "insufficient_evidence": (
            status == "insufficient_evidence"
        ),
    }


def test_blocking_gap_forces_insufficient_evidence():
    fake = FakeInvestigator(
        base_response()
    )

    svc = StructuredLLMInvestigator(
        investigator=fake
    )

    packet = {
        "incident": {
            "incident_id": "INC-GAP-001"
        },
        "detections": [
            {
                "detection_id": "SM-003",
                "rule_name": (
                    "Credential Manager Activity"
                ),
            }
        ],
        "events": [],
        "behaviors": [],
        "behavior_detections": [],
        "evidence": [],
    }

    result = svc.investigate(packet)

    assert (
        result.status
        == "insufficient_evidence"
    )

    assert (
        result.insufficient_evidence
        is True
    )

    assert any(
        "Raw Windows event records" in gap
        for gap in result.evidence_gaps
    )

    assert (
        "DETERMINISTIC EVIDENCE-GAP ANALYSIS"
        in fake.last_kwargs["analyst_question"]
    )


def test_nonblocking_gap_does_not_force_insufficient_evidence():
    fake = FakeInvestigator(
        base_response()
    )

    svc = StructuredLLMInvestigator(
        investigator=fake
    )

    packet = {
        "incident": {
            "incident_id": "INC-GAP-002"
        },
        "events": [
            {
                "event_id": "EV-1",
                "raw_data": ["user"],
            }
        ],
        "detections": [
            {
                "detection_id": "D-1",
                "rule_name": "Privilege Activity",
            }
        ],
        "behaviors": [],
        "behavior_detections": [],
        "evidence": [],
    }

    result = svc.investigate(packet)

    assert (
        result.status
        == "investigating"
    )

    assert (
        result.insufficient_evidence
        is False
    )

    assert any(
        "User context" in gap
        for gap in result.evidence_gaps
    )


def test_synthetic_gap_is_preserved_as_warning():
    fake = FakeInvestigator(
        base_response()
    )

    svc = StructuredLLMInvestigator(
        investigator=fake
    )

    packet = {
        "incident": {
            "incident_id": "INC-GAP-003"
        },
        "events": [
            {
                "event_id": "EV-1",
                "raw_data": ["x"],
            }
        ],
        "detections": [],
        "behaviors": [
            {
                "telemetry_id": "TEL-1",
                "synthetic": True,
                "behavior_type": (
                    "browser_data_access"
                ),
            }
        ],
        "behavior_detections": [],
        "evidence": [],
    }

    result = svc.investigate(packet)

    assert any(
        "Synthetic telemetry must not be treated"
        in warning
        for warning in result.safety_warnings
    )


if __name__ == "__main__":
    test_blocking_gap_forces_insufficient_evidence()
    test_nonblocking_gap_does_not_force_insufficient_evidence()
    test_synthetic_gap_is_preserved_as_warning()

    print("3 passed")