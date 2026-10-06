from ..graph.graph_builder import build_incident_graph
from .attack_sequence import reconstruct_attack_sequence
from .investigation_agent import InvestigationAgent


def packet(
    detections=None,
    behaviors=None,
    behavior_detections=None,
    mitre=None,
    events=None,
):
    return {
        "incident": {
            "incident_id": "INC-SEQUENCE-CURRENT",
            "host": "TEST-HOST",
        },
        "correlation": {
            "rule_id": "CM-001",
            "conditions": {
                "same_host": True,
                "chronological_order": True,
            },
        },
        "events": events or [],
        "detections": detections or [],
        "behaviors": behaviors or [],
        "behavior_detections": behavior_detections or [],
        "mitre": {
            "combined_techniques": mitre or [],
        },
        "entities": {
            "hosts": ["TEST-HOST"],
            "users": [],
            "processes": [],
            "ips": [],
        },
        "evidence": [],
    }


def detection(rule_id, timestamp, source_record):
    return {
        "detection_id": rule_id,
        "rule_id": rule_id,
        "rule_name": rule_id,
        "timestamp": timestamp,
        "source_record": source_record,
        "host": "TEST-HOST",
    }


def behavior(behavior_type, timestamp, telemetry_id, synthetic=False):
    return {
        "behavior_type": behavior_type,
        "timestamp": timestamp,
        "telemetry_id": telemetry_id,
        "host": "TEST-HOST",
        "synthetic": synthetic,
        "source": "endpoint_behavior",
    }


def behavior_detection(rule_id, timestamp, detection_id, telemetry_id):
    return {
        "rule_id": rule_id,
        "rule_name": rule_id,
        "detection_id": detection_id,
        "timestamp": timestamp,
        "source_telemetry": telemetry_id,
        "host": "TEST-HOST",
    }


def technique(technique_id, source_detection):
    return {
        "technique_id": technique_id,
        "technique_name": technique_id,
        "tactic": "Discovery",
        "source_detection": source_detection,
    }


def test_chronological_ordering():
    fact_packet = packet(
        detections=[
            detection("SM-003", "2026-01-01T10:02:00Z", 1002),
            detection("SM-002", "2026-01-01T10:01:00Z", 1001),
        ]
    )

    result = reconstruct_attack_sequence(fact_packet)

    assert result.status == "complete_sequence"
    assert [step.source_reference for step in result.steps] == [
        "1001",
        "1002",
    ]


def test_equal_timestamp_uses_source_record_ordering():
    fact_packet = packet(
        detections=[
            detection("SM-003", "2026-01-01T10:00:00Z", 1002),
            detection("SM-002", "2026-01-01T10:00:00Z", 1001),
        ]
    )

    result = reconstruct_attack_sequence(fact_packet)

    assert [step.source_reference for step in result.steps] == [
        "1001",
        "1002",
    ]


def test_detection_to_mitre_sequence():
    fact_packet = packet(
        detections=[
            detection("SM-002", "2026-01-01T10:00:00Z", 1001)
        ],
        mitre=[technique("T1087", "SM-002")],
    )

    step = reconstruct_attack_sequence(fact_packet).steps[0]

    assert step.detection_reference == "1001"
    assert step.mitre_technique == "T1087"
    assert step.tactic == "Discovery"


def test_behavior_to_mitre_sequence():
    fact_packet = packet(
        behaviors=[
            behavior("script_execution", "2026-01-01T10:00:00Z", "TEL-1")
        ],
        behavior_detections=[
            behavior_detection("BT-001", "2026-01-01T10:01:00Z", "BT-001-TEL-1", "TEL-1")
        ],
        mitre=[technique("T1059", "BT-001-TEL-1")],
    )

    result = reconstruct_attack_sequence(fact_packet)

    assert result.steps[0].behavior_reference == "TEL-1"
    assert result.steps[1].mitre_technique == "T1059"


def test_correlation_ordering_is_preserved_by_timestamps():
    fact_packet = packet(
        detections=[
            detection("SM-002", "2026-01-01T10:00:00Z", 1001),
            detection("SM-003", "2026-01-01T10:01:00Z", 1002),
        ]
    )

    result = reconstruct_attack_sequence(fact_packet)

    assert [step.source_reference for step in result.steps] == [
        "1001",
        "1002",
    ]


def test_graph_backed_sequence_reuses_graph_nodes():
    fact_packet = packet(
        detections=[
            detection("SM-002", "2026-01-01T10:00:00Z", 1001),
            detection("SM-003", "2026-01-01T10:01:00Z", 1002),
        ]
    )
    graph = build_incident_graph(fact_packet)

    result = reconstruct_attack_sequence(fact_packet, graph=graph)

    assert result.status == "complete_sequence"
    assert result.steps[0].step_id == "detection:SM-002"
    assert result.steps[1].step_id == "detection:SM-003"


def test_partial_sequence_is_explicit():
    fact_packet = packet(
        detections=[
            detection("SM-002", "2026-01-01T10:00:00Z", 1001),
            detection("SM-003", None, 1002),
        ]
    )

    result = reconstruct_attack_sequence(fact_packet)

    assert result.status == "partial_sequence"
    assert result.limitations


def test_no_meaningful_sequence_is_explicit():
    fact_packet = packet(
        detections=[detection("SM-002", None, 1001)]
    )

    result = reconstruct_attack_sequence(fact_packet)

    assert result.status == "no_meaningful_sequence"
    assert result.steps[0].timestamp is None


def test_insufficient_evidence_is_explicit():
    result = reconstruct_attack_sequence(packet())

    assert result.status == "insufficient_evidence"
    assert result.insufficient_evidence is True
    assert not result.steps


def test_synthetic_telemetry_warning():
    fact_packet = packet(
        behaviors=[
            behavior(
                "browser_data_access",
                "2026-01-01T10:00:00Z",
                "TEL-SYNTH",
                synthetic=True,
            )
        ]
    )

    result = reconstruct_attack_sequence(fact_packet)

    assert any("Synthetic behavior telemetry" in item for item in result.limitations)
    assert result.steps[0].synthetic is True


def test_attribution_warning_is_preserved():
    fact_packet = packet(
        detections=[
            detection("SM-002", "2026-01-01T10:00:00Z", 1001)
        ],
        mitre=[technique("T1087", "SM-002")],
    )

    result = reconstruct_attack_sequence(fact_packet)

    assert any("do not prove malware attribution" in item for item in result.limitations)


def test_evidence_references_are_preserved():
    fact_packet = packet(
        detections=[
            {
                **detection("SM-002", "2026-01-01T10:00:00Z", 1001),
                "evidence_id": "EV-1001",
            }
        ]
    )

    step = reconstruct_attack_sequence(fact_packet).steps[0]

    assert "EV-1001" in step.evidence_refs
    assert "1001" in step.evidence_refs


def test_no_invented_steps():
    fact_packet = packet(
        detections=[
            detection("SM-002", "2026-01-01T10:00:00Z", 1001)
        ]
    )

    result = reconstruct_attack_sequence(fact_packet)

    descriptions = [step.description.lower() for step in result.steps]
    assert descriptions == ["sm-002"]
    assert "lateral movement" not in descriptions
    assert "data exfiltration" not in descriptions


def test_reconstruction_failure_is_isolated_from_investigation():
    class BrokenGraph:
        nodes = [object()]

    fact_packet = packet(
        detections=[
            detection("SM-002", "2026-01-01T10:00:00Z", 1001)
        ]
    )

    response = InvestigationAgent().investigate(
        fact_packet,
        include_attack_sequence=True,
        graph=BrokenGraph(),
    )

    assert response.grounded is True
    assert response.observed_facts
    assert response.attack_sequence["status"] == "insufficient_evidence"


def test_investigation_agent_optional_sequence():
    fact_packet = packet(
        detections=[
            detection("SM-002", "2026-01-01T10:00:00Z", 1001),
            detection("SM-003", "2026-01-01T10:01:00Z", 1002),
        ]
    )

    response = InvestigationAgent().investigate(
        fact_packet,
        include_attack_sequence=True,
    )

    assert response.grounded is True
    assert response.attack_sequence["status"] == "complete_sequence"
    assert len(response.attack_sequence["steps"]) == 2


def test_reconstruction_is_repeatable():
    fact_packet = packet(
        detections=[
            detection("SM-002", "2026-01-01T10:00:00Z", 1001),
            detection("SM-003", "2026-01-01T10:01:00Z", 1002),
        ]
    )

    first = reconstruct_attack_sequence(fact_packet).to_dict()
    second = reconstruct_attack_sequence(fact_packet).to_dict()

    assert first == second


def main():
    tests = [
        value
        for name, value in globals().items()
        if name.startswith("test_") and callable(value)
    ]
    for test in tests:
        test()
    print(f"{len(tests)} attack sequence tests passed")


if __name__ == "__main__":
    main()
