"""
Deterministic tests for the SentinelMesh investigation service.

These tests do not call Ollama.

They verify that a real SentinelMesh-style incident is converted
into a safe canonical Fact Packet.
"""

from .investigation_service import (
    SentinelMeshInvestigationService,
)


def build_realistic_incident():
    return {
        "incident_id": (
            "MSI-TEST-BT-001"
        ),
        "timestamp": (
            "2026-09-20T19:07:23+00:00"
        ),
        "host": "LAPTOP-SGNH3KHQ",
        "incident_type": (
            "multi_source_suspicious_activity"
        ),
        "severity": "high",
        "correlation_rule": "MSC-001",
        "rule_name": (
            "Windows Security and Behavior Telemetry "
            "Correlation"
        ),
        "threat_profile": "SocGholish",
        "time_window_seconds": 10,
        "evidence": [
            {
                "source": "windows_security",
                "rule_id": "SM-002",
                "rule_name": (
                    "User Account Enumeration"
                ),
                "severity": "low",
                "source_record": 2780474,
            },
            {
                "source": "behavior_telemetry",
                "rule_id": "BT-001",
                "rule_name": (
                    "Suspicious Script Execution"
                ),
                "severity": "medium",
                "threat_profile": "SocGholish",
                "behavior_type": (
                    "script_execution"
                ),
                "detection_id": (
                    "BT-001-TEST"
                ),
            },
        ],
        "status": "new",
        "enrichment": {
            "synthetic_evidence": True,
            "attribution_status": (
                "behavioral_profile_match_only"
            ),
            "analyst_interpretation": (
                "Windows Security telemetry and "
                "synthetic behavior telemetry were "
                "observed on the same host."
            ),
        },
        "mitre_context": {
            "windows_techniques": [
                {
                    "technique_id": "T1087",
                    "technique_name": (
                        "Account Discovery"
                    ),
                    "tactic": "Discovery",
                }
            ],
            "behavior_techniques": [
                {
                    "technique_id": "T1059",
                    "technique_name": (
                        "Command and Scripting Interpreter"
                    ),
                    "tactic": "Execution",
                }
            ],
            "combined_techniques": [
                {
                    "technique_id": "T1087",
                    "technique_name": (
                        "Account Discovery"
                    ),
                    "tactic": "Discovery",
                },
                {
                    "technique_id": "T1059",
                    "technique_name": (
                        "Command and Scripting Interpreter"
                    ),
                    "tactic": "Execution",
                },
            ],
            "technique_count": 2,
            "tactics_observed": [
                "Discovery",
                "Execution",
            ],
            "mapping_status": (
                "contextual_behavioral_mapping"
            ),
            "attribution_warning": (
                "MITRE technique mapping describes "
                "observed behavior and does not prove "
                "malware attribution."
            ),
        },
        "risk_scoring": {
            "model_version": (
                "SentinelMesh-Risk-v3"
            ),
            "maximum_score": 100,
            "total_score": 56,
            "risk_level": "medium",
            "scores": {
                "detection_severity": 12,
                "behavioral_evidence": 6,
                "correlation_strength": 15,
                "mitre_context": 9,
                "threat_profile_alignment": 10,
                "persistence_privilege": 0,
                "network_activity": 0,
                "repetition": 4,
            },
            "factor_details": {},
        },
    }


def test_fact_packet_construction():
    incident = build_realistic_incident()

    packet = (
        SentinelMeshInvestigationService
        .build_fact_packet(
            incident
        )
    )

    assert (
        packet["incident"]["incident_id"]
        == "MSI-TEST-BT-001"
    )

    assert (
        packet["incident"]["host"]
        == "LAPTOP-SGNH3KHQ"
    )

    assert len(
        packet["evidence"]
    ) == 2

    assert len(
        packet["detections"]
    ) == 1

    assert len(
        packet["behavior_detections"]
    ) == 1

    assert (
        packet["correlation"]["rule_id"]
        == "MSC-001"
    )

    assert (
        packet["risk"]["total_score"]
        == 56
    )

    assert (
        packet["risk"]["risk_level"]
        == "medium"
    )


def test_synthetic_telemetry_is_preserved():
    incident = build_realistic_incident()

    packet = (
        SentinelMeshInvestigationService
        .build_fact_packet(
            incident
        )
    )

    uncertainty_text = "\n".join(
        packet["uncertainties"]
    )

    assert (
        "synthetic"
        in uncertainty_text.lower()
    )


def test_attribution_warning_is_preserved():
    incident = build_realistic_incident()

    packet = (
        SentinelMeshInvestigationService
        .build_fact_packet(
            incident
        )
    )

    uncertainty_text = "\n".join(
        packet["uncertainties"]
    )

    assert (
        "behavioral_profile_match_only"
        in uncertainty_text
    )


def test_missing_raw_behavior_is_an_evidence_gap():
    incident = build_realistic_incident()

    packet = (
        SentinelMeshInvestigationService
        .build_fact_packet(
            incident
        )
    )

    gap_text = "\n".join(
        packet["evidence_gaps"]
    )

    assert (
        "raw behavior telemetry"
        in gap_text.lower()
    )


def test_mitre_context_is_preserved():
    incident = build_realistic_incident()

    packet = (
        SentinelMeshInvestigationService
        .build_fact_packet(
            incident
        )
    )

    techniques = (
        packet["mitre"]
        ["combined_techniques"]
    )

    technique_ids = {
        item["technique_id"]
        for item in techniques
    }

    assert "T1087" in technique_ids
    assert "T1059" in technique_ids


def main():
    print(
        "\n"
        "=================================================="
    )
    print(
        "SENTINELMESH INVESTIGATION SERVICE TEST"
    )
    print(
        "=================================================="
    )

    test_fact_packet_construction()
    print(
        "Fact Packet construction: PASS"
    )

    test_synthetic_telemetry_is_preserved()
    print(
        "Synthetic telemetry preservation: PASS"
    )

    test_attribution_warning_is_preserved()
    print(
        "Attribution preservation: PASS"
    )

    test_missing_raw_behavior_is_an_evidence_gap()
    print(
        "Evidence gap detection: PASS"
    )

    test_mitre_context_is_preserved()
    print(
        "MITRE preservation: PASS"
    )

    print(
        "\nALL INVESTIGATION SERVICE TESTS PASSED"
    )


if __name__ == "__main__":
    main()