from .historical_comparison import (
    compare_historical_incidents,
)
from .investigation_agent import InvestigationAgent


def packet(
    incident_id="INC-CURRENT",
    detections=None,
    behaviors=None,
    mitre=None,
    profile=None,
    evidence_sources=None,
    synthetic=False,
):
    detections = detections or []
    behaviors = behaviors or []
    mitre = mitre or []
    evidence_sources = evidence_sources or []

    evidence = []
    for index, source in enumerate(evidence_sources):
        evidence.append(
            {
                "evidence_id": f"EV-{incident_id}-{index}",
                "source": source,
                "rule_id": (
                    detections[index].get("rule_id")
                    if index < len(detections)
                    else None
                ),
                "synthetic": synthetic,
            }
        )

    profiles = []
    if profile:
        profiles.append(
            {
                "profile_name": profile,
                "attribution_status": (
                    "behavioral_profile_match_only"
                ),
            }
        )

    return {
        "incident": {
            "incident_id": incident_id,
        },
        "detections": detections,
        "behaviors": behaviors,
        "behavior_detections": [],
        "mitre": {
            "combined_techniques": mitre,
        },
        "threat_profiles": profiles,
        "evidence": evidence,
    }


def detection(rule_id):
    return {
        "detection_id": rule_id,
        "rule_id": rule_id,
        "rule_name": rule_id,
        "source_record": f"record-{rule_id}",
    }


def behavior(behavior_type, synthetic=False):
    return {
        "telemetry_id": f"TEL-{behavior_type}",
        "behavior_type": behavior_type,
        "synthetic": synthetic,
        "source": "endpoint_behavior",
    }


def technique(technique_id):
    return {
        "technique_id": technique_id,
        "technique_name": technique_id,
        "tactic": "Test",
        "source_detection": "SM-001",
    }


def test_identical_detection_patterns():
    current = packet(detections=[detection("SM-001")])
    historical = packet("INC-HIST-1", detections=[detection("SM-001")])

    result = compare_historical_incidents(current, [historical])

    assert result.status == "match_found"
    assert result.comparisons[0].shared_detections == ["SM-001"]
    assert result.comparisons[0].similarity_score == 35.0


def test_partial_detection_overlap():
    current = packet(
        detections=[detection("SM-001"), detection("SM-002")]
    )
    historical = packet(
        "INC-HIST-2",
        detections=[detection("SM-002"), detection("SM-003")],
    )

    comparison = compare_historical_incidents(
        current,
        [historical],
    ).comparisons[0]

    assert comparison.shared_detections == ["SM-002"]
    assert comparison.similarity_factors[0]["overlap"] == 0.3333


def test_identical_mitre_techniques():
    current = packet(mitre=[technique("T1087")])
    historical = packet("INC-HIST-3", mitre=[technique("T1087")])

    comparison = compare_historical_incidents(
        current,
        [historical],
    ).comparisons[0]

    assert comparison.shared_mitre_techniques == ["T1087"]
    assert comparison.similarity_factors[2]["score"] == 20.0


def test_partial_mitre_overlap():
    current = packet(
        mitre=[technique("T1087"), technique("T1059")]
    )
    historical = packet(
        "INC-HIST-4",
        mitre=[technique("T1087"), technique("T1547")],
    )

    comparison = compare_historical_incidents(
        current,
        [historical],
    ).comparisons[0]

    assert comparison.shared_mitre_techniques == ["T1087"]
    assert comparison.similarity_factors[2]["overlap"] == 0.3333


def test_behavior_similarity():
    current = packet(
        behaviors=[behavior("script_execution")]
    )
    historical = packet(
        "INC-HIST-5",
        behaviors=[behavior("script_execution")],
    )

    comparison = compare_historical_incidents(
        current,
        [historical],
    ).comparisons[0]

    assert comparison.shared_behaviors == ["script_execution"]
    assert comparison.similarity_factors[1]["score"] == 20.0


def test_threat_profile_similarity():
    current = packet(profile="GlassWorm")
    historical = packet("INC-HIST-6", profile="GlassWorm")

    comparison = compare_historical_incidents(
        current,
        [historical],
    ).comparisons[0]

    assert comparison.shared_threat_profiles == ["GlassWorm"]
    assert comparison.similarity_factors[3]["score"] == 15.0


def test_different_incidents_have_no_meaningful_overlap():
    current = packet(detections=[detection("SM-001")])
    historical = packet(
        "INC-HIST-7",
        detections=[detection("SM-999")],
    )

    result = compare_historical_incidents(current, [historical])

    assert result.status == "no_meaningful_match"
    assert result.comparisons[0].similarity_score == 0.0
    assert result.comparisons[0].similarity_level == "none"


def test_insufficient_current_evidence():
    result = compare_historical_incidents(
        packet(detections=[]),
        [packet("INC-HIST-8", detections=[detection("SM-001")])],
    )

    assert result.status == "insufficient_evidence"
    assert result.insufficient_evidence is True


def test_synthetic_telemetry_limitation_is_preserved():
    current = packet(
        behaviors=[behavior("browser_data_access", synthetic=True)],
        synthetic=True,
    )
    historical = packet(
        "INC-HIST-9",
        behaviors=[behavior("browser_data_access", synthetic=True)],
        synthetic=True,
    )

    comparison = compare_historical_incidents(
        current,
        [historical],
    ).comparisons[0]

    assert "synthetic" in comparison.shared_evidence_characteristics
    assert any(
        "Synthetic telemetry" in limitation
        for limitation in comparison.limitations
    )


def test_attribution_warning_is_preserved():
    current = packet(profile="GlassWorm")
    historical = packet("INC-HIST-10", profile="GlassWorm")

    comparison = compare_historical_incidents(
        current,
        [historical],
    ).comparisons[0]

    assert any(
        "does not establish malware attribution" in limitation
        for limitation in comparison.limitations
    )


def test_evidence_references_are_preserved():
    current = packet(
        detections=[detection("SM-001")],
        evidence_sources=["windows_security"],
    )
    historical = packet(
        "INC-HIST-11",
        detections=[detection("SM-001")],
        evidence_sources=["windows_security"],
    )

    comparison = compare_historical_incidents(
        current,
        [historical],
    ).comparisons[0]

    assert "EV-INC-CURRENT-0" in comparison.evidence_refs["current"]
    assert "EV-INC-HIST-11-0" in comparison.evidence_refs["historical"]
    assert comparison.similarity_factors[0][
        "current_evidence_refs"
    ]


def test_similarity_score_is_deterministic():
    current = packet(
        detections=[detection("SM-001")],
        behaviors=[behavior("script_execution")],
        mitre=[technique("T1059")],
        profile="SocGholish",
        evidence_sources=["windows_security"],
    )
    historical = packet(
        "INC-HIST-12",
        detections=[detection("SM-001")],
        behaviors=[behavior("script_execution")],
        mitre=[technique("T1059")],
        profile="SocGholish",
        evidence_sources=["windows_security"],
    )

    first = compare_historical_incidents(current, [historical]).to_dict()
    second = compare_historical_incidents(current, [historical]).to_dict()

    assert first == second


def test_investigation_survives_comparison_failure():
    current = packet(detections=[detection("SM-001")])
    response = InvestigationAgent().investigate(
        current,
        historical_fact_packets=[None],
    )

    assert response.grounded is True
    assert response.observed_facts
    assert response.historical_comparison["status"] == (
        "insufficient_evidence"
    )


def test_no_historical_incidents_available():
    current = packet(detections=[detection("SM-001")])

    result = compare_historical_incidents(current, [])

    assert result.status == "no_meaningful_match"
    assert not result.comparisons
    assert any(
        "historical incident" in limitation.lower()
        for limitation in result.limitations
    )


def test_similarity_levels_are_explicit():
    weak = compare_historical_incidents(
        packet(detections=[detection("SM-001")]),
        [packet("INC-WEAK", detections=[detection("SM-001")])],
    ).comparisons[0]

    moderate = compare_historical_incidents(
        packet(
            detections=[detection("SM-001")],
            mitre=[technique("T1087")],
        ),
        [
            packet(
                "INC-MODERATE",
                detections=[detection("SM-001")],
                mitre=[technique("T1087")],
            )
        ],
    ).comparisons[0]

    strong = compare_historical_incidents(
        packet(
            detections=[detection("SM-001")],
            behaviors=[behavior("script_execution")],
            mitre=[technique("T1059")],
            profile="SocGholish",
            evidence_sources=["windows_security"],
        ),
        [
            packet(
                "INC-STRONG",
                detections=[detection("SM-001")],
                behaviors=[behavior("script_execution")],
                mitre=[technique("T1059")],
                profile="SocGholish",
                evidence_sources=["windows_security"],
            )
        ],
    ).comparisons[0]

    assert weak.similarity_level == "weak"
    assert moderate.similarity_level == "moderate"
    assert strong.similarity_level == "strong"


def main():
    tests = [
        value
        for name, value in globals().items()
        if name.startswith("test_") and callable(value)
    ]
    for test in tests:
        test()
    print(f"{len(tests)} historical comparison tests passed")


if __name__ == "__main__":
    main()
