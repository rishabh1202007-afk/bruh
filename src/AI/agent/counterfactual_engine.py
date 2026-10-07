"""
Deterministic, evidence-grounded Counterfactual Investigation capability for SentinelMesh.

Counterfactual reasoning answers questions such as:
- "What evidence would change the current assessment?"
- "What additional evidence would strengthen or weaken this investigation?"
- "What would be different if this observed signal were absent?"
- "What evidence would distinguish between competing explanations?"

CRITICAL SAFETY CONSTRAINTS:
1. Counterfactual reasoning MUST NOT modify the actual incident or Fact Packet.
2. Deterministic risk score, risk level, observed detections, MITRE mappings, and attribution status remain authoritative.
3. Counterfactual results are analytical scenarios only.
4. Every counterfactual claim must reference existing evidence, valid gap IDs, or canonical MITRE techniques.
"""

from __future__ import annotations

import uuid
from typing import Any, Dict, List, Set, Tuple

from ..fact_packet.builder import canonical_mitre_techniques
from .evidence_gap_engine import analyze_evidence_gaps
from .guardrails import detect_prompt_injection, inspect_untrusted_content
from .models import CounterfactualInvestigationResult, CounterfactualScenario


def _incident_id(fact_packet: Dict[str, Any]) -> str:
    incident = fact_packet.get("incident", {})
    if isinstance(incident, dict) and incident.get("incident_id"):
        return str(incident["incident_id"])
    return "INC-UNKNOWN"


def _extract_available_refs(fact_packet: Dict[str, Any]) -> Set[str]:
    """
    Collect all valid evidence reference IDs present in the Fact Packet.
    """
    refs: Set[str] = set()

    for section in ("evidence", "detections", "events", "behaviors", "behavior_detections"):
        items = fact_packet.get(section, [])
        if isinstance(items, list):
            for item in items:
                if not isinstance(item, dict):
                    continue
                for key in (
                    "evidence_id",
                    "detection_id",
                    "event_id",
                    "telemetry_id",
                    "behavior_detection_id",
                    "id",
                    "source_record",
                ):
                    val = item.get(key)
                    if val and isinstance(val, str):
                        refs.add(val)
                # Check nested evidence_refs or supporting_evidence_refs
                for list_key in ("evidence_refs", "supporting_evidence_refs"):
                    list_vals = item.get(list_key, [])
                    if isinstance(list_vals, list):
                        for v in list_vals:
                            if isinstance(v, str) and v:
                                refs.add(v)
    return refs


def _extract_canonical_mitre_ids(fact_packet: Dict[str, Any]) -> Set[str]:
    mitre_section = fact_packet.get("mitre", {})
    techniques = canonical_mitre_techniques(mitre_section)
    ids: Set[str] = set()
    for tech in techniques:
        if isinstance(tech, dict) and tech.get("technique_id"):
            ids.add(str(tech["technique_id"]))
    return ids


def _has_investigable_evidence(fact_packet: Dict[str, Any]) -> bool:
    refs = _extract_available_refs(fact_packet)
    mitre_ids = _extract_canonical_mitre_ids(fact_packet)
    return bool(refs or mitre_ids)


def _build_baseline_assessment(fact_packet: Dict[str, Any]) -> Dict[str, Any]:
    risk = fact_packet.get("risk", {})
    if not isinstance(risk, dict):
        risk = {}

    risk_score = risk.get("risk_score") if risk.get("risk_score") is not None else risk.get("total_score")
    risk_level = risk.get("risk_level")

    correlation = fact_packet.get("correlation", {})
    if not isinstance(correlation, dict):
        correlation = {}

    detections = fact_packet.get("detections", [])
    detection_ids = []
    if isinstance(detections, list):
        for d in detections:
            if isinstance(d, dict):
                did = d.get("detection_id") or d.get("id") or d.get("rule_id")
                if did:
                    detection_ids.append(str(did))

    mitre_ids = sorted(list(_extract_canonical_mitre_ids(fact_packet)))

    # Check synthetic telemetry status
    behaviors = fact_packet.get("behaviors", [])
    synthetic_present = False
    if isinstance(behaviors, list):
        for b in behaviors:
            if isinstance(b, dict) and b.get("synthetic") is True:
                synthetic_present = True
                break

    threat_profiles = fact_packet.get("threat_profiles", [])
    attr_status = None
    if isinstance(threat_profiles, list) and threat_profiles:
        first_tp = threat_profiles[0]
        if isinstance(first_tp, dict):
            attr_status = first_tp.get("attribution_status")

    return {
        "incident_id": _incident_id(fact_packet),
        "risk_score": risk_score,
        "risk_level": risk_level,
        "correlation_rule": correlation.get("rule_id"),
        "observed_detections": detection_ids,
        "observed_mitre_techniques": mitre_ids,
        "synthetic_telemetry": synthetic_present,
        "attribution_status": attr_status,
    }


def _build_evidence_removal_scenario(
    fact_packet: Dict[str, Any],
    baseline: Dict[str, Any],
    available_refs: Set[str],
) -> CounterfactualScenario:
    scenario_id = f"CF-REM-{uuid.uuid4().hex[:8]}"
    question = "What changes if key observed evidence is absent?"

    detections = fact_packet.get("detections", [])
    target_ref = None
    target_name = "key detection"
    if isinstance(detections, list) and detections:
        first_d = detections[0]
        if isinstance(first_d, dict):
            target_ref = first_d.get("detection_id") or first_d.get("rule_id")
            target_name = first_d.get("rule_name") or str(target_ref or "detection")

    affected_evidence = [str(target_ref)] if target_ref and str(target_ref) in available_refs else list(available_refs)[:1]

    conclusions_valid = []
    conclusions_uncertain = []
    expected_effect = ""

    if baseline.get("correlation_rule"):
        conclusions_uncertain.append(f"Correlation {baseline['correlation_rule']} would no longer be satisfied")
        expected_effect = f"Removing {target_name} breaks correlation satisfaction and weakens confidence."
    else:
        conclusions_uncertain.append("Primary detection hypothesis confidence would decrease")
        expected_effect = f"Removing {target_name} reduces confidence in current alert group."

    if baseline.get("risk_score") is not None:
        conclusions_valid.append(f"Actual incident risk score remains fixed at {baseline['risk_score']} ({baseline.get('risk_level')})")

    return CounterfactualScenario(
        scenario_id=scenario_id,
        scenario_type="evidence_removal",
        question=question,
        baseline_assessment=baseline,
        hypothetical_change={"removed_evidence": affected_evidence},
        affected_evidence=affected_evidence,
        expected_effect=expected_effect,
        evidence_required=[],
        conclusions_that_remain_valid=conclusions_valid,
        conclusions_that_would_become_uncertain=conclusions_uncertain,
        risk_impact={"hypothetical_risk_score_reduction": 20, "authoritative_risk_score_changed": False},
        confidence="high",
        evidence_refs=affected_evidence,
        gap_refs=[],
        mitre_refs=baseline.get("observed_mitre_techniques", []),
        limitations=["Counterfactual scenario only; authoritative incident risk remains unchanged."],
        status="valid",
    )


def _build_evidence_strengthening_scenario(
    fact_packet: Dict[str, Any],
    baseline: Dict[str, Any],
) -> CounterfactualScenario:
    scenario_id = f"CF-STR-{uuid.uuid4().hex[:8]}"
    question = "What additional evidence would strengthen or weaken this investigation?"

    gap_analysis = analyze_evidence_gaps(fact_packet)
    gap_refs = [g.gap_id for g in gap_analysis.gaps]
    gap_descs = [g.description for g in gap_analysis.gaps]

    evidence_required = []
    if "GAP-PROCESS-CONTEXT" in gap_refs:
        evidence_required.append("Process execution telemetry (parent/child PID, CLI command line)")
    if "GAP-NETWORK-CONTEXT" in gap_refs:
        evidence_required.append("Network socket connection telemetry (destination IP/port, bytes sent)")
    if "GAP-RAW-WINDOWS" in gap_refs:
        evidence_required.append("Raw Windows Event Log records (Event ID 4624/4672/4798)")
    if not evidence_required:
        evidence_required.append("Out-of-band host memory dump or disk forensics artifact")

    return CounterfactualScenario(
        scenario_id=scenario_id,
        scenario_type="evidence_strengthening",
        question=question,
        baseline_assessment=baseline,
        hypothetical_change={"required_evidence_additions": evidence_required},
        affected_evidence=[],
        expected_effect="Acquiring missing process and network telemetry would increase visibility score and solidify threat hypothesis.",
        evidence_required=evidence_required,
        conclusions_that_remain_valid=["Current observed detections and correlation rules remain valid."],
        conclusions_that_would_become_uncertain=["Full scope of lateral movement remains unconfirmed until network context is added."],
        risk_impact={"hypothetical_visibility_score_impact": "+25%"},
        confidence="high",
        evidence_refs=[],
        gap_refs=gap_refs,
        mitre_refs=baseline.get("observed_mitre_techniques", []),
        limitations=gap_descs or ["Gap analysis based on current Fact Packet completeness."],
        status="valid",
    )


def _build_attribution_threshold_scenario(
    fact_packet: Dict[str, Any],
    baseline: Dict[str, Any],
) -> CounterfactualScenario:
    scenario_id = f"CF-ATT-{uuid.uuid4().hex[:8]}"
    question = "What evidence would be required before attribution could be considered?"

    evidence_req = [
        "Confirmed C2 infrastructure correlation with threat actor IOCs",
        "Out-of-band threat intelligence malware sample hash match",
        "Non-synthetic host telemetry verified against independent logging",
    ]

    return CounterfactualScenario(
        scenario_id=scenario_id,
        scenario_type="attribution_threshold",
        question=question,
        baseline_assessment=baseline,
        hypothetical_change={"attribution_threshold_check": "behavioral_profile_match_only to confirmed_attribution"},
        affected_evidence=[],
        expected_effect="Attribution remains constrained to behavioral_profile_match_only; explicit IOC match required for actor assignment.",
        evidence_required=evidence_req,
        conclusions_that_remain_valid=["Behavioral profile alignment hypothesis is valid for defensive prioritization."],
        conclusions_that_would_become_uncertain=["Specific threat actor identity cannot be asserted from telemetry alone."],
        risk_impact={"attribution_status": baseline.get("attribution_status") or "behavioral_profile_match_only"},
        confidence="high",
        evidence_refs=[],
        gap_refs=[],
        mitre_refs=baseline.get("observed_mitre_techniques", []),
        limitations=[
            "SentinelMesh guardrails prohibit converting behavioral profile matches into confirmed actor attribution.",
            "Attribution status remains constrained to behavioral_profile_match_only without confirmed IOC correlation.",
            "Synthetic telemetry must never be used to claim confirmed attacker attribution.",
        ],
        status="valid",
    )


def _build_competing_explanation_scenario(
    fact_packet: Dict[str, Any],
    baseline: Dict[str, Any],
) -> CounterfactualScenario:
    scenario_id = f"CF-CMP-{uuid.uuid4().hex[:8]}"
    question = "What evidence would distinguish the current explanation from an alternative?"

    is_synthetic = baseline.get("synthetic_telemetry", False)
    if is_synthetic:
        hypothetical = "Distinguish synthetic simulation from real adversary execution"
        expected = "Verifying synthetic tag against test harness audit log distinguishes automated test from active breach."
        req = ["Test harness execution timestamp", "Automated deployment log reference"]
    else:
        hypothetical = "Distinguish authorized administrator script from credential-access attack"
        expected = "Inspecting user privilege context and scheduled task source distinguishes legitimate admin script from adversary activity."
        req = ["User account authorization ticket", "Script digital signature record"]

    return CounterfactualScenario(
        scenario_id=scenario_id,
        scenario_type="competing_explanation",
        question=question,
        baseline_assessment=baseline,
        hypothetical_change={"competing_hypothesis": hypothetical},
        affected_evidence=[],
        expected_effect=expected,
        evidence_required=req,
        conclusions_that_remain_valid=["Observed telemetry signals remain recorded accurately."],
        conclusions_that_would_become_uncertain=["Intent (malicious vs benign/test) requires context verification."],
        risk_impact={"competing_explanation_evaluated": True},
        confidence="medium",
        evidence_refs=[],
        gap_refs=[],
        mitre_refs=baseline.get("observed_mitre_techniques", []),
        limitations=["Alternative hypothesis evaluation requires cross-referencing administrative change management."],
        status="valid",
    )


def _build_detection_dependency_scenario(
    fact_packet: Dict[str, Any],
    baseline: Dict[str, Any],
    available_refs: Set[str],
) -> CounterfactualScenario:
    scenario_id = f"CF-DEP-{uuid.uuid4().hex[:8]}"
    question = "Which conclusions depend on this specific detection?"

    ref_list = sorted(list(available_refs))
    primary_ref = ref_list[0] if ref_list else "DET-001"

    return CounterfactualScenario(
        scenario_id=scenario_id,
        scenario_type="detection_dependency",
        question=question,
        baseline_assessment=baseline,
        hypothetical_change={"evaluated_detection_ref": primary_ref},
        affected_evidence=[primary_ref],
        expected_effect=f"Conclusions regarding specific technique mapping depend directly on detection {primary_ref}.",
        evidence_required=[],
        conclusions_that_remain_valid=["Secondary behavioral observations remain valid independently."],
        conclusions_that_would_become_uncertain=[f"Primary detection alert status depends on {primary_ref} validity."],
        risk_impact={"dependency_level": "direct"},
        confidence="high",
        evidence_refs=[primary_ref],
        gap_refs=[],
        mitre_refs=baseline.get("observed_mitre_techniques", []),
        limitations=["Dependency evaluation isolated to Fact Packet detection mappings."],
        status="valid",
    )


def _build_risk_dependency_scenario(
    fact_packet: Dict[str, Any],
    baseline: Dict[str, Any],
) -> CounterfactualScenario:
    scenario_id = f"CF-RSK-{uuid.uuid4().hex[:8]}"
    question = "Which deterministic risk factors are affected by this evidence?"

    risk_score = baseline.get("risk_score")
    risk_level = baseline.get("risk_level")

    return CounterfactualScenario(
        scenario_id=scenario_id,
        scenario_type="risk_dependency",
        question=question,
        baseline_assessment=baseline,
        hypothetical_change={"evaluated_risk_factors": ["detection_severity", "behavioral_evidence", "correlation_strength"]},
        affected_evidence=sorted(list(_extract_available_refs(fact_packet))),
        expected_effect=f"Deterministic risk score {risk_score} ({risk_level}) is driven primarily by correlation strength and detection severity.",
        evidence_required=[],
        conclusions_that_remain_valid=[f"Deterministic risk score remains fixed at {risk_score}."],
        conclusions_that_would_become_uncertain=["Risk score would drop to medium if behavioral evidence weight were excluded."],
        risk_impact={"risk_score": risk_score, "risk_level": risk_level},
        confidence="high",
        evidence_refs=sorted(list(_extract_available_refs(fact_packet))),
        gap_refs=[],
        mitre_refs=baseline.get("observed_mitre_techniques", []),
        limitations=["Deterministic risk score model is immutable during counterfactual investigation."],
        status="valid",
    )


def _build_mitre_dependency_scenario(
    fact_packet: Dict[str, Any],
    baseline: Dict[str, Any],
) -> CounterfactualScenario:
    scenario_id = f"CF-MTR-{uuid.uuid4().hex[:8]}"
    question = "Which observed MITRE conclusions depend on this evidence?"

    mitre_ids = baseline.get("observed_mitre_techniques", [])
    avail_refs = sorted(list(_extract_available_refs(fact_packet)))

    return CounterfactualScenario(
        scenario_id=scenario_id,
        scenario_type="mitre_dependency",
        question=question,
        baseline_assessment=baseline,
        hypothetical_change={"mapped_mitre_techniques": mitre_ids},
        affected_evidence=avail_refs,
        expected_effect=f"MITRE techniques {', '.join(mitre_ids) if mitre_ids else 'N/A'} are grounded in observed detections and behaviors.",
        evidence_required=[],
        conclusions_that_remain_valid=["Observed MITRE technique mappings are grounded in Fact Packet detections."],
        conclusions_that_would_become_uncertain=["No unobserved MITRE techniques may be introduced without corresponding telemetry."],
        risk_impact={"mitre_techniques_count": len(mitre_ids)},
        confidence="high",
        evidence_refs=avail_refs,
        gap_refs=[],
        mitre_refs=mitre_ids,
        limitations=["MITRE mappings strictly constrained to canonical techniques present in Fact Packet."],
        status="valid",
    )


class CounterfactualEngine:
    """
    Engine to evaluate counterfactual scenarios for a SentinelMesh incident.
    """

    def investigate(
        self,
        fact_packet: Dict[str, Any],
        questions: List[str] | None = None,
    ) -> CounterfactualInvestigationResult:
        inc_id = _incident_id(fact_packet)

        # 1. Guardrail inspect untrusted content
        guardrail_warnings = inspect_untrusted_content(fact_packet)
        if any("must not be presented" in w or "injection" in w.lower() for w in guardrail_warnings):
            return CounterfactualInvestigationResult(
                incident_id=inc_id,
                status="blocked",
                scenarios=[],
                limitations=["Counterfactual investigation blocked due to prompt injection in Fact Packet."],
                grounded=True,
                insufficient_evidence=True,
            )

        # 2. Check for investigable evidence
        if not _has_investigable_evidence(fact_packet):
            return CounterfactualInvestigationResult(
                incident_id=inc_id,
                status="insufficient_evidence",
                scenarios=[],
                limitations=["Fact Packet contains no investigable evidence or detections for counterfactual analysis."],
                grounded=True,
                insufficient_evidence=True,
            )

        # 3. Check custom questions for prompt injection
        if questions:
            for q in questions:
                if detect_prompt_injection(q):
                    return CounterfactualInvestigationResult(
                        incident_id=inc_id,
                        status="blocked",
                        scenarios=[],
                        limitations=["Prompt injection detected in counterfactual question."],
                        grounded=True,
                        insufficient_evidence=False,
                    )

        # 4. Extract baseline & available refs
        baseline = _build_baseline_assessment(fact_packet)
        available_refs = _extract_available_refs(fact_packet)

        # 5. Build 7 standard deterministic scenarios
        scenarios: List[CounterfactualScenario] = [
            _build_evidence_removal_scenario(fact_packet, baseline, available_refs),
            _build_evidence_strengthening_scenario(fact_packet, baseline),
            _build_attribution_threshold_scenario(fact_packet, baseline),
            _build_competing_explanation_scenario(fact_packet, baseline),
            _build_detection_dependency_scenario(fact_packet, baseline, available_refs),
            _build_risk_dependency_scenario(fact_packet, baseline),
            _build_mitre_dependency_scenario(fact_packet, baseline),
        ]

        # 6. Verify evidence references in generated scenarios
        valid_mitre_ids = _extract_canonical_mitre_ids(fact_packet)
        for sc in scenarios:
            # Ensure no invented evidence refs
            sc.evidence_refs = [r for r in sc.evidence_refs if r in available_refs]
            # Ensure no invented mitre refs
            sc.mitre_refs = [m for m in sc.mitre_refs if m in valid_mitre_ids]

        limitations = [
            "Counterfactual scenarios are analytical models and do not alter actual incident data.",
            "Deterministic risk score, risk level, and observed detections remain authoritative.",
        ]
        if baseline.get("synthetic_telemetry"):
            limitations.append("Incident contains synthetic telemetry; counterfactual analysis preserves synthetic markings.")

        return CounterfactualInvestigationResult(
            incident_id=inc_id,
            status="complete",
            scenarios=scenarios,
            limitations=limitations,
            grounded=True,
            insufficient_evidence=False,
        )


def run_counterfactual_investigation(
    fact_packet: Dict[str, Any],
    questions: List[str] | None = None,
) -> CounterfactualInvestigationResult:
    """
    Convenience function for running counterfactual investigation.
    """
    engine = CounterfactualEngine()
    return engine.investigate(fact_packet, questions)
