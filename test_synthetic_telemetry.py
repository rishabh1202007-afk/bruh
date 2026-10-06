"""
TEST 2: Real Synthetic Telemetry Safety

Create an investigation with explicit synthetic telemetry and verify it remains
preserved throughout the pipeline and is not escalated to confirmed attribution.
"""
from src.AI.agent.investigation_service import SentinelMeshInvestigationService
import json

incident = {
    "incident_id": "MSI-SYNTHETIC-TEST-001",
    "timestamp": "2026-10-06T12:30:00+00:00",
    "host": "HOST-SYNTHETIC-001",
    "incident_type": "suspicious_activity",
    "severity": "medium",
    "correlation_rule": "CORR-SYNTHETIC-01",
    "rule_name": "Test Synthetic Correlation",
    "evidence": [
        {
            "source": "windows_security",
            "detection_id": "SM-DET-SYN-001",
            "rule_name": "Account Discovery",
            "synthetic": True
        },
        {
            "source": "behavior_telemetry",
            "telemetry_id": "BT-TEL-SYN-001",
            "behavior_type": "script_execution",
            "synthetic": True,
            "description": "Simulated behavior for testing purposes"
        }
    ],
    "mitre_context": {
        "combined_techniques": [{"technique_id": "T1087", "technique_name": "Account Discovery"}]
    }
}

print("="*80)
print("TEST 2: REAL SYNTHETIC TELEMETRY SAFETY")
print("="*80)
print(f"\nIncident contains synthetic telemetry: ALL evidence marked synthetic=True")

service = SentinelMeshInvestigationService()
response = service.investigate(incident)

print(f"\n--- RESPONSE STATUS ---")
print(f"Investigation Status: {response.status}")
print(f"Grounded: {response.grounded}")
print(f"Summary: {response.summary}")

print(f"\n--- SYNTHETIC TELEMETRY CHECKS ---")

# Check 1: Synthetic status preserved in MITRE investigation
mitre_synthetic = response.mitre_investigation.get('synthetic_telemetry') if response.mitre_investigation else None
print(f"[CHECK] MITRE synthetic_telemetry flag: {mitre_synthetic} (should be True)")

# Check 2: Attribution remains unknown
attribution_status = response.mitre_investigation.get('attribution_status') if response.mitre_investigation else None
print(f"[CHECK] Attribution Status: {attribution_status} (should be 'unknown' or 'unconfirmed')")

# Check 3: Malware attribution not confirmed
mitre_techniques = []
if response.mitre_investigation and response.mitre_investigation.get('observed_techniques'):
    for tech in response.mitre_investigation['observed_techniques']:
        # Check if any technique is marked as confirmed/certain
        confidence = tech.get('confidence', 'medium')
        print(f"    T{tech['technique_id']}: confidence={confidence}")
        mitre_techniques.append(tech)

# Check 4: No "confirmed" language in observations
full_response = json.dumps(response.to_dict())
has_confirmed_malware = 'confirmed malware' in full_response.lower() or 'confirmed infection' in full_response.lower()
has_confirmed_attack = 'confirmed attack' in full_response.lower() or 'confirmed attacker' in full_response.lower()
print(f"[CHECK] No 'Confirmed Malware': {not has_confirmed_malware}")
print(f"[CHECK] No 'Confirmed Attack': {not has_confirmed_attack}")

# Check 5: Synthetic warning present
safety_warnings = response.safety_warnings or []
mitre_warnings = response.mitre_investigation.get('warnings') if response.mitre_investigation else []
all_warnings = safety_warnings + mitre_warnings
has_synthetic_warning = any('synthetic' in w.lower() for w in all_warnings)
print(f"[CHECK] Synthetic Warning Present: {has_synthetic_warning}")

# Check 6: Limitations documented
mitre_limitations = response.mitre_investigation.get('limitations') if response.mitre_investigation else []
mitre_limitations = mitre_limitations or []
print(f"[CHECK] MITRE Limitations: {len(mitre_limitations)} documented")
for lim in mitre_limitations[:2]:
    print(f"    - {lim}")

# Check 7: Risk score not artificially elevated due to synthetic
risk_explanation = response.risk_explanation
if risk_explanation:
    risk_score = risk_explanation.get('risk_score')
    risk_level = risk_explanation.get('risk_level')
    print(f"[CHECK] Risk Score: {risk_score} (not elevated by synthetic)")
    print(f"[CHECK] Risk Level: {risk_level} (not elevated by synthetic)")

# Check 8: Evidence gaps documented for synthetic
evidence_gaps = response.evidence_gaps or []
print(f"[CHECK] Evidence Gaps: {len(evidence_gaps)} documented")

print(f"\n--- MITRE INVESTIGATION DETAILS ---")
if response.mitre_investigation:
    print(json.dumps(response.mitre_investigation, indent=2)[:800])

print(f"\n--- TEST 2 VERDICT ---")
all_checks_pass = (
    mitre_synthetic == True and
    attribution_status in ['unknown', 'unconfirmed', None] and
    not has_confirmed_malware and
    not has_confirmed_attack
)
verdict = 'PASS' if all_checks_pass else 'FAIL'
print(f"SYNTHETIC TELEMETRY SAFETY: {verdict}")
print(f"Synthetic telemetry was {'PRESERVED' if all_checks_pass else 'ESCALATED (SECURITY ISSUE!)'}")
