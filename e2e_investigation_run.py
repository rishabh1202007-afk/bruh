from src.AI.agent.investigation_service import SentinelMeshInvestigationService
import json

incident = {
    "incident_id": "MSI-E2E-001",
    "timestamp": "2026-10-06T10:00:00+00:00",
    "host": "HOST-01",
    "incident_type": "suspicious_activity",
    "severity": "high",
    "correlation_rule": "CORR-01",
    "rule_name": "Test Correlation Rule",
    "evidence": [
        {"source": "windows_security", "detection_id": "SM-DET-001", "rule_name": "Account Discovery"},
        {"source": "behavior_telemetry", "telemetry_id": "BT-TEL-001", "behavior_type": "script_execution", "synthetic": False}
    ],
    "mitre_context": {
        "combined_techniques": [{"technique_id": "T1087", "technique_name": "Account Discovery"}]
    }
}

service = SentinelMeshInvestigationService()
response = service.investigate(incident)

print("--- ACTUAL INVESTIGATION RESPONSE ---")
print(json.dumps(response.to_dict(), indent=2))
