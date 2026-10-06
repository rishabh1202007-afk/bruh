from src.AI.agent.investigation_service import SentinelMeshInvestigationService
from src.AI.agent.llm_investigator import LLMInvestigator
from src.AI.fact_packet.builder import build_fact_packet
from src.AI.rag.fact_packet_context import build_rag_context
import json
import sys
sys.path.insert(0, '.')

incident = {
    "incident_id": "MSI-E2E-DEBUG-001",
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

# Debug: Check if LLM investigator can be called directly
print("=== TESTING LLM INVESTIGATOR DIRECTLY ===")

fact_packet = build_fact_packet(incident)
rag_context = build_rag_context(fact_packet, top_k=5)

investigator = LLMInvestigator(model="qwen3:8b", temperature=0.0, max_output_tokens=1200)
llm_response = investigator.investigate(
    fact_packet=fact_packet,
    retrieval_context=rag_context.to_dict(),
    analyst_question="Test question"
)

print(f"LLM Response Status: {llm_response.metadata.get('status')}")
print(f"LLM Called: {llm_response.metadata.get('llm_called')}")
print(f"LLM Response Text (first 500 chars):\n{llm_response.text[:500]}")
print(f"\nFull metadata:\n{json.dumps(llm_response.metadata, indent=2)}")

print("\n=== FULL SERVICE INVESTIGATION ===")
response = service.investigate(incident)
print(json.dumps(response.to_dict(), indent=2))
