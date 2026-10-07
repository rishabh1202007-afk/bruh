================================================================================
AI INTEGRATION ANALYSIS — PHASE 1 INSPECTION COMPLETE
================================================================================

Date: 2026-10-07
Status: INSPECTED

================================================================================
1. DETERMINISTIC INCIDENT PIPELINE FLOW
================================================================================

CURRENT IMPLEMENTATION (Verified):

Windows Event Ingestion
  ↓
Event Classification (event_classifier.py)
  ↓
Event Normalization (event_normalizer.py)
  ↓
Detection Rules (rule_engine.py)
  → Output: detections.jsonl
  
Correlation Engine (correlation_engine.py)
  Input: detections.jsonl
  Rules: SM-002 (Account Discovery) + SM-003 (Credential Manager)
  Window: 300 seconds
  Output: correlated_incidents.jsonl
  
Incident Enrichment (incident_enricher.py)
  Input: correlated_incidents.jsonl
  Output: enriched_incidents.jsonl
  
Behavior Telemetry Generation (behavior_generator.py)
  Input: threat_profiles.json
  Output: behavior_telemetry.jsonl
  Marks synthetic=True

Behavior Detection/MITRE Mapping (behavior_mitre_mapper.py)
  Input: behavior_telemetry.jsonl
  Output: behavior_mitre_mapped.jsonl

Multisource Enrichment (multisource_incident_enricher.py)
  Input: enriched_incidents.jsonl + behavior_mitre_mapped.jsonl
  Output: enriched_multisource_incidents.jsonl

Multisource MITRE Enrichment (multisource_mitre_enricher.py)
  Input: enriched_multisource_incidents.jsonl
  Output: mitre_enriched_multisource_incidents.jsonl

Final Risk Scoring (final_risk_scorer.py)
  Input: mitre_enriched_multisource_incidents.jsonl
  Input: threat_profiles.json
  Output: final_risk_scored_incidents.jsonl
  
================================================================================
2. AI INTEGRATION POINT (CURRENT STATE)
================================================================================

InvestigationService (investigation_service.py):
  
  DEFAULT_INCIDENT_FILE = "data/raw/final_risk_scored_incidents.jsonl"
  
  Expected incident schema from deterministic pipeline:
  {
    "incident_id": str,
    "timestamp": str (ISO 8601),
    "host": str,
    "severity": str (critical|high|medium|low|info),
    "incident_type": str,
    "correlation_rule": str,
    "rule_name": str,
    "events": [
      {"rule_id": str, "rule_name": str, "source_record": str}
    ],
    "time_window_seconds": int,
    "status": str,
    "observed_behaviors": [str],
    "summary": str,
    "analyst_context": {...},
    "recommended_investigation": [str],
    "threat_profile": str,
    "enrichment": {"attribution_status": str},
    "mitre_context": {
      "windows_techniques": [...],
      "behavior_techniques": [...],
      "combined_techniques": [...]
    },
    "risk_scoring": {
      "total_score": int,
      "risk_level": str,
      "model_version": str,
      "factor_details": {...}
    }
  }

================================================================================
3. FACT PACKET BUILDER INTERFACE
================================================================================

Signature: build_fact_packet(
  incident: Dict,
  detections: List | None = None,
  behaviors: List | None = None,
  behavior_detections: List | None = None,
  mitre: List | None = None,
  risk: Dict | None = None,
  evidence: List | None = None
) -> Dict

Expected incident data structure:
  - incident_id
  - timestamp
  - host
  - severity
  - incident_type
  - status
  - correlation_rule
  - rule_name
  - threat_profile (optional)
  - enrichment.attribution_status (optional)
  - mitre_context (optional)
  
Expected detections list items:
  - detection_id
  - rule_id
  - rule_name
  - evidence_id
  - severity
  - host (optional)
  - username/target_username/subject_username (optional)
  - process_name (optional)

Expected behaviors list items:
  - behavior_id
  - synthetic (bool) — MUST be preserved
  - evidence_id
  - description
  - source (optional)
  - host (optional)

Expected risk dict:
  - total_score (int)
  - risk_level (str)
  - model_version (str)
  - factor_details (dict, optional)

================================================================================
4. SCHEMA CONSISTENCY ISSUES IDENTIFIED
================================================================================

SOURCE LABELING INCONSISTENCY:

behavior_generator.py (line 91):
  "source": "endpoint_behavior"
  "synthetic": True

behavior_mitre_mapper.py expects:
  Detection input with detection_id

Final enriched incident may have:
  "observed_behaviors": [str descriptions]
  
ISSUE:
  - Synthetic behavior telemetry is generated as "endpoint_behavior"
  - But it's not being captured in a "behaviors" list for Fact Packet
  - The enriched incident has "observed_behaviors" as descriptions only
  - Need to trace whether synthetic behaviors are being passed to final incident

EVIDENCE SOURCE TRACKING:

Current evidence sources in deterministic pipeline:
  - "windows_detection" (from Windows Security logs)
  - "behavior_detection" (from behavior_generator)

Expected by Fact Packet:
  - behaviors[] with synthetic flag
  - detections[] with detection_id

ACTION REQUIRED:
  - Verify that synthetic telemetry reaches final_risk_scored_incidents
  - Confirm schema for behaviors in final incident
  - Ensure synthetic flag is preserved through entire pipeline

================================================================================
5. CURRENT TEST COVERAGE
================================================================================

Existing AI Tests: 75/75 passing
  - 67 regression tests (various AI components)
  - 8 benchmark scenarios (comprehensive security properties)

Tests use mock incidents (not real pipeline outputs yet).

MISSING:
  - End-to-end test from real SentinelMesh pipeline → AI investigation
  - Integration test using actual final_risk_scored_incidents.jsonl output

================================================================================
6. INTEGRATION BOUNDARY DEFINITION
================================================================================

DETERMINISTIC SENTINEL MESH OWNS:
  ✓ Detection logic
  ✓ Correlation rules
  ✓ MITRE mapping (deterministic)
  ✓ Risk scoring (deterministic, authoritative)
  ✓ Incident enrichment
  ✓ Threat profile matching

AI OWNS:
  ✓ Investigation assistant
  ✓ Evidence explanation
  ✓ Counterfactual reasoning (explicitly hypothetical)
  ✓ Attack sequence reconstruction (from evidence)
  ✓ Risk score explanation (does not modify)
  ✓ Evidence gap identification
  ✓ Historical comparison
  ✓ Next investigation recommendations

NEITHER SHOULD DO:
  ✗ Invent evidence
  ✗ Invent MITRE techniques
  ✗ Override deterministic risk
  ✗ Upgrade synthetic to real
  ✗ Treat behavioral profile match as confirmed attribution

================================================================================
7. INTEGRATION IMPLEMENTATION PLAN
================================================================================

PHASE A: VERIFY PIPELINE OUTPUT SCHEMA
  1. Run the deterministic pipeline end-to-end
  2. Inspect actual final_risk_scored_incidents.jsonl structure
  3. Verify synthetic telemetry is included
  4. Identify any schema gaps vs. Fact Packet builder expectations

PHASE B: CREATE PIPELINE-TO-AI ADAPTER
  1. Create integration test that:
     - Loads incident from final_risk_scored_incidents.jsonl
     - Extracts detections, behaviors, MITRE, risk
     - Calls build_fact_packet with correct parameters
     - Verifies Fact Packet structure
  2. Handle schema mismatches if found

PHASE C: END-TO-END INTEGRATION TEST
  1. Create test that runs:
     deterministic_incident
     → fact_packet
     → investigation_service.investigate()
     → structured_ai_response
  2. Verify evidence grounding
  3. Verify synthetic telemetry preservation
  4. Verify deterministic risk immutability
  5. Verify LLM failure isolation

PHASE D: EVIDENCE GROUNDING VERIFICATION
  1. Test valid evidence reference → accepted
  2. Test invented evidence → rejected
  3. Test unsupported MITRE → rejected
  4. Test insufficient evidence → explicit status

PHASE E: SECURITY PROPERTIES
  1. Synthetic telemetry remains synthetic
  2. Attribution remains conservative
  3. Prompt injection blocked
  4. LLM failure doesn't break detection

PHASE F: REGRESSION & QUALITY
  1. Existing AI tests still pass
  2. Existing benchmarks still pass
  3. Compilation passes
  4. No circular imports
  5. No dead code

================================================================================
8. FILES TO INSPECT NEXT
================================================================================

To understand actual output schema:

1. src/detection/multisource_mitre_enricher.py
   - What does it output?
   
2. src/detection/final_risk_scorer.py (complete file)
   - Final incident schema
   
3. Run pipeline end-to-end:
   - python3 src/ingestion/windows_event_ingestor.py
   - python3 src/detection/rule_engine.py
   - python3 src/detection/correlation_engine.py
   - python3 src/detection/incident_enricher.py
   - python3 src/telemetry/behavior_generator.py
   - python3 src/detection/behavior_mitre_mapper.py
   - python3 src/detection/multisource_correlation.py
   - python3 src/detection/multisource_incident_enricher.py
   - python3 src/detection/multisource_mitre_enricher.py
   - python3 src/detection/final_risk_scorer.py
   
4. Inspect data/raw/final_risk_scored_incidents.jsonl output

================================================================================
9. CURRENT STATE SUMMARY
================================================================================

READY:
  ✓ AI component is well-designed and tested
  ✓ Fact Packet builder exists and is flexible
  ✓ Investigation service exists and handles LLM failure
  ✓ Evidence validator exists
  ✓ Security guardrails in place
  ✓ 75/75 tests passing
  ✓ Live Qwen3:8b verified

NEEDED:
  - End-to-end integration with real pipeline
  - Verification that synthetic telemetry flows through entire pipeline
  - Integration test proving Fact Packet correctly receives incident evidence
  - Evidence grounding test using real pipeline output

================================================================================
NEXT: Run deterministic pipeline to inspect final incident schema
================================================================================
