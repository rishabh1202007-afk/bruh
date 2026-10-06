from typing import Any, Dict

RISK_EXPLANATION_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "summary",
        "risk_interpretation",
        "key_factors",
        "evidence_summary",
        "limitations",
        "attribution_statement",
        "recommended_next_steps",
        "insufficient_evidence",
        "evidence_refs",
    ],
    "properties": {
        "summary": {"type": "string"},
        "risk_interpretation": {"type": "string"},
        "key_factors": {"type": "array", "items": {"type": "string"}},
        "evidence_summary": {"type": "array", "items": {"type": "string"}},
        "limitations": {"type": "array", "items": {"type": "string"}},
        "attribution_statement": {"type": "string"},
        "recommended_next_steps": {"type": "array", "items": {"type": "string"}},
        "insufficient_evidence": {"type": "boolean"},
        "evidence_refs": {"type": "array", "items": {"type": "string"}},
    },
}

MITRE_INVESTIGATION_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "status",
        "observed_techniques",
        "knowledge_context",
        "evidence_gaps",
        "attribution_status",
        "synthetic_telemetry",
        "warnings",
        "next_investigation_steps"
    ],
    "properties": {
        "status": {"type": "string"},
        "observed_techniques": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["technique_id", "technique_name", "tactics", "explanation"],
                "properties": {
                    "technique_id": {"type": "string"},
                    "technique_name": {"type": "string"},
                    "tactics": {"type": "array", "items": {"type": "string"}},
                    "observed_behavior": {"type": "string"},
                    "explanation": {"type": "string"},
                    "evidence_refs": {"type": "array", "items": {"type": "string"}},
                    "confidence": {"type": "string"},
                    "limitations": {"type": "array", "items": {"type": "string"}},
                }
            }
        },
        "knowledge_context": {"type": "array", "items": {"type": "object"}},
        "evidence_gaps": {"type": "array", "items": {"type": "string"}},
        "attribution_status": {"type": "string"},
        "synthetic_telemetry": {"type": "boolean"},
        "warnings": {"type": "array", "items": {"type": "string"}},
        "next_investigation_steps": {"type": "array", "items": {"type": "string"}}
    }
}

