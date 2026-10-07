#!/usr/bin/env python3
"""
Map the actual SentinelMesh AI pipeline end-to-end.

This documents what exists NOW, not what should exist.
"""

import sys
sys.path.insert(0, '.')
sys.path.insert(0, './src')

# Core pipeline components
from src.AI.fact_packet.builder import build_fact_packet
from src.AI.rag.fact_packet_context import build_rag_context
from src.AI.agent.guardrails import run_guardrails
from src.AI.agent.investigation_agent import InvestigationAgent
from src.AI.agent.investigation_service import SentinelMeshInvestigationService
from src.AI.agent.evidence_validator import validate_investigation_response

# Optional capabilities
from src.AI.agent.risk_explanation import explain_risk_score
from src.AI.agent.attack_sequence import reconstruct_attack_sequence
from src.AI.agent.mitre_investigator import investigate_mitre
from src.AI.agent.recommendation_engine import RecommendationEngine
from src.AI.agent.evidence_gap_engine import analyze_evidence_gaps
from src.AI.agent.historical_comparison import compare_historical_incidents
from src.AI.agent.counterfactual_engine import run_counterfactual_investigation
from src.AI.agent.feedback_store import FeedbackStore

# LLM providers
from src.AI.llm.ollama_provider import OllamaProvider

print("="*80)
print("SENTINELMESH AI PIPELINE ARCHITECTURE")
print("="*80)
print()

print("DETERMINISTIC SECURITY PIPELINE (Always runs):")
print("  1. Fact Packet Builder")
print("     └─ Input: SentinelMesh incident + detections + behaviors + MITRE + risk")
print("     └─ Output: Canonical Fact Packet")
print()

print("  2. Fact Packet Validator")
print("     └─ Validates Fact Packet structure")
print()

print("  3. Evidence Graph (optional)")
print("     └─ Can build relationship graph")
print()

print("  4. RAG Context Builder")
print("     └─ Builds investigation queries from Fact Packet")
print("     └─ Retrieves security + SentinelMesh knowledge")
print("     └─ Knowledge is contextual, NOT incident evidence")
print()

print("  5. Guardrails (Safety)")
print("     └─ Detects prompt injection in untrusted fields")
print("     └─ Validates synthetic telemetry marking")
print("     └─ Validates attribution status")
print()

print("AI INVESTIGATION AGENT (Triggered when requested):")
print("  6. Investigation Agent")
print("     └─ Base deterministic facts from Fact Packet")
print("     └─ Knowledge context from RAG")
print("     └─ Evidence gaps from gap engine")
print("     └─ Uncertainties from guardrails")
print()

print("OPTIONAL AI CAPABILITIES (Explicit flags):")
print("  7a. Risk Explanation")
print("      └─ Explains existing deterministic risk score")
print("      └─ Does not modify the score")
print()

print("  7b. Attack Sequence Reconstruction")
print("      └─ Reconstructs timeline from deterministic data")
print()

print("  7c. MITRE Investigation")
print("      └─ Maps techniques from deterministic detections")
print()

print("  7d. Next Investigation Recommendation")
print("      └─ Recommends next steps based on evidence gaps")
print()

print("  7e. Evidence Gap Analysis")
print("      └─ Identifies missing evidence categories")
print()

print("  7f. Historical Comparison")
print("      └─ Compares against supplied historical incidents")
print()

print("  7g. Counterfactual Investigation")
print("      └─ Explores hypothetical scenarios")
print("      └─ Does not modify actual Fact Packet")
print()

print("  7h. Analyst Feedback Loop")
print("      └─ Accepts structured feedback")
print("      └─ Metadata only, does not modify security truth")
print()

print("LLM LAYER (Optional, when capabilities need explanation):")
print("  8. Ollama / Qwen3:8b Provider")
print("     └─ Used for text explanation (Risk, Attack Sequence, etc.)")
print("     └─ Structured output via JSON schema")
print("     └─ Failure isolation: falls back to deterministic result")
print()

print("OUTPUT VALIDATION:")
print("  9. Evidence Validator")
print("     └─ Ensures all claims reference valid evidence")
print("     └─ Separates Fact Packet evidence from RAG knowledge")
print("     └─ Rejects unsupported claims")
print("     └─ Marks response as grounded or insufficient")
print()

print("INVESTIGATION SERVICE (Orchestrator):")
print("  10. SentinelMeshInvestigationService")
print("      └─ Coordinates all components")
print("      └─ Accepts optional capability flags")
print("      └─ Returns unified investigation response")
print()

print("="*80)
print("RESPONSE MODEL")
print("="*80)
print()

print("InvestigationResponse contains:")
print("  - incident_id")
print("  - status (grounded | insufficient_evidence | blocked)")
print("  - summary (deterministic)")
print("  - observed_facts (deterministic + evidence-backed)")
print("  - knowledge_context (RAG retrieval)")
print("  - uncertainties (guardrail warnings)")
print("  - evidence_gaps (gap analysis)")
print("  - next_investigation_steps (recommendations)")
print("  - safety_warnings (guardrails)")
print("  - grounded (boolean: all claims backed by evidence)")
print("  - insufficient_evidence (boolean: not enough data)")
print("  - historical_comparison (optional)")
print("  - attack_sequence (optional)")
print("  - risk_explanation (optional)")
print("  - counterfactual_investigation (optional)")
print("  - feedback_metadata (optional)")
print()

print("="*80)
print("SECURITY INVARIANTS ENFORCED")
print("="*80)
print()

print("✓ Deterministic risk score NEVER modified by AI")
print("✓ Detections NEVER created by AI")
print("✓ MITRE techniques NEVER invented by AI")
print("✓ Synthetic telemetry status NEVER changed")
print("✓ Behavioral attribution NEVER upgraded to confirmed")
print("✓ Prompt injection NEVER executed")
print("✓ Unsupported evidence NEVER accepted")
print("✓ LLM failure NEVER disables deterministic results")
print()

print("="*80)
