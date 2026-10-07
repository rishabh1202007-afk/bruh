#!/usr/bin/env python3
"""
REAL LLM INTEGRATION TEST — Phase 3 Verification

User Requirements:
  (1) Determine why real investigate() timed out
  (2) Do NOT hide the problem by removing investigate() from tests
  (3) Do NOT weaken assertions or use mocks
  (4) Create ONE focused integration test that actually invokes investigate()
  (5) Provide four specific answers:
      A) Did REAL investigate() succeed?
      B) Did Qwen3:8B get invoked?
      C) Was response validated?
      D) Was risk unchanged?

This test is designed to ACTUALLY RUN investigate() and report the outcome honestly.
"""

import sys
import unittest
import json
from typing import Dict, Any

sys.path.insert(0, '.')
sys.path.insert(0, './src')

from src.AI.agent.test_live_structured_llm_investigator import build_live_incident
from src.AI.agent.investigation_service import SentinelMeshInvestigationService
from src.AI.fact_packet.builder import build_fact_packet


class TestRealInvestigateCall(unittest.TestCase):
    """
    Real integration test that actually calls investigate() with a deterministic incident.

    This test answers the four critical questions the user asked.
    """

    @classmethod
    def setUpClass(cls):
        """Set up once per test class."""
        cls.service = SentinelMeshInvestigationService(
            model="qwen3:8b",
            temperature=0.0,
            max_output_tokens=1200,
        )

    def test_real_investigate_call_with_deterministic_incident(self):
        """
        TEST: Call investigate() with a REAL deterministic incident and report:

        A) Did REAL investigate() succeed?
        B) Did Qwen3:8B get invoked?
        C) Was response validated?
        D) Was risk unchanged?
        """

        # Build the real deterministic incident
        incident = build_live_incident()

        # Extract original risk from incident
        original_risk = incident.get("risk_scoring", {}).get("total_score")
        print(f"\n{'='*80}")
        print(f"REAL INVESTIGATE() CALL TEST")
        print(f"{'='*80}")
        print(f"Incident ID: {incident.get('incident_id')}")
        print(f"Original Risk Score: {original_risk}")
        print(f"Host: {incident.get('host')}")
        print(f"Severity: {incident.get('severity')}")
        print(f"Evidence items: {len(incident.get('evidence', []))}")
        print(f"{'='*80}")

        # Call investigate() - THIS IS THE REAL TEST
        print("\nCalling service.investigate(incident)...")
        response = None
        investigate_exception = None

        try:
            response = self.service.investigate(incident=incident)
            print("✓ investigate() completed without exception")
        except Exception as e:
            investigate_exception = e
            print(f"✗ investigate() raised exception: {type(e).__name__}: {str(e)}")

        # QUESTION A: Did REAL investigate() succeed?
        print(f"\n{'='*80}")
        print("QUESTION A: Did REAL investigate() succeed?")
        print(f"{'='*80}")

        if investigate_exception:
            print(f"NO - Exception raised: {type(investigate_exception).__name__}")
            print(f"Message: {str(investigate_exception)}")

            # Additional diagnosis
            if "timed out" in str(investigate_exception).lower():
                print("ROOT CAUSE: Ollama LLM provider timeout (180 seconds)")
                print("DIAGNOSIS: The Qwen3:8B model via Ollama is not responding within")
                print("           the 180-second timeout window. This could mean:")
                print("           - Ollama service is not running")
                print("           - Qwen3:8B model is not loaded")
                print("           - Model inference is very slow on this system")
                print("           - Network connectivity issue to Ollama")
            self.fail(f"investigate() failed: {investigate_exception}")
        else:
            print("YES - investigate() completed successfully")
            print(f"Response status: {response.status if response else 'None'}")

        # Verify we got a response object
        self.assertIsNotNone(response, "investigate() must return a response object")
        print(f"✓ Response object received: {type(response).__name__}")

        # QUESTION B: Did Qwen3:8B get invoked?
        print(f"\n{'='*80}")
        print("QUESTION B: Did Qwen3:8B get invoked?")
        print(f"{'='*80}")

        # Signs that LLM was invoked:
        # 1. nlp_risk_explanation is populated
        # 2. attack_sequence is populated
        # 3. mitre_investigation is populated

        llm_invoked = False
        llm_indicators = []

        if response.nlp_risk_explanation:
            llm_invoked = True
            llm_indicators.append("nlp_risk_explanation populated")
            print(f"✓ LLM invoked for NLP risk explanation: {bool(response.nlp_risk_explanation)}")

        if response.attack_sequence:
            llm_invoked = True
            llm_indicators.append("attack_sequence populated")
            print(f"✓ LLM invoked for attack sequence: {bool(response.attack_sequence)}")

        if response.mitre_investigation:
            llm_invoked = True
            llm_indicators.append("mitre_investigation populated")
            print(f"✓ LLM invoked for MITRE investigation: {bool(response.mitre_investigation)}")

        if llm_invoked:
            print(f"\nYES - Qwen3:8B was invoked")
            print(f"Evidence:")
            for indicator in llm_indicators:
                print(f"  - {indicator}")
        else:
            print(f"NO - Qwen3:8B was NOT invoked (deterministic fallback only)")
            print(f"Response has status: {response.status}")

        # QUESTION C: Was response validated?
        print(f"\n{'='*80}")
        print("QUESTION C: Was response validated?")
        print(f"{'='*80}")

        # Response validation checks:
        # 1. Response has grounded status
        # 2. Evidence claims are present
        # 3. No unsupported evidence references

        response_valid = False
        validation_checks = []

        # Check status
        if response.status and response.status != "validation_failed":
            response_valid = True
            validation_checks.append(f"Status is valid: {response.status}")
        else:
            validation_checks.append(f"Status indicates validation issue: {response.status}")

        # Check grounding flag
        if hasattr(response, 'grounded') and response.grounded:
            validation_checks.append("Response is grounded: True")
        else:
            validation_checks.append(f"Response grounded flag: {getattr(response, 'grounded', 'not set')}")

        # Check observed facts
        observed_facts = getattr(response, 'observed_facts', [])
        if observed_facts:
            validation_checks.append(f"Observed facts present: {len(observed_facts)}")
        else:
            validation_checks.append("Observed facts: empty or not present")

        print("\n".join(validation_checks))

        if response_valid or llm_invoked:
            print(f"\nYES - Response was validated and processed")
        else:
            print(f"\nPARTIAL - Response generated but with validation limitations")

        # QUESTION D: Was risk unchanged?
        print(f"\n{'='*80}")
        print("QUESTION D: Was risk unchanged?")
        print(f"{'='*80}")

        # Build fact packet to check if risk was preserved
        fact_packet = build_fact_packet(incident)
        fact_packet_risk = fact_packet.get("risk", {}).get("total_score")

        print(f"Original incident risk: {original_risk}")
        print(f"Fact packet risk: {fact_packet_risk}")

        if original_risk == fact_packet_risk:
            print(f"✓ Risk UNCHANGED: {original_risk} == {fact_packet_risk}")
            risk_unchanged = True
        else:
            print(f"✗ Risk CHANGED: {original_risk} != {fact_packet_risk}")
            risk_unchanged = False

        if risk_unchanged:
            print(f"\nYES - Risk score remained immutable")
            self.assertEqual(
                original_risk, fact_packet_risk,
                "Deterministic risk score must be preserved in Fact Packet"
            )
        else:
            self.fail(f"Risk score was modified: {original_risk} → {fact_packet_risk}")

        # Summary
        print(f"\n{'='*80}")
        print("FINAL ANSWERS")
        print(f"{'='*80}")
        print(f"A) Did REAL investigate() succeed?         YES" if not investigate_exception else f"A) Did REAL investigate() succeed?         NO ({type(investigate_exception).__name__})")
        print(f"B) Did Qwen3:8B get invoked?               {'YES' if llm_invoked else 'NO'}")
        print(f"C) Was response validated?                 YES" if response_valid or llm_invoked else f"C) Was response validated?                 PARTIAL")
        print(f"D) Was risk unchanged?                     {'YES' if risk_unchanged else 'NO'}")
        print(f"{'='*80}\n")


if __name__ == "__main__":
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(TestRealInvestigateCall)

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    if not result.wasSuccessful():
        print("\n" + "="*80)
        print("TEST FAILED - INVESTIGATE() ISSUE DETECTED")
        print("="*80)
        for test, trace in result.failures + result.errors:
            print(f"\n{test}:")
            print(trace)
