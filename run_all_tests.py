import sys
import unittest

sys.path.insert(0, '.')
sys.path.insert(0, './src')

# Import the 4 test classes that actually exist
from src.AI.agent.test_recommendation_engine import TestRecommendationEngine
from src.AI.agent.test_investigation_integration import TestInvestigationIntegration
from src.AI.agent.test_llm_risk_explanation import TestLLMRiskExplainer
from src.AI.agent.test_mitre_investigator import TestMITREInvestigator
from src.AI.agent.test_risk_explanation import TestRiskExplanation

# Import new capability test classes
from src.AI.agent.test_counterfactual_engine import TestCounterfactualEngine
from src.AI.agent.test_feedback_store import TestAnalystFeedbackLoop
from src.AI.agent.test_counterfactual_feedback_integration import TestCounterfactualFeedbackIntegration

# Import AI benchmark scenarios
from src.AI.agent.test_ai_benchmark import (
    TestScenarioA_WindowsInvestigation,
    TestScenarioB_SyntheticTelemetry,
    TestScenarioC_InsufficientEvidence,
    TestScenarioD_PromptInjection,
    TestScenarioE_UnsupportedEvidence,
    TestScenarioF_LLMFailure,
    TestScenarioG_Counterfactual,
    TestScenarioH_HistoricalComparison,
)

# Import end-to-end integration test
from src.AI.agent.test_end_to_end_integration import TestEndToEndAIIntegration

# Create test suite
suite = unittest.TestSuite()

for test_class in [
    TestRecommendationEngine,
    TestInvestigationIntegration,
    TestLLMRiskExplainer,
    TestMITREInvestigator,
    TestRiskExplanation,
    TestCounterfactualEngine,
    TestAnalystFeedbackLoop,
    TestCounterfactualFeedbackIntegration,
    # AI Benchmark scenarios (8 tests)
    TestScenarioA_WindowsInvestigation,
    TestScenarioB_SyntheticTelemetry,
    TestScenarioC_InsufficientEvidence,
    TestScenarioD_PromptInjection,
    TestScenarioE_UnsupportedEvidence,
    TestScenarioF_LLMFailure,
    TestScenarioG_Counterfactual,
    TestScenarioH_HistoricalComparison,
    # End-to-end integration (8 tests)
    TestEndToEndAIIntegration,
]:
    tests = unittest.TestLoader().loadTestsFromTestCase(test_class)
    suite.addTests(tests)

runner = unittest.TextTestRunner(verbosity=2)
result = runner.run(suite)

print("\n" + "="*80)
print("TEST SUMMARY")
print("="*80)
print(f"Tests run: {result.testsRun}")
print(f"Passed: {result.testsRun - len(result.failures) - len(result.errors)}")
print(f"Failed: {len(result.failures)}")
print(f"Errors: {len(result.errors)}")
print(f"Skipped: {len(result.skipped)}")


