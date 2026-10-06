import sys
import unittest

sys.path.insert(0, '.')

# Import the 4 test classes that actually exist
from src.AI.agent.test_recommendation_engine import TestRecommendationEngine
from src.AI.agent.test_investigation_integration import TestInvestigationIntegration
from src.AI.agent.test_llm_risk_explanation import TestLLMRiskExplainer
from src.AI.agent.test_mitre_investigator import TestMITREInvestigator
from src.AI.agent.test_risk_explanation import TestRiskExplanation

# Create test suite
suite = unittest.TestSuite()

for test_class in [
    TestRecommendationEngine,
    TestInvestigationIntegration,
    TestLLMRiskExplainer,
    TestMITREInvestigator,
    TestRiskExplanation,
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
