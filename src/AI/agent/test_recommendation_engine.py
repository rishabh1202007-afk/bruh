import unittest
import sys
sys.path.insert(0, '.')
from src.AI.agent.recommendation_engine import RecommendationEngine

class TestRecommendationEngine(unittest.TestCase):
    def setUp(self):
        self.engine = RecommendationEngine()

    def test_process_context_gap(self):
        fact_packet = {'detections': [{'rule_name': 'Suspicious Script Execution'}]}
        recommendations = self.engine.recommend(fact_packet)
        self.assertTrue(any(r.evidence_gap_refs == ['GAP-PROCESS-CONTEXT'] for r in recommendations))

    def test_network_context_gap(self):
        fact_packet = {'detections': [{'rule_name': 'Possible Command and Control Activity'}]}
        recommendations = self.engine.recommend(fact_packet)
        self.assertTrue(any(r.evidence_gap_refs == ['GAP-NETWORK-CONTEXT'] for r in recommendations))

    def test_mitre_mapping(self):
        fact_packet = {'mitre': [{'technique_id': 'T1059', 'technique_name': 'Command and Scripting Interpreter'}]}
        recommendations = self.engine.recommend(fact_packet)
        self.assertTrue(any(r.mitre_refs == ['T1059'] for r in recommendations))

    def test_priority_is_set(self):
        fact_packet = {'detections': [{'rule_name': 'Possible Command and Control Activity'}]}
        recommendations = self.engine.recommend(fact_packet)
        for r in recommendations:
            self.assertIn(r.priority, ['low', 'medium', 'high', 'critical'])

if __name__ == '__main__':
    unittest.main()
