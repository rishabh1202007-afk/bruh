import unittest
from .risk_explanation import explain_risk_score, RiskExplanation

class TestRiskExplanation(unittest.TestCase):
    def test_ranking_and_tie_breaking(self):
        packet = {
            "incident": {"incident_id": "INC-002"},
            "risk": {
                "total_score": 50,
                "factor_details": {
                    "detection_severity": {"score": 5, "maximum": 15},
                    "behavioral_evidence": {"score": 15, "maximum": 15},
                    "correlation_strength": {"score": 5, "maximum": 15}, # Same score (5), should be ranked by FACTOR_ORDER
                }
            }
        }
        explanation = explain_risk_score(packet)
        # Check ranking order
        factors = [f["factor"] for f in explanation.top_contributing_factors]
        # FACTOR_ORDER: detection_severity, behavioral_evidence, correlation_strength
        # Expected: behavioral_evidence (score 15), detection_severity (score 5), correlation_strength (score 5)
        self.assertEqual(factors[0], "behavioral_evidence")
        self.assertEqual(factors[1], "detection_severity")
        self.assertEqual(factors[2], "correlation_strength")

    def test_attribution_warning(self):
        packet = {
            "incident": {"incident_id": "INC-003"},
            "risk": {
                "total_score": 10,
                "factor_details": {
                    "threat_profile_alignment": {"score": 10, "maximum": 10}
                }
            },
            "threat_profiles": [{"attribution_status": "behavioral_profile_match_only"}]
        }
        explanation = explain_risk_score(packet)
        self.assertIsNotNone(explanation.attribution_warning)
        self.assertIn("behavioral context only", explanation.attribution_warning)

    def test_insufficient_evidence(self):
        packet = {"incident": {"incident_id": "INC-NONE"}}
        explanation = explain_risk_score(packet)
        self.assertTrue(explanation.insufficient_evidence)
        self.assertEqual(explanation.status, "insufficient_evidence")

    def test_synthetic_telemetry(self):
        packet = {
            "incident": {"incident_id": "INC-SYNTHETIC"},
            "risk": {
                "total_score": 10,
                "factor_details": {
                    "behavioral_evidence": {"score": 10, "maximum": 15}
                }
            },
            "behaviors": [{"behavior_id": "B-1", "synthetic": True}]
        }
        explanation = explain_risk_score(packet)
        self.assertTrue(any("Synthetic" in limit for limit in explanation.limitations))

if __name__ == "__main__":
    unittest.main()
