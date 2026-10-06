import unittest
from unittest.mock import Mock
from .investigation_service import SentinelMeshInvestigationService
from .models import InvestigationResponse

class TestInvestigationIntegration(unittest.TestCase):
    def test_unified_investigation_result(self):
        mock_investigator = Mock()
        # Ensure investigator returns a response that matches InvestigationResponse construction
        mock_investigator.investigate.return_value = InvestigationResponse(
            incident_id="INC-001",
            status="investigating",
            summary="All components integrated."
        )
        svc = SentinelMeshInvestigationService(investigator=mock_investigator)
        
        incident = {
            "incident_id": "INC-001",
            "evidence": [],
            "risk_scoring": {"total_score": 10, "factor_details": {}}
        }
        
        result = svc.investigate(incident)
        
        self.assertEqual(result.incident_id, "INC-001")
        self.assertIsNotNone(result.risk_explanation)
        self.assertIsNotNone(result.nlp_risk_explanation)
        self.assertIsNotNone(result.attack_sequence)

if __name__ == "__main__":
    unittest.main()
