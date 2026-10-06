from typing import Any, Dict, List
from .models import InvestigationStep
from .evidence_gap_engine import EvidenceGapEngine
from ..fact_packet.builder import canonical_mitre_techniques

class RecommendationEngine:
    def recommend(self, fact_packet: Dict[str, Any]) -> List[InvestigationStep]:
        recommendations: List[InvestigationStep] = []

        # 1. Evidence Gaps
        gap_engine = EvidenceGapEngine()
        gap_analysis = gap_engine.analyze(fact_packet)
        for gap in gap_analysis.gaps:
            action = ""
            if "process_context" in gap.category:
                action = "Collect process execution context for the affected host."
            elif "network_context" in gap.category:
                action = "Review network connections around the incident timestamp."
            elif "user_context" in gap.category:
                action = "Review account activity and associated context."
            else:
                action = f"Investigate potential evidence gap: {gap.description}"

            recommendations.append(
                InvestigationStep(
                    action=action,
                    rationale=gap.why_it_matters,
                    priority=gap.priority,
                    supporting_evidence_refs=gap.supporting_refs,
                    evidence_gap_refs=[gap.gap_id]
                )
            )

        # 2. MITRE Techniques
        for technique in canonical_mitre_techniques(fact_packet.get("mitre", {})):
            technique_id = technique.get("technique_id")
            if not technique_id:
                continue

            # Simple logic for now
            action = f"Review activity mapped to MITRE technique {technique_id} ({technique.get('technique_name')})."
            recommendations.append(
                InvestigationStep(
                    action=action,
                    rationale=f"Observed MITRE technique {technique_id} requires context.",
                    priority="medium",
                    mitre_refs=[technique_id]
                )
            )

        return recommendations
