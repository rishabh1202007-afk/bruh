import json
import re
from typing import Any, Dict, Iterable, List, Set

from ..llm.models import LLMResponse
from .evidence_gap_engine import (
    EvidenceGapAnalysis,
    analyze_evidence_gaps,
)
from .evidence_validator import (
    assert_valid_investigation_response,
)
from .investigation_agent import InvestigationResponse
from .llm_investigator import LLMInvestigator
from .base_structured_llm_investigator import BaseStructuredLLMInvestigator

STRUCTURED_RESPONSE_INSTRUCTION = """
<REPLACE_WITH_ACTUAL_CONTENT_FROM_ORIGINAL_FILE>
"""
