"""
SentinelMesh AI Investigation Agent.

The agent is an investigation assistant, not the detection authority.
"""

from .investigation_agent import (
    InvestigationAgent,
    investigate,
)

__all__ = [
    "InvestigationAgent",
    "investigate",
]