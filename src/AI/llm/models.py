"""
Data models for the SentinelMesh LLM layer.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class LLMRequest:
    """
    Request sent to an LLM provider.
    """

    system_prompt: str
    user_prompt: str
    model: str
    temperature: float = 0.0
    max_output_tokens: int = 1200
    metadata: Dict[str, Any] = field(
        default_factory=dict
    )


@dataclass
class LLMResponse:
    """
    Normalized response returned by an LLM provider.
    """

    text: str
    model: str
    provider: str
    request_id: str | None = None
    raw_response: Dict[str, Any] = field(
        default_factory=dict
    )
    metadata: Dict[str, Any] = field(
        default_factory=dict
    )


__all__ = [
    "LLMRequest",
    "LLMResponse",
]