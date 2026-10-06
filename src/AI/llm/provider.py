"""
Provider abstraction for SentinelMesh LLM integrations.
"""

from abc import ABC, abstractmethod

from .models import LLMRequest, LLMResponse


class LLMProvider(ABC):
    """
    Abstract interface implemented by every SentinelMesh LLM provider.
    """

    @abstractmethod
    def generate(
        self,
        request: LLMRequest,
    ) -> LLMResponse:
        """
        Generate an LLM response.

        Implementations must not modify the supplied request.
        """
        raise NotImplementedError


__all__ = [
    "LLMProvider",
]