"""
Azure OpenAI provider for SentinelMesh.

Uses the Azure OpenAI v1 Responses API through the OpenAI Python SDK.

Required environment variables:

    AZURE_OPENAI_ENDPOINT
    AZURE_OPENAI_API_KEY
    AZURE_OPENAI_DEPLOYMENT

Example:

    AZURE_OPENAI_ENDPOINT=https://your-resource.openai.azure.com
    AZURE_OPENAI_API_KEY=...
    AZURE_OPENAI_DEPLOYMENT=your-model-deployment
"""

import os
from typing import Any, Dict

from .models import LLMRequest, LLMResponse
from .provider import LLMProvider


class AzureOpenAIProvider(LLMProvider):
    """
    SentinelMesh LLM provider backed by Azure OpenAI.
    """

    provider_name = "azure_openai"

    def __init__(
        self,
        endpoint: str | None = None,
        api_key: str | None = None,
        deployment: str | None = None,
    ):
        self.endpoint = (
            endpoint
            or os.getenv("AZURE_OPENAI_ENDPOINT")
        )

        self.api_key = (
            api_key
            or os.getenv("AZURE_OPENAI_API_KEY")
        )

        self.deployment = (
            deployment
            or os.getenv("AZURE_OPENAI_DEPLOYMENT")
        )

        missing = []

        if not self.endpoint:
            missing.append(
                "AZURE_OPENAI_ENDPOINT"
            )

        if not self.api_key:
            missing.append(
                "AZURE_OPENAI_API_KEY"
            )

        if not self.deployment:
            missing.append(
                "AZURE_OPENAI_DEPLOYMENT"
            )

        if missing:
            raise ValueError(
                "Missing Azure OpenAI configuration: "
                + ", ".join(missing)
            )

        try:
            from openai import OpenAI
        except ImportError as exc:
            raise ImportError(
                "The 'openai' package is required for "
                "AzureOpenAIProvider. Install it with "
                "'python3 -m pip install openai'."
            ) from exc

        base_url = (
            self.endpoint.rstrip("/")
            + "/openai/v1/"
        )

        self.client = OpenAI(
            api_key=self.api_key,
            base_url=base_url,
        )

    def generate(
        self,
        request: LLMRequest,
    ) -> LLMResponse:
        """
        Generate a response using Azure OpenAI.
        """

        response = self.client.responses.create(
            model=request.model
            or self.deployment,
            input=[
                {
                    "role": "system",
                    "content": request.system_prompt,
                },
                {
                    "role": "user",
                    "content": request.user_prompt,
                },
            ],
            temperature=request.temperature,
            max_output_tokens=request.max_output_tokens,
        )

        text = getattr(
            response,
            "output_text",
            None,
        )

        if text is None:
            text = ""

        raw_response: Dict[str, Any] = {}

        if hasattr(response, "model_dump"):
            raw_response = response.model_dump()

        request_id = getattr(
            response,
            "id",
            None,
        )

        response_model = getattr(
            response,
            "model",
            None,
        ) or request.model or self.deployment

        return LLMResponse(
            text=text,
            model=response_model,
            provider=self.provider_name,
            request_id=request_id,
            raw_response=raw_response,
            metadata={
                "deployment": self.deployment,
            },
        )


__all__ = [
    "AzureOpenAIProvider",
]