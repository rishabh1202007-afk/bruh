import json
import os
import urllib.error
import urllib.request
from typing import Any, Dict

from .models import LLMRequest, LLMResponse
from .provider import LLMProvider


class OllamaProvider(LLMProvider):
    """
    Local Ollama LLM provider for SentinelMesh.

    Uses Ollama's local /api/chat endpoint and does not require
    an external API key or cloud service.
    """

    provider_name = "ollama"

    def __init__(
        self,
        host: str | None = None,
        default_model: str | None = None,
        timeout: int = 180,
    ):
        self.host = (
            host
            or os.getenv("OLLAMA_HOST")
            or "http://127.0.0.1:11434"
        ).rstrip("/")

        self.default_model = (
            default_model
            or os.getenv("OLLAMA_MODEL")
            or "qwen3:8b"
        )

        self.timeout = timeout

    def generate(self, request: LLMRequest) -> LLMResponse:
        """
        Generate a response using the locally running Ollama model.

        If request.metadata contains a JSON schema under
        ``response_format``, Ollama is instructed to follow that schema.

        If no response format is supplied, no output-format constraint
        is sent to Ollama.
        """

        model = request.model or self.default_model

        response_format = request.metadata.get("response_format")

        payload: Dict[str, Any] = {
            "model": model,
            "messages": [
                {
                    "role": "system",
                    "content": request.system_prompt,
                },
                {
                    "role": "user",
                    "content": request.user_prompt,
                },
            ],
            "stream": False,
            "think": False,
            "options": {
                "temperature": request.temperature,
                "num_predict": request.max_output_tokens,
            },
        }

        # Only constrain the response format when the caller explicitly
        # requests structured output.
        if response_format is not None:
            payload["format"] = response_format

        url = f"{self.host}/api/chat"
        body = json.dumps(payload).encode("utf-8")

        http_request = urllib.request.Request(
            url,
            data=body,
            headers={
                "Content-Type": "application/json",
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(
                http_request,
                timeout=self.timeout,
            ) as response:
                response_body = response.read().decode("utf-8")

        except urllib.error.HTTPError as exc:
            # HTTPError means Ollama was reached successfully but rejected
            # the request. Read the actual server response so debugging does
            # not incorrectly report this as a connection failure.
            try:
                error_body = exc.read().decode("utf-8", errors="replace")
            except Exception:
                error_body = ""

            raise RuntimeError(
                "Ollama rejected the request "
                f"(HTTP {exc.code}) at {url}.\n"
                f"Server response: {error_body or '<empty response>'}"
            ) from exc

        except urllib.error.URLError as exc:
            raise RuntimeError(
                "Could not connect to Ollama at "
                f"{self.host}. Make sure Ollama is running.\n"
                f"Reason: {exc.reason}"
            ) from exc

        except TimeoutError as exc:
            raise RuntimeError(
                f"Ollama request timed out after "
                f"{self.timeout} seconds."
            ) from exc

        try:
            data = json.loads(response_body)
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                "Ollama returned an invalid JSON response.\n"
                f"Response: {response_body[:1000]}"
            ) from exc

        message = data.get("message", {})

        if not isinstance(message, dict):
            raise RuntimeError(
                "Ollama response did not contain a valid message object."
            )

        text = message.get("content", "")

        if not isinstance(text, str):
            raise RuntimeError(
                "Ollama response contained invalid message content."
            )

        if not text.strip():
            raise RuntimeError(
                "Ollama returned an empty message content."
            )

        response_model = data.get("model") or model
        request_id = data.get("id")

        metadata = {
            "host": self.host,
            "done": data.get("done"),
            "done_reason": data.get("done_reason"),
            "prompt_eval_count": data.get("prompt_eval_count"),
            "eval_count": data.get("eval_count"),
            "total_duration": data.get("total_duration"),
            "load_duration": data.get("load_duration"),
            "structured_output": response_format is not None,
            "thinking_disabled": True,
        }

        return LLMResponse(
            text=text,
            model=response_model,
            provider=self.provider_name,
            request_id=request_id,
            raw_response=data,
            metadata=metadata,
        )


__all__ = ["OllamaProvider"]