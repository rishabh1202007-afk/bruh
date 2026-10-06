from .models import LLMRequest
from .ollama_provider import OllamaProvider


def main():
    print("=" * 70)
    print("SENTINELMESH OLLAMA PROVIDER TEST")
    print("=" * 70)

    provider = OllamaProvider()

    request = LLMRequest(
        system_prompt=(
            "You are a test assistant for SentinelMesh. "
            "Answer briefly and do not invent security evidence."
        ),
        user_prompt=(
            "In one sentence, explain what a security incident is."
        ),
        model="qwen3:8b",
        temperature=0.0,
        max_output_tokens=150,
        metadata={
            "test": "ollama_provider",
        },
    )

    print("\nProvider:", provider.provider_name)
    print("Model:", request.model)
    print("Endpoint:", provider.host)

    response = provider.generate(request)

    assert response.provider == "ollama"
    assert response.model == "qwen3:8b"
    assert isinstance(response.text, str)
    assert response.text.strip()

    print("\n--- MODEL RESPONSE ---")
    print(response.text.strip())

    print("\n--- RESPONSE METADATA ---")
    print("Provider:", response.provider)
    print("Model:", response.model)
    print("Request ID:", response.request_id)
    print("Evaluation tokens:", response.metadata.get("eval_count"))

    print("\nProvider contract: PASS")
    print("Ollama connection: PASS")
    print("Model response: PASS")

    print("=" * 70)
    print("ALL OLLAMA PROVIDER TESTS PASSED")
    print("=" * 70)


if __name__ == "__main__":
    main()