from AI.llm.models import LLMRequest
from AI.llm.ollama_provider import OllamaProvider


def main():
    provider = OllamaProvider(
        default_model="qwen3:8b",
        timeout=180,
    )

    request = LLMRequest(
        system_prompt=(
            "You are a JSON generation test for SentinelMesh. "
            "Return ONLY one valid JSON object. "
            "Do not use Markdown. "
            "Do not explain anything outside the JSON."
        ),
        user_prompt=(
            "Return exactly this JSON structure with meaningful string values "
            "and empty arrays where appropriate:\n"
            "{\n"
            '  "status": "investigating",\n'
            '  "summary": "JSON output test",\n'
            '  "observed_facts": [],\n'
            '  "knowledge_context": [],\n'
            '  "uncertainties": [],\n'
            '  "evidence_gaps": [],\n'
            '  "next_investigation_steps": [],\n'
            '  "safety_warnings": [],\n'
            '  "grounded": true,\n'
            '  "insufficient_evidence": false\n'
            "}"
        ),
        model="qwen3:8b",
        temperature=0.0,
        max_output_tokens=1200,
    )

    response = provider.generate(request)

    print()
    print("=== OLLAMA STRUCTURED JSON DIAGNOSTIC ===")
    print(f"Model: {response.model}")
    print(f"Provider: {response.provider}")
    print()
    print("=== RAW MODEL CONTENT ===")
    print(response.text)
    print()
    print("=== RAW OLLAMA RESPONSE ===")
    print(response.raw_response)
    print()
    print("=== METADATA ===")
    print(response.metadata)


if __name__ == "__main__":
    main()