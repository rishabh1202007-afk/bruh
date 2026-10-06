from .llm_investigator import LLMInvestigator
from .test_llm_investigator import build_test_fact_packet


def main():
    print("=" * 70)
    print("SENTINELMESH LIVE QWEN3 INVESTIGATION TEST")
    print("=" * 70)

    fact_packet = build_test_fact_packet()

    investigator = LLMInvestigator(
        model="qwen3:8b",
        temperature=0.0,
        max_output_tokens=500,
    )

    response = investigator.investigate(
        fact_packet=fact_packet,
        analyst_question=(
            "Analyze this incident using only the supplied "
            "Fact Packet. Clearly distinguish observed facts, "
            "security knowledge, uncertainty, and recommended "
            "investigation steps. Do not invent evidence."
        ),
    )

    print("\n--- INCIDENT ---")
    print(
        fact_packet["incident"]["incident_id"]
    )

    print("\n--- MODEL ---")
    print(response.model)

    print("\n--- PROVIDER ---")
    print(response.provider)

    print("\n--- STATUS ---")
    print(response.metadata.get("status"))

    print("\n--- QWEN3 INVESTIGATION RESPONSE ---")
    print(response.text)

    print("\n--- METADATA ---")
    print("LLM called:", response.metadata.get("llm_called"))
    print("Evaluation tokens:", response.metadata.get("eval_count"))

    assert response.provider == "ollama"
    assert response.model == "qwen3:8b"
    assert response.text.strip()
    assert response.metadata.get("llm_called") is True

    print("\n" + "=" * 70)
    print("LIVE QWEN3 INVESTIGATION TEST PASSED")
    print("=" * 70)


if __name__ == "__main__":
    main()