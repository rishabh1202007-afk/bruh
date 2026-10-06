"""
Test the SentinelMesh deterministic RAG retriever.
"""

from .retriever import retrieve


def print_results(result):
    """
    Print one retrieval result in a readable format.
    """

    print("\n" + "=" * 70)
    print("QUERY:")
    print(result.query)

    print("\n--- SECURITY KNOWLEDGE ---")

    if not result.security_knowledge:
        print("No results.")
    else:
        for item in result.security_knowledge:
            print(
                f"[{item.relevance}] "
                f"{item.title}"
            )

            print(
                f"    Source: {item.source}"
            )

            print(
                f"    Ref: "
                f"{', '.join(item.evidence_refs)}"
            )

            print(
                f"    {item.content}"
            )

    print("\n--- SENTINELMESH KNOWLEDGE ---")

    if not result.sentinelmesh_knowledge:
        print("No results.")
    else:
        for item in result.sentinelmesh_knowledge:
            print(
                f"[{item.relevance}] "
                f"{item.title}"
            )

            print(
                f"    Source: {item.source}"
            )

            print(
                f"    Ref: "
                f"{', '.join(item.evidence_refs)}"
            )

            print(
                f"    {item.content}"
            )

    print("\n--- WARNINGS ---")

    if result.warnings:
        for warning in result.warnings:
            print(
                f"- {warning}"
            )
    else:
        print("None")

    print(
        "\nInsufficient evidence:",
        result.insufficient_evidence,
    )


def main():
    """
    Run deterministic RAG retrieval tests.
    """

    queries = [
        "SM-002 account discovery",
        "credential manager activity",
        "synthetic telemetry attribution",
        "MITRE credential access",
        "CM-001 account discovery credential activity",
    ]

    for query in queries:

        result = retrieve(
            query=query,
            top_k=5,
        )

        print_results(result)

    # Explicit empty-query test.
    empty_result = retrieve("")

    print("\n" + "=" * 70)
    print("EMPTY QUERY TEST")
    print(
        "Insufficient evidence:",
        empty_result.insufficient_evidence,
    )
    print(
        "Warnings:",
        empty_result.warnings,
    )


if __name__ == "__main__":
    main()