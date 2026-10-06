import subprocess
import sys
import os

# Define the baseline tests
BASELINE_TESTS = [
    "src.AI.agent.test_attack_sequence",
    "src.AI.agent.test_historical_comparison",
    "src.AI.agent.test_evidence_validator",
    "src.AI.agent.test_gap_integration",
    "src.AI.agent.test_investigation_agent",
    "src.AI.agent.test_investigation_service",
    "src.AI.agent.test_investigation_service_rag",
    "src.AI.agent.test_structured_llm_investigator",
]

os.environ["PYTHONPATH"] = os.path.abspath("src")

passed_count = 0
failed_count = 0

print(f"{'Test module':<60} | {'Status'}")
print("-" * 75)

for test_module in BASELINE_TESTS:
    result = subprocess.run(
        [sys.executable, "-m", test_module],
        capture_output=True,
        text=True
    )
    if result.returncode == 0:
        print(f"{test_module:<60} | PASS")
        passed_count += 1
    else:
        print(f"{test_module:<60} | FAIL")
        failed_count += 1
        # Print first few lines of error to understand why
        print(result.stdout[:200])
        print(result.stderr[:200])

print("-" * 75)
print(f"Total: {len(BASELINE_TESTS)}")
print(f"Passed: {passed_count}")
print(f"Failed: {failed_count}")
EOF
python test_baseline.py
