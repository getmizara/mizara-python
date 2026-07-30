"""
Mizara + LangChain create_agent() demo

Runs two scenarios showing the enforced guardrail:
  Scenario A: record without PHI → ALLOW  → returned
  Scenario B: record with PHI    → REDACT → blocked before it runs

Requires: OPENAI_API_KEY environment variable, plus the langchain-openai
package (pip install langchain-openai) for the gpt-4o-mini provider used
here - swap the model string and provider package for any other model.
Run: python examples/langchain-agent/demo.py
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))
sys.path.insert(0, str(Path(__file__).parent))

from agent import agent


def run_scenario(name: str, message: str) -> None:
    print(f"─── {name} {'─' * max(0, 50 - len(name))}")
    print(f"Input: \"{message}\"\n")
    result = agent.invoke({"messages": [{"role": "user", "content": message}]})
    print(result["messages"][-1].content)
    print()


def main() -> None:
    if not os.environ.get("OPENAI_API_KEY"):
        print("Error: OPENAI_API_KEY environment variable is required.")
        print("  export OPENAI_API_KEY=sk-...")
        sys.exit(1)

    print("Mizara + LangChain create_agent() - Enforced Guardrail Demo\n")

    run_scenario(
        "Scenario A - Look up record rec_100 (no PHI)",
        "Look up customer record rec_100. It does not contain PHI.",
    )
    run_scenario(
        "Scenario B - Look up record rec_200 (contains PHI)",
        "Look up customer record rec_200. It contains PHI.",
    )


if __name__ == "__main__":
    main()
