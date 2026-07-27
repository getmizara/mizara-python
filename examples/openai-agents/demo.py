"""
Mizara + OpenAI Agents SDK demo

Runs two scenarios showing the authorization gate:
  Scenario A: $1,200 payment  → ALLOW  → executes
  Scenario B: $25,000 payment → DENY   → blocked

Requires: OPENAI_API_KEY environment variable
Run:      python examples/openai-agents/demo.py
"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))
sys.path.insert(0, str(Path(__file__).parent))

from agent import agent
from agents import Runner


async def run_scenario(name: str, message: str) -> None:
    print(f"─── {name} {'─' * max(0, 50 - len(name))}")
    print(f"Input: \"{message}\"\n")
    result = await Runner.run(agent, message)
    print(result.final_output)
    print()


async def main() -> None:
    if not os.environ.get("OPENAI_API_KEY"):
        print("Error: OPENAI_API_KEY environment variable is required.")
        print("  export OPENAI_API_KEY=sk-...")
        sys.exit(1)

    print("Mizara + OpenAI Agents SDK - Authorization Gate Demo\n")

    await run_scenario(
        "Scenario A - Approve $1,200 payment (under the limit)",
        "Please approve a $1,200 payment for invoice INV-4471.",
    )
    await run_scenario(
        "Scenario B - Approve $25,000 payment (over the limit)",
        "Please approve a $25,000 payment for invoice INV-4472.",
    )


if __name__ == "__main__":
    asyncio.run(main())
