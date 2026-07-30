"""
Mizara + OpenAI Agents SDK demo

Runs two scenarios showing the enforced guardrail:
  Scenario A: 200 recipients, internal    → ALLOW    → sends
  Scenario B: 50,000 recipients, external → RE_ROUTE  → blocked before it runs

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

    print("Mizara + OpenAI Agents SDK - Enforced Guardrail Demo\n")

    await run_scenario(
        "Scenario A - Broadcast to 200 internal recipients (under the threshold)",
        "Send a broadcast to our 200 internal team members announcing the new release.",
    )
    await run_scenario(
        "Scenario B - Broadcast to 50,000 external customers (over the threshold)",
        "Send a broadcast to all 50,000 external customers announcing the new release.",
    )


if __name__ == "__main__":
    asyncio.run(main())
