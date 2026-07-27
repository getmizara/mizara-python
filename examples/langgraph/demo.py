"""
Run: python examples/langgraph/demo.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from langchain_core.messages import HumanMessage
sys.path.insert(0, str(Path(__file__).parent))
from agent import graph

scenarios = [
    {
        "name": "Scenario A - Delete in staging (allowed environment)",
        "message": "Please delete the temporary cache instance res_9c21 in staging, it is no longer needed.",
    },
    {
        "name": "Scenario B - Delete in production (requires approval)",
        "message": "Please delete the primary database instance res_9c21 in production, we are decommissioning the old service.",
    },
]

print("Mizara + LangGraph (Python) - Authorization Gate Demo\n")

for s in scenarios:
    print(f"─── {s['name']} {'─' * (50 - len(s['name']))}")
    print(f"Input: \"{s['message']}\"\n")

    result = graph.invoke({"messages": [HumanMessage(content=s["message"])]})
    print(result["messages"][-1].content)
    print()
