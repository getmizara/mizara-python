"""
Mizara + LangChain create_agent() integration example

Shows the enforced pattern: mizara_middleware() runs as wrap_tool_call
middleware, so the policy decision happens before the tool can execute -
the model can't bypass this by simply not calling an authorize tool first.

For the lower-level raw StateGraph pattern (building the graph nodes
yourself instead of using create_agent), see examples/langgraph/.

Requires: OPENAI_API_KEY environment variable
Run:      python examples/langchain-agent/demo.py
"""

from __future__ import annotations

import json
from pathlib import Path

from langchain.agents import create_agent
from langchain.tools import tool
from mizara import create_mizara_client
from mizara.langchain import mizara_middleware

_mizara = create_mizara_client(
    policy_path=str(Path(__file__).parent / "policy.json")
)


@tool
def access_customer_record(record_id: str, contains_phi: bool) -> str:
    """
    Looks up a customer record.

    Args:
        record_id: The record to fetch.
        contains_phi: Whether this record contains protected health information.
    """
    return json.dumps({"record_id": record_id, "status": "found", "contains_phi": contains_phi})


agent = create_agent(
    model="gpt-4o-mini",
    tools=[access_customer_record],
    system_prompt=(
        "You are a customer support agent. Look up customer records as requested "
        "using access_customer_record. If a lookup is rejected, explain why to the "
        "user in plain terms and do not retry it yourself."
    ),
    middleware=[mizara_middleware(_mizara, actor_id="support_agent_v1")],
)
