"""
Mizara + OpenAI Agents SDK integration example

Shows the enforced pattern: mizara_guardrail() runs as a tool_input_guardrail
on the tool itself, so the policy decision happens before the tool can
execute - the model can't bypass this by simply not calling an authorize
tool first, unlike wiring authorize() in as a separate callable tool.

Requires: OPENAI_API_KEY environment variable
Run:      python examples/openai-agents/demo.py
"""

from __future__ import annotations

import json
from pathlib import Path

from agents import Agent, function_tool
from mizara import create_mizara_client
from mizara.openai_agents import mizara_guardrail

_mizara = create_mizara_client(
    policy_path=str(Path(__file__).parent / "policy.json")
)


@function_tool(tool_input_guardrails=[mizara_guardrail(_mizara, actor_id="comms_agent_v1")])
def send_customer_broadcast(message: str, recipient_count: int, external: bool) -> str:
    """
    Sends a broadcast message to customers.

    Args:
        message: The broadcast content.
        recipient_count: How many recipients this will reach.
        external: Whether recipients are outside the company (customers) vs internal.
    """
    return json.dumps({
        "success": True,
        "sent_to": recipient_count,
        "message_preview": message[:80],
    })


agent = Agent(
    name="comms-agent",
    instructions=(
        "You are a customer communications agent. Send broadcasts as requested "
        "using send_customer_broadcast. If a send is rejected, explain why to the user "
        "in plain terms and do not retry it yourself."
    ),
    tools=[send_customer_broadcast],
)
