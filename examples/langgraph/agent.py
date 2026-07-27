"""
Mizara + LangGraph (Python) integration example

Shows the authorization gate pattern: mizara.authorize() evaluates a
pending tool call BEFORE it executes, and the graph routes to execution
or rejection based on the decision.

Graph:
  START → agent → authorize → [ALLOW]  → tools → agent → END
                             → [DENY]   → blocked        → END

No LLM API key required - the agent node is simulated so you can run
this immediately. Replace agentNode with a real LLM call to use in
production.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Annotated, Any, Optional

from langgraph.graph import END, START, StateGraph
from langgraph.graph.message import add_messages
from langchain_core.messages import AIMessage, HumanMessage, ToolMessage
from typing_extensions import TypedDict

from mizara import create_mizara_client

mizara = create_mizara_client(
    policy_path=str(Path(__file__).parent / "policy.json")
)


# ── State ─────────────────────────────────────────────────────────────────────

class State(TypedDict):
    messages: Annotated[list, add_messages]
    authorization: Optional[dict[str, Any]]


# ── Nodes ─────────────────────────────────────────────────────────────────────

def agent_node(state: State) -> dict:
    """
    Decides what to do next.

    Production: replace with a real LLM call:
        response = llm.bind_tools(tools).invoke(state["messages"])
        return {"messages": [response]}

    This demo simulates the LLM deciding to delete a cloud resource, with
    the environment read from the initial human message.
    """
    last = state["messages"][-1]

    # After receiving a tool result or blocked response, we're done
    if isinstance(last, ToolMessage):
        return {
            "messages": [AIMessage(content=f"Resource deleted successfully. {last.content}")]
        }

    if isinstance(last, AIMessage) and not last.tool_calls:
        return {}

    # Extract the target environment from the human message (demo simulation)
    human = next((m for m in state["messages"] if isinstance(m, HumanMessage)), None)
    match = re.search(r"\b(production|staging|development)\b", human.content if human else "", re.IGNORECASE)
    environment = match.group(1).lower() if match else "staging"

    return {
        "messages": [
            AIMessage(
                content="",
                tool_calls=[{
                    "id": f"call_{id(state)}",
                    "name": "delete_cloud_resource",
                    "args": {"environment": environment, "resource_id": "res_9c21"},
                    "type": "tool_call",
                }],
            )
        ]
    }


def authorization_node(state: State) -> dict:
    """
    The enforcement gate. mizara.authorize() evaluates the pending tool
    call before anything executes.
    """
    last = state["messages"][-1]
    if not isinstance(last, AIMessage) or not last.tool_calls:
        return {}

    call = last.tool_calls[0]
    result = mizara.authorize(
        actor={"id": "agent_platform_v4", "type": "autonomous_agent", "framework": "langgraph"},
        action={"name": call["name"], "risk_profile": "high_irreversible"},
        resource={
            "type": "cloud_resource",
            "id": call["args"].get("resource_id", "unknown"),
            "attributes": call["args"],
        },
        context={"client_id": "demo_customer"},
    )

    return {
        "authorization": {
            "status": result.status,
            "rule_id": result.evaluation_metadata.triggered_rule_id,
            "receipt_id": result.cryptographic_receipt.id,
            "error": result.enforcement.user_facing_error,
        }
    }


def tools_node(state: State) -> dict:
    """Executes the tool - only reached when authorization returned ALLOW."""
    last = state["messages"][-1]
    if not isinstance(last, AIMessage) or not last.tool_calls:
        return {}

    call = last.tool_calls[0]
    auth = state.get("authorization", {})

    # Simulate calling the actual cloud provider's delete API
    result = {
        "success": True,
        "deletion_id": f"del_{abs(hash(call['id']))}",
        "resource_id": call["args"]["resource_id"],
        "mizara_receipt": auth.get("receipt_id"),
    }

    return {
        "messages": [
            ToolMessage(
                tool_call_id=call["id"],
                content=str(result),
                name=call["name"],
            )
        ],
        "authorization": None,
    }


def blocked_node(state: State) -> dict:
    """Reached when authorization returned DENY, REDACT, or RE_ROUTE."""
    last = state["messages"][-1]
    call = last.tool_calls[0] if isinstance(last, AIMessage) and last.tool_calls else None
    auth = state.get("authorization", {})

    return {
        "messages": [
            AIMessage(
                content="\n".join(filter(None, [
                    f"[mizara] Action blocked - status: {auth.get('status')}",
                    f"Tool: {call['name']}" if call else None,
                    f"Rule: {auth.get('rule_id')}",
                    f"Reason: {auth.get('error')}",
                    f"Receipt: {auth.get('receipt_id')}",
                ]))
            )
        ],
        "authorization": None,
    }


# ── Routing ───────────────────────────────────────────────────────────────────

def route_after_agent(state: State) -> str:
    last = state["messages"][-1]
    if isinstance(last, AIMessage) and last.tool_calls:
        return "authorize"
    return END


def route_after_authorization(state: State) -> str:
    return "tools" if state.get("authorization", {}).get("status") == "ALLOW" else "blocked"


# ── Graph ─────────────────────────────────────────────────────────────────────

graph = (
    StateGraph(State)
    .add_node("agent", agent_node)
    .add_node("authorize", authorization_node)
    .add_node("tools", tools_node)
    .add_node("blocked", blocked_node)
    .add_edge(START, "agent")
    .add_conditional_edges("agent", route_after_agent)
    .add_conditional_edges("authorize", route_after_authorization)
    .add_edge("tools", "agent")
    .add_edge("blocked", END)
    .compile()
)
