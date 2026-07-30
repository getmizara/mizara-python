"""
LangChain / LangGraph integration. Requires the 'langchain' extra:
    pip install mizara[langchain]

Wraps a Mizara client as wrap_tool_call middleware, so a policy decision
runs before the tool executes and can block it - unlike exposing
authorize() as a separate tool, the model can't skip this by just not
calling it.
"""

from __future__ import annotations

from typing import Any

try:
    from langchain.agents.middleware import AgentMiddleware, wrap_tool_call
    from langchain_core.messages import ToolMessage
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "mizara.langchain requires the 'langchain' extra: pip install mizara[langchain]"
    ) from exc

from .resilient_client import ResilientHostedClient
from .sdk import MizaraClient
from .types import Action, Actor, Resource


def mizara_middleware(
    client: MizaraClient | ResilientHostedClient,
    *,
    actor_id: str = "langchain_agent",
    resource_type: str | None = None,
) -> AgentMiddleware:
    """
    Builds LangChain/LangGraph agent middleware backed by the given Mizara
    client. Pass it to create_agent(middleware=[...]).

    The tool's name becomes the action name Mizara evaluates against; the
    tool's arguments become the resource attributes. resource_type defaults
    to the tool name if not given.

    ALLOW calls the tool as normal. DENY, REDACT, and RE_ROUTE all reject the
    call with the policy's remediation message - REDACT and RE_ROUTE don't
    have a meaningful pre-execution behavior of their own here (REDACT
    applies to output that doesn't exist yet at this point, and RE_ROUTE's
    approval wait isn't wired in), so all three currently mean "don't run
    this." Same design note as mizara.openai_agents.
    """

    def _run(request: Any, handler: Any) -> Any:
        tool_call = request.tool_call
        arguments = tool_call.get("args") or {}

        result = client.authorize(
            actor=Actor(id=actor_id, type="autonomous_agent", framework="langchain"),
            action=Action(name=tool_call["name"]),
            resource=Resource(
                type=resource_type or tool_call["name"],
                id=tool_call["id"],
                attributes=arguments if isinstance(arguments, dict) else {},
            ),
        )

        if result.status == "ALLOW":
            return handler(request)

        message = result.enforcement.user_facing_error or f"Blocked by Mizara policy ({result.status})."
        return ToolMessage(
            content=message,
            name=tool_call["name"],
            tool_call_id=tool_call["id"],
            status="error",
        )

    return wrap_tool_call(_run, name="mizara_authorize")
