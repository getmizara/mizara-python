"""
OpenAI Agents SDK integration. Requires the 'openai' extra:
    pip install mizara[openai]

Wraps a Mizara client as a tool_input_guardrail, so a policy decision runs
before the tool executes and can block it - unlike exposing authorize() as
a separate callable tool, the model can't skip this by just not calling it.
"""

from __future__ import annotations

import json
from typing import Any

try:
    from agents.tool_guardrails import (
        ToolGuardrailFunctionOutput,
        ToolInputGuardrail,
        ToolInputGuardrailData,
    )
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "mizara.openai_agents requires the 'openai' extra: pip install mizara[openai]"
    ) from exc

from .resilient_client import ResilientHostedClient
from .sdk import MizaraClient
from .types import Action, Actor, Resource


def mizara_guardrail(
    client: MizaraClient | ResilientHostedClient,
    *,
    actor_id: str = "openai_agent",
    resource_type: str | None = None,
) -> ToolInputGuardrail[Any]:
    """
    Builds a tool_input_guardrail backed by the given Mizara client.

    Pass it to any @function_tool via tool_input_guardrails=[...]. The tool's
    name becomes the action name Mizara evaluates against; the tool's raw
    arguments become the resource attributes. resource_type defaults to the
    tool name if not given.

    ALLOW lets the call through. DENY, REDACT, and RE_ROUTE all reject the
    call with the policy's remediation message - REDACT and RE_ROUTE don't
    have a meaningful input-stage behavior of their own here (REDACT applies
    to output that doesn't exist yet at this point, and RE_ROUTE's approval
    wait isn't wired in), so all three currently mean "don't run this."
    """

    def _run(data: ToolInputGuardrailData) -> ToolGuardrailFunctionOutput:
        try:
            arguments = json.loads(data.context.tool_arguments or "{}")
        except json.JSONDecodeError:
            arguments = {}

        result = client.authorize(
            actor=Actor(id=actor_id, type="autonomous_agent", framework="openai-agents"),
            action=Action(name=data.context.tool_name),
            resource=Resource(
                type=resource_type or data.context.tool_name,
                id=data.context.tool_call_id,
                attributes=arguments if isinstance(arguments, dict) else {},
            ),
        )

        info = {
            "status": result.status,
            "rule_id": result.evaluation_metadata.triggered_rule_id,
            "receipt_id": result.cryptographic_receipt.id,
        }

        if result.status == "ALLOW":
            return ToolGuardrailFunctionOutput.allow(output_info=info)

        message = result.enforcement.user_facing_error or f"Blocked by Mizara policy ({result.status})."
        return ToolGuardrailFunctionOutput.reject_content(message=message, output_info=info)

    return ToolInputGuardrail(guardrail_function=_run, name="mizara_authorize")
