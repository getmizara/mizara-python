"""
Mizara + OpenAI Agents SDK integration example

Shows how to add mizara.authorize() as a function tool so the agent
evaluates it before executing any consequential action.

Requires: OPENAI_API_KEY environment variable
Run:      python examples/openai-agents/demo.py
"""

from __future__ import annotations

import json
from pathlib import Path

from agents import Agent, function_tool
from mizara import create_mizara_client

_mizara = create_mizara_client(
    policy_path=str(Path(__file__).parent / "policy.json")
)


@function_tool
def mizara_authorize(
    actor_id: str,
    action_name: str,
    resource_type: str,
    resource_id: str,
    amount: float | None = None,
) -> str:
    """
    Evaluate whether an agent action should proceed under the active policy.
    Call this before executing any consequential action such as a payment,
    data write, or infrastructure change. Returns ALLOW, DENY, REDACT, or
    RE_ROUTE with a signed receipt.

    Args:
        actor_id: Unique ID of the agent making the request.
        action_name: Name of the action (e.g. approve_payment, transmit_data).
        resource_type: Type of resource being acted on (e.g. invoice_payment).
        resource_id: Unique ID of the specific resource.
        amount: Monetary amount if applicable.
    """
    attributes = {}
    if amount is not None:
        attributes["amount"] = amount

    result = _mizara.authorize(
        actor={"id": actor_id, "type": "autonomous_agent", "framework": "openai-agents"},
        action={"name": action_name, "risk_profile": "high_irreversible"},
        resource={"type": resource_type, "id": resource_id, "attributes": attributes},
        context={"client_id": "demo_customer"},
    )

    return json.dumps({
        "status": result.status,
        "rule": result.evaluation_metadata.triggered_rule_id,
        "receipt": result.cryptographic_receipt.id,
        "blocked": result.enforcement.action_halted,
        "reason": result.enforcement.user_facing_error,
    })


@function_tool
def approve_payment(invoice_id: str, amount: float, currency: str = "USD") -> str:
    """
    Approve an invoice payment. Only call this after mizara_authorize has
    returned ALLOW for approve_payment.

    Args:
        invoice_id: The invoice to pay.
        amount: The payment amount.
        currency: Currency code (default USD).
    """
    return json.dumps({
        "success": True,
        "payment_id": f"pay_{hash(invoice_id) % 100000:05d}",
        "amount": amount,
        "currency": currency,
    })


agent = Agent(
    name="finance-agent",
    instructions=(
        "You are a finance operations agent. "
        "Before approving any payment, you MUST call mizara_authorize first. "
        "If it returns DENY, explain the policy limit and do not proceed. "
        "If it returns ALLOW, proceed with approve_payment."
    ),
    tools=[mizara_authorize, approve_payment],
)
