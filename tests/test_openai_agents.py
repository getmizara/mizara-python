import json

import pytest

pytest.importorskip("agents")

from agents import Agent  # noqa: E402
from agents.tool_context import ToolContext  # noqa: E402
from agents.tool_guardrails import ToolInputGuardrailData  # noqa: E402

from mizara.openai_agents import mizara_guardrail  # noqa: E402
from mizara.sdk import MizaraClient  # noqa: E402
from mizara.types import Policy, PolicyRule  # noqa: E402

POLICY = Policy(
    policy_id="pol_openai_guardrail_test",
    client_id="test",
    rules=[
        PolicyRule(
            id="rule_block_prod_terminate",
            target_action="terminate_compute_instance",
            condition="resource.attributes.environment == 'production'",
            effect="DENY",
            fallback_effect="ALLOW",
            remediation_message="Terminating a production instance requires approval.",
        )
    ],
)


def _guardrail_data(tool_name: str, arguments: dict) -> ToolInputGuardrailData:
    agent = Agent(name="test-agent", instructions="test")
    context = ToolContext(
        context=None,
        tool_name=tool_name,
        tool_call_id="call_1",
        tool_arguments=json.dumps(arguments),
    )
    return ToolInputGuardrailData(context=context, agent=agent)


def test_allows_a_call_with_no_matching_rule():
    client = MizaraClient(policy=POLICY)
    guardrail = mizara_guardrail(client)

    data = _guardrail_data("terminate_compute_instance", {"environment": "staging"})
    output = guardrail.guardrail_function(data)

    assert output.behavior["type"] == "allow"
    assert output.output_info["status"] == "ALLOW"


def test_blocks_a_call_the_policy_denies():
    client = MizaraClient(policy=POLICY)
    guardrail = mizara_guardrail(client)

    data = _guardrail_data("terminate_compute_instance", {"environment": "production"})
    output = guardrail.guardrail_function(data)

    assert output.behavior["type"] == "reject_content"
    assert "approval" in output.behavior["message"]
    assert output.output_info["status"] == "DENY"
    assert output.output_info["rule_id"] == "rule_block_prod_terminate"
    assert output.output_info["receipt_id"]


def test_uncovered_action_defaults_to_deny():
    client = MizaraClient(policy=POLICY)
    guardrail = mizara_guardrail(client)

    data = _guardrail_data("send_marketing_broadcast", {"recipient_count": 50000})
    output = guardrail.guardrail_function(data)

    assert output.behavior["type"] == "reject_content"
    assert output.output_info["status"] == "DENY"
    assert output.output_info["rule_id"] is None
