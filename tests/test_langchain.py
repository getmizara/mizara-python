import pytest

pytest.importorskip("langchain")

from langchain_core.messages.tool import ToolCall  # noqa: E402
from langgraph.prebuilt.tool_node import ToolCallRequest  # noqa: E402

from mizara.langchain import mizara_middleware  # noqa: E402
from mizara.sdk import MizaraClient  # noqa: E402
from mizara.types import Policy, PolicyRule  # noqa: E402

POLICY = Policy(
    policy_id="pol_langchain_middleware_test",
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


def _request(tool_name: str, args: dict) -> ToolCallRequest:
    tool_call = ToolCall(type="tool_call", name=tool_name, args=args, id="call_1")
    return ToolCallRequest(tool_call=tool_call, tool=None, state=None, runtime=None)


def test_allows_a_call_with_no_matching_rule_and_invokes_the_handler():
    client = MizaraClient(policy=POLICY)
    middleware = mizara_middleware(client)

    calls = []

    def handler(request):
        calls.append(request)
        return "executed"

    result = middleware.wrap_tool_call(
        _request("terminate_compute_instance", {"environment": "staging"}), handler
    )

    assert result == "executed"
    assert len(calls) == 1


def test_blocks_a_call_the_policy_denies_without_invoking_the_handler():
    client = MizaraClient(policy=POLICY)
    middleware = mizara_middleware(client)

    def handler(request):
        raise AssertionError("handler should not be called when the policy denies")

    result = middleware.wrap_tool_call(
        _request("terminate_compute_instance", {"environment": "production"}), handler
    )

    assert result.status == "error"
    assert "approval" in result.content
    assert result.tool_call_id == "call_1"


def test_uncovered_action_defaults_to_deny():
    client = MizaraClient(policy=POLICY)
    middleware = mizara_middleware(client)

    def handler(request):
        raise AssertionError("handler should not be called for an uncovered action")

    result = middleware.wrap_tool_call(
        _request("send_marketing_broadcast", {"recipient_count": 50000}), handler
    )

    assert result.status == "error"
