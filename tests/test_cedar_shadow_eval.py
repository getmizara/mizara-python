from mizara.cedar_compiler import compile_condition_to_cedar
from mizara.cedar_shadow_eval import run_shadow_comparison
from mizara.engine import resolve_rule
from mizara.types import Action, Actor, AuthorizeInput, Policy, PolicyRule, Resource


def shadow_agrees(policy: Policy, input_data: AuthorizeInput) -> bool:
    match = resolve_rule(input_data, policy)
    status = match.status if match else "DENY"
    shadow = run_shadow_comparison(policy, input_data, status)
    return (not shadow.ran) or shadow.agreed is True


def test_compiles_numeric_threshold_comparison():
    compiled = compile_condition_to_cedar("resource.attributes.amount <= 100.00")
    assert compiled is not None
    assert "resource.attributes.amount" in compiled


def test_whole_number_decimal_compiles_to_bare_cedar_integer():
    compiled = compile_condition_to_cedar("resource.attributes.amount <= 100.00")
    assert compiled is not None
    assert "<= 100)" in compiled
    assert "100.0" not in compiled


def test_fractional_literal_is_unsupported():
    assert compile_condition_to_cedar("resource.attributes.amount <= 50.25") is None


def test_compiles_compound_and():
    compiled = compile_condition_to_cedar('context.amount <= 100 && resource.type == "order"')
    assert compiled is not None and "&&" in compiled


def test_compiles_contains():
    compiled = compile_condition_to_cedar('context.tags.contains("vip")')
    assert compiled is not None and ".contains(" in compiled


def test_division_is_unsupported():
    assert compile_condition_to_cedar("context.amount / 2 <= 100") is None


def test_invalid_syntax_returns_none():
    assert compile_condition_to_cedar("this is not valid && &&") is None


_BASIC_POLICY = Policy(
    policy_id="test",
    client_id="test",
    rules=[
        PolicyRule(
            id="rule_example",
            target_action="execute_action",
            condition="resource.attributes.amount <= 100.00",
            effect="ALLOW",
            fallback_effect="DENY",
        )
    ],
)


def test_shadow_agrees_when_condition_passes():
    input_data = AuthorizeInput(
        actor=Actor(id="a1", type="agent"),
        action=Action(name="execute_action"),
        resource=Resource(type="order", id="r1", attributes={"amount": 50}),
    )
    assert shadow_agrees(_BASIC_POLICY, input_data)


def test_shadow_agrees_when_condition_fails():
    input_data = AuthorizeInput(
        actor=Actor(id="a1", type="agent"),
        action=Action(name="execute_action"),
        resource=Resource(type="order", id="r1", attributes={"amount": 150}),
    )
    assert shadow_agrees(_BASIC_POLICY, input_data)


def test_shadow_agrees_when_field_is_entirely_absent():
    input_data = AuthorizeInput(
        actor=Actor(id="a1", type="agent"),
        action=Action(name="execute_action"),
        resource=Resource(type="order", id="r1"),
    )
    assert shadow_agrees(_BASIC_POLICY, input_data)


def test_shadow_agrees_on_deny_overriding_allow_severity_resolution():
    policy = Policy(
        policy_id="test",
        client_id="test",
        rules=[
            PolicyRule(id="allow_small", target_action="x", condition="context.amount <= 500", effect="ALLOW", fallback_effect="DENY"),
            PolicyRule(id="deny_flagged", target_action="x", condition="context.flagged == true", effect="DENY", fallback_effect="ALLOW"),
        ],
    )
    flagged = AuthorizeInput(
        actor=Actor(id="a1", type="agent"), action=Action(name="x"),
        resource=Resource(type="order", id="r1"), context={"amount": 100, "flagged": True},
    )
    not_flagged = AuthorizeInput(
        actor=Actor(id="a1", type="agent"), action=Action(name="x"),
        resource=Resource(type="order", id="r1"), context={"amount": 100, "flagged": False},
    )
    assert shadow_agrees(policy, flagged)
    assert shadow_agrees(policy, not_flagged)


def test_shadow_skips_rule_with_uncompilable_condition_instead_of_miscomparing():
    policy = Policy(
        policy_id="test", client_id="test",
        rules=[PolicyRule(id="r1", target_action="any", condition="context.amount / 2 <= 100", effect="ALLOW", fallback_effect="DENY")],
    )
    input_data = AuthorizeInput(
        actor=Actor(id="a1", type="agent"), action=Action(name="x"),
        resource=Resource(type="order", id="r1"), context={"amount": 100},
    )
    match = resolve_rule(input_data, policy)
    shadow = run_shadow_comparison(policy, input_data, match.status if match else "DENY")
    assert shadow.ran is False
    assert shadow.skipped_rules == [{"rule_id": "r1", "reason": "condition not expressible in Cedar"}]
