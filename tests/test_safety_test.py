from mizara.safety_test import SCENARIOS, run_safety_test
from mizara.types import Policy, PolicyRule


def test_scenario_ids_are_unique():
    ids = [s.id for s in SCENARIOS]
    assert len(ids) == len(set(ids))


def test_uncovered_action_defaults_to_deny_without_a_triggered_rule():
    policy = Policy(policy_id="pol_empty", client_id="test", rules=[])
    results = run_safety_test(policy)

    assert len(results) == len(SCENARIOS)
    for result in results:
        assert result.status == "DENY"
        assert result.verdict == "DEFAULT-DENIED"
        assert result.triggered_rule_id is None


def test_explicit_matching_rule_is_reported_as_protected():
    policy = Policy(
        policy_id="pol_protected",
        client_id="test",
        rules=[
            PolicyRule(
                id="rule_block_prod_terminate",
                target_action="terminate_compute_instance",
                condition="resource.attributes.environment == 'production'",
                effect="DENY",
                fallback_effect="ALLOW",
            )
        ],
    )
    results = {r.scenario.id: r for r in run_safety_test(policy)}

    protected = results["production_infra_change"]
    assert protected.status == "DENY"
    assert protected.verdict == "PROTECTED"
    assert protected.triggered_rule_id == "rule_block_prod_terminate"


def test_rule_that_falls_through_to_allow_is_reported_as_fail():
    policy = Policy(
        policy_id="pol_gap",
        client_id="test",
        rules=[
            PolicyRule(
                id="rule_high_instance_count_only",
                target_action="provision_compute_cluster",
                condition="resource.attributes.instance_count > 999999",
                effect="DENY",
                fallback_effect="ALLOW",
            )
        ],
    )
    results = {r.scenario.id: r for r in run_safety_test(policy)}

    gap = results["large_scale_provisioning"]
    assert gap.status == "ALLOW"
    assert gap.verdict == "FAIL"
