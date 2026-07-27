import pytest
from mizara import create_mizara_client
from mizara.types import Policy, PolicyRule

TEST_POLICY = Policy(
    policy_id="pol_test_v1",
    client_id="test_client",
    rules=[
        PolicyRule(
            id="rule_max_payout_limit",
            target_action="execute_payout",
            condition="resource.attributes.amount <= 50.00",
            effect="ALLOW",
            fallback_effect="DENY",
            remediation_message="Transaction value exceeds maximum unapproved client threshold of $50.00.",
        )
    ],
)


def test_denies_75_against_50_policy():
    mizara = create_mizara_client(policy=TEST_POLICY)
    result = mizara.authorize(
        actor={"id": "agent_1", "type": "autonomous_agent"},
        action={"name": "execute_payout"},
        resource={"type": "monetary_transaction", "id": "tx_1", "attributes": {"amount": 75}},
    )
    assert result.status == "DENY"
    assert result.evaluation_metadata.triggered_rule_id == "rule_max_payout_limit"
    assert result.enforcement.action_halted is True
    assert "exceeds maximum" in (result.enforcement.user_facing_error or "")


def test_allows_25_against_50_policy():
    mizara = create_mizara_client(policy=TEST_POLICY)
    result = mizara.authorize(
        actor={"id": "agent_1", "type": "autonomous_agent"},
        action={"name": "execute_payout"},
        resource={"type": "monetary_transaction", "id": "tx_2", "attributes": {"amount": 25}},
    )
    assert result.status == "ALLOW"
    assert result.enforcement.action_halted is False
    assert result.enforcement.user_facing_error is None


def test_fails_closed_when_no_rule_matches():
    mizara = create_mizara_client(policy=TEST_POLICY)
    result = mizara.authorize(
        actor={"id": "agent_1", "type": "autonomous_agent"},
        action={"name": "delete_database"},
        resource={"type": "monetary_transaction", "id": "tx_3", "attributes": {}},
    )
    assert result.status == "DENY"
    assert result.evaluation_metadata.triggered_rule_id is None


def test_receipt_is_unique_per_decision():
    mizara = create_mizara_client(policy=TEST_POLICY)
    r1 = mizara.authorize(
        actor={"id": "agent_1", "type": "autonomous_agent"},
        action={"name": "execute_payout"},
        resource={"type": "monetary_transaction", "id": "tx_4", "attributes": {"amount": 10}},
    )
    r2 = mizara.authorize(
        actor={"id": "agent_1", "type": "autonomous_agent"},
        action={"name": "execute_payout"},
        resource={"type": "monetary_transaction", "id": "tx_5", "attributes": {"amount": 10}},
    )
    assert r1.cryptographic_receipt.id != r2.cryptographic_receipt.id  # unique ids
    assert r1.cryptographic_receipt.hash != r2.cryptographic_receipt.hash  # different resource ids → different hash
    assert r1.cryptographic_receipt.signature


# The exact example policy from the V1 MVP spec: a payout-limit rule
# targeting execute_payout, and a regional data-isolation rule targeting
# "any". Both can match the same execute_payout request.
MULTI_RULE_POLICY = Policy(
    policy_id="pol_payout_v1",
    client_id="acme_corp",
    rules=[
        PolicyRule(
            id="rule_max_payout_limit",
            target_action="execute_payout",
            condition="resource.attributes.amount <= 50.00",
            effect="ALLOW",
            fallback_effect="DENY",
            remediation_message="Transaction value exceeds maximum unapproved client threshold of $50.00.",
        ),
        PolicyRule(
            id="rule_regional_data_isolation",
            target_action="any",
            condition="context.target_jurisdiction == 'EU' && context.data_classification.contains('PII')",
            effect="ALLOW",
            fallback_effect="REDACT",
            remediation_message="Sensitive European personal profiles must be dynamically masked before transport.",
        ),
    ],
)


def test_combines_both_matching_rules_instead_of_only_firing_the_first():
    mizara = create_mizara_client(policy=MULTI_RULE_POLICY)
    # Within the $50 limit (rule 1 alone would ALLOW), but NOT EU+PII, so
    # rule 2's fallback (REDACT) also applies. Most restrictive must win.
    result = mizara.authorize(
        actor={"id": "agent_1", "type": "autonomous_agent"},
        action={"name": "execute_payout"},
        resource={"type": "monetary_transaction", "id": "tx_1", "attributes": {"amount": 25, "currency": "USD"}},
        context={"target_jurisdiction": "US", "data_classification": ["PII"]},
    )
    assert result.status == "REDACT"
    assert result.evaluation_metadata.triggered_rule_id == "rule_regional_data_isolation"


def test_deny_overrides_allow_regardless_of_rule_order():
    mizara = create_mizara_client(policy=MULTI_RULE_POLICY)
    # Over the $50 limit -> rule 1 DENYs. Also EU+PII -> rule 2 ALLOWs
    # (condition true). DENY must still win.
    result = mizara.authorize(
        actor={"id": "agent_1", "type": "autonomous_agent"},
        action={"name": "execute_payout"},
        resource={"type": "monetary_transaction", "id": "tx_2", "attributes": {"amount": 75, "currency": "USD"}},
        context={"target_jurisdiction": "EU", "data_classification": ["PII"]},
    )
    assert result.status == "DENY"
    assert result.evaluation_metadata.triggered_rule_id == "rule_max_payout_limit"


def test_tie_on_severity_is_deterministic_earlier_rule_wins():
    tie_policy = Policy(
        policy_id="pol_tie_v1",
        client_id="test_client",
        rules=[
            PolicyRule(
                id="rule_a_deny",
                target_action="any",
                condition="resource.attributes.amount > 1000000",
                effect="ALLOW",
                fallback_effect="DENY",
            ),
            PolicyRule(
                id="rule_b_deny",
                target_action="any",
                condition="resource.attributes.amount > 1000000",
                effect="ALLOW",
                fallback_effect="DENY",
            ),
        ],
    )
    mizara = create_mizara_client(policy=tie_policy)
    result = mizara.authorize(
        actor={"id": "agent_1", "type": "autonomous_agent"},
        action={"name": "anything"},
        resource={"type": "monetary_transaction", "id": "tx_3", "attributes": {"amount": 10}},
    )
    assert result.status == "DENY"
    assert result.evaluation_metadata.triggered_rule_id == "rule_a_deny"
