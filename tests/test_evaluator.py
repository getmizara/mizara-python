from mizara.evaluator import evaluate_condition

BASE_SCOPE = {
    "actor": {"id": "a1", "type": "autonomous_agent"},
    "action": {"name": "execute_payout"},
    "resource": {"type": "monetary_transaction", "id": "tx_1", "attributes": {"amount": 75}},
    "context": {"target_jurisdiction": "EU", "data_classification": ["PII", "PCI"]},
}


def test_numeric_lte_false():
    assert evaluate_condition("resource.attributes.amount <= 50.00", BASE_SCOPE) is False


def test_numeric_lte_true():
    scope = {**BASE_SCOPE, "resource": {**BASE_SCOPE["resource"], "attributes": {"amount": 25}}}
    assert evaluate_condition("resource.attributes.amount <= 50.00", scope) is True


def test_numeric_gt():
    assert evaluate_condition("resource.attributes.amount > 50.00", BASE_SCOPE) is True


def test_string_equality_true():
    assert evaluate_condition("context.target_jurisdiction == 'EU'", BASE_SCOPE) is True


def test_string_equality_false():
    assert evaluate_condition("context.target_jurisdiction == 'US'", BASE_SCOPE) is False


def test_array_contains_true():
    assert evaluate_condition("context.data_classification.contains('PII')", BASE_SCOPE) is True


def test_array_contains_false():
    assert evaluate_condition("context.data_classification.contains('PHI')", BASE_SCOPE) is False


def test_compound_and():
    expr = "context.target_jurisdiction == 'EU' && context.data_classification.contains('PII')"
    assert evaluate_condition(expr, BASE_SCOPE) is True


def test_compound_and_short_circuit():
    expr = "context.target_jurisdiction == 'US' && context.data_classification.contains('PII')"
    assert evaluate_condition(expr, BASE_SCOPE) is False


def test_arithmetic_addition():
    assert evaluate_condition("resource.attributes.amount + 5 > 79", BASE_SCOPE) is True
    assert evaluate_condition("resource.attributes.amount + 5 > 81", BASE_SCOPE) is False


def test_arithmetic_subtraction():
    assert evaluate_condition("resource.attributes.amount - 25 == 50", BASE_SCOPE) is True


def test_missing_field_ordering_comparison_is_false_not_a_crash():
    scope = {**BASE_SCOPE, "resource": {"type": "monetary_transaction", "id": "tx_1"}}
    assert evaluate_condition("resource.attributes.amount <= 50.00", scope) is False
    assert evaluate_condition("resource.attributes.amount >= 50.00", scope) is False
    assert evaluate_condition("resource.attributes.amount < 50.00", scope) is False
    assert evaluate_condition("resource.attributes.amount > 50.00", scope) is False


def test_arithmetic_cumulative_session_pattern():
    scope = {
        **BASE_SCOPE,
        "context": {"session_total": 350, "target_jurisdiction": "EU", "data_classification": ["PII"]},
    }
    # 350 + 75 = 425 > 400 → false (over limit)
    assert evaluate_condition("context.session_total + resource.attributes.amount <= 400", scope) is False

    scope2 = {
        **BASE_SCOPE,
        "context": {"session_total": 300, "target_jurisdiction": "EU", "data_classification": ["PII"]},
    }
    # 300 + 75 = 375 <= 500 → true (under limit)
    assert evaluate_condition("context.session_total + resource.attributes.amount <= 500", scope2) is True
