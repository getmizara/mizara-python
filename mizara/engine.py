from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .evaluator import evaluate_condition
from .types import AuthorizationStatus, AuthorizeInput, Policy, PolicyRule

_SEVERITY: dict[AuthorizationStatus, int] = {
    "DENY": 3,
    "RE_ROUTE": 2,
    "REDACT": 1,
    "ALLOW": 0,
}


@dataclass
class RuleMatch:
    rule: PolicyRule
    status: AuthorizationStatus


def resolve_rule(input_data: AuthorizeInput, policy: Policy) -> Optional[RuleMatch]:
    """
    Evaluates every rule matching the action and returns the most
    restrictive outcome. Ties keep the earlier rule. Fail closed -
    callers treat None as DENY.
    """
    scope = {
        "actor": {
            "id": input_data.actor.id,
            "type": input_data.actor.type,
            "framework": input_data.actor.framework,
        },
        "action": {
            "name": input_data.action.name,
            "risk_profile": input_data.action.risk_profile,
        },
        "resource": {
            "type": input_data.resource.type,
            "id": input_data.resource.id,
            "attributes": input_data.resource.attributes or {},
        },
        "context": input_data.context or {},
    }

    best: Optional[RuleMatch] = None

    for rule in policy.rules:
        matches = rule.target_action == "any" or rule.target_action == input_data.action.name
        if not matches:
            continue
        condition_met = evaluate_condition(rule.condition, scope)
        status = rule.effect if condition_met else rule.fallback_effect

        if best is None or _SEVERITY[status] > _SEVERITY[best.status]:
            best = RuleMatch(rule=rule, status=status)

    return best
