"""
Runs a policy through Cedar alongside the real decision engine, purely
for comparison - never used to decide. See cedar_compiler.py for the
condition translation and decision_engine.py (resolve_rule) for the
function that actually decides.

cedarpy is an optional dependency (the `cedar` extra) since it's a
native compiled wheel, not something every mizara install should need.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from .cedar_compiler import compile_condition_to_cedar
from .types import Actor, AuthorizationStatus, AuthorizeInput, Policy, PolicyRule, Resource

try:
    import cedarpy
except ImportError as _import_error:  # pragma: no cover
    cedarpy = None
    _cedarpy_import_error = _import_error


@dataclass
class CedarCompilation:
    cedar_policy_text: str
    compiled_rule_ids: list[str]
    skipped_rules: list[dict[str, str]] = field(default_factory=list)


# Cedar is binary (permit/forbid); a rule's ALLOW branch compiles to
# permit, any other status to forbid, since forbid always overrides
# permit - matching Mizara's max-severity resolution. Both branches
# share one condition, so an uncompilable condition skips the rule.
def _compile_rule(rule: PolicyRule) -> tuple[Optional[list[str]], Optional[str]]:
    scope = (
        "action"
        if rule.target_action == "any"
        else f'action == Mizara::Action::"{rule.target_action}"'
    )
    condition = compile_condition_to_cedar(rule.condition)
    if condition is None:
        return None, "condition not expressible in Cedar"

    effect_kw = "permit" if rule.effect == "ALLOW" else "forbid"
    fallback_kw = "permit" if rule.fallback_effect == "ALLOW" else "forbid"

    return (
        [
            f"{effect_kw}(principal, {scope}, resource) when {{ {condition} }};",
            f"{fallback_kw}(principal, {scope}, resource) when {{ !({condition}) }};",
        ],
        None,
    )


def compile_policy_to_cedar(policy: Policy) -> CedarCompilation:
    compiled_rule_ids: list[str] = []
    skipped_rules: list[dict[str, str]] = []
    policies: list[str] = []

    for rule in policy.rules:
        rule_policies, skipped_reason = _compile_rule(rule)
        if rule_policies is None:
            skipped_rules.append({"rule_id": rule.id, "reason": skipped_reason or "unknown"})
        else:
            compiled_rule_ids.append(rule.id)
            policies.extend(rule_policies)

    return CedarCompilation(
        cedar_policy_text="\n".join(policies),
        compiled_rule_ids=compiled_rule_ids,
        skipped_rules=skipped_rules,
    )


def _entity_attrs(value: Actor | Resource) -> dict[str, Any]:
    attrs = dict(vars(value))
    attrs.pop("id", None)
    return {k: v for k, v in attrs.items() if v is not None}


@dataclass
class ShadowComparisonResult:
    ran: bool
    agreed: Optional[bool] = None
    cedar_decision: Optional[str] = None
    mizara_allowed: Optional[bool] = None
    cedar_errors: Optional[list[str]] = None
    skipped_rules: list[dict[str, str]] = field(default_factory=list)


def run_shadow_comparison(
    policy: Policy, input_data: AuthorizeInput, mizara_status: AuthorizationStatus
) -> ShadowComparisonResult:
    if cedarpy is None:
        raise ImportError(
            "run_shadow_comparison requires the 'cedar' extra: pip install mizara[cedar]"
        ) from _cedarpy_import_error

    compilation = compile_policy_to_cedar(policy)
    if not compilation.compiled_rule_ids:
        return ShadowComparisonResult(ran=False, skipped_rules=compilation.skipped_rules)

    principal_uid = {"type": "Mizara::Actor", "id": input_data.actor.id}
    resource_uid = {"type": "Mizara::Resource", "id": input_data.resource.id}

    try:
        result = cedarpy.is_authorized(
            {
                "principal": principal_uid,
                "action": {"type": "Mizara::Action", "id": input_data.action.name},
                "resource": resource_uid,
                "context": input_data.context or {},
            },
            compilation.cedar_policy_text,
            [
                {"uid": principal_uid, "attrs": _entity_attrs(input_data.actor), "parents": []},
                {"uid": resource_uid, "attrs": _entity_attrs(input_data.resource), "parents": []},
            ],
        )
    except Exception as err:  # pragma: no cover
        return ShadowComparisonResult(
            ran=True, cedar_errors=[str(err)], skipped_rules=compilation.skipped_rules
        )

    cedar_decision = "allow" if result.allowed else "deny"
    mizara_allowed = mizara_status == "ALLOW"
    errors = list(result.diagnostics.errors) if result.diagnostics.errors else None

    return ShadowComparisonResult(
        ran=True,
        agreed=(cedar_decision == "allow") == mizara_allowed,
        cedar_decision=cedar_decision,
        mizara_allowed=mizara_allowed,
        cedar_errors=errors,
        skipped_rules=compilation.skipped_rules,
    )
