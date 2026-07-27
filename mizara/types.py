from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal, Optional

AuthorizationStatus = Literal["ALLOW", "DENY", "REDACT", "RE_ROUTE"]


@dataclass
class Actor:
    id: str
    type: str
    framework: Optional[str] = None


@dataclass
class Action:
    name: str
    risk_profile: Optional[str] = None


@dataclass
class Resource:
    type: str
    id: str
    attributes: Optional[dict[str, Any]] = None


@dataclass
class AuthorizeInput:
    actor: Actor
    action: Action
    resource: Resource
    context: Optional[dict[str, Any]] = None


@dataclass
class PolicyRule:
    id: str
    target_action: str
    condition: str
    effect: AuthorizationStatus
    fallback_effect: AuthorizationStatus
    remediation_message: Optional[str] = None


@dataclass
class Policy:
    policy_id: str
    client_id: str
    rules: list[PolicyRule]
    # Numeric version of this rule set. None for policies loaded from a
    # bare local JSON file with no version history behind them.
    version: Optional[int] = None


@dataclass
class CryptographicReceipt:
    id: str
    hash: str
    signature: str
    # Present on Ed25519-signed receipts; absent on legacy HMAC ones, which
    # remain valid historical records but aren't independently verifiable
    # without the shared secret that produced them.
    algorithm: Optional[str] = None
    public_key: Optional[str] = None


@dataclass
class EvaluationMetadata:
    triggered_rule_id: Optional[str]
    policy_bundle_version: str
    execution_time_ms: float
    # The exact rule-set version active at decision time, so a receipt can
    # be checked against the policy as it existed then, not as it exists
    # now. None when the policy has no version (e.g. local bare JSON file).
    policy_version: Optional[int] = None


@dataclass
class Enforcement:
    action_halted: bool
    user_facing_error: Optional[str]


@dataclass
class AuthorizeResult:
    status: AuthorizationStatus
    evaluation_metadata: EvaluationMetadata
    enforcement: Enforcement
    cryptographic_receipt: CryptographicReceipt
