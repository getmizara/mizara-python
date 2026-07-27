from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Callable, Optional

from .engine import resolve_rule
from .receipts import create_receipt
from .resilient_client import ResilientHostedClient
from .types import (
    Action,
    Actor,
    AuthorizeInput,
    AuthorizeResult,
    Enforcement,
    EvaluationMetadata,
    Policy,
    PolicyRule,
    Resource,
)

_HOSTED_URL = "https://mizara-services.vercel.app"


def _load_policy(path: str) -> Policy:
    data = json.loads(Path(path).read_text())
    return Policy(
        policy_id=data["policy_id"],
        client_id=data["client_id"],
        rules=[
            PolicyRule(
                id=r["id"],
                target_action=r["target_action"],
                condition=r["condition"],
                effect=r["effect"],
                fallback_effect=r["fallback_effect"],
                remediation_message=r.get("remediation_message"),
            )
            for r in data["rules"]
        ],
    )


class MizaraClient:
    """Local evaluation client."""

    def __init__(self, policy: Policy) -> None:
        self._policy = policy

    def authorize(
        self,
        actor: Actor | dict[str, Any],
        action: Action | dict[str, Any],
        resource: Resource | dict[str, Any],
        context: Optional[dict[str, Any]] = None,
    ) -> AuthorizeResult:
        if isinstance(actor, dict):
            actor = Actor(**actor)
        if isinstance(action, dict):
            action = Action(**action)
        if isinstance(resource, dict):
            resource = Resource(**resource)

        input_data = AuthorizeInput(
            actor=actor, action=action, resource=resource, context=context
        )

        start = time.perf_counter()
        match = resolve_rule(input_data, self._policy)
        elapsed_ms = round((time.perf_counter() - start) * 1000, 3)

        status = match.status if match else "DENY"
        receipt = create_receipt(
            input_data=input_data,
            status=status,
            triggered_rule_id=match.rule.id if match else None,
        )

        return AuthorizeResult(
            status=status,
            evaluation_metadata=EvaluationMetadata(
                triggered_rule_id=match.rule.id if match else None,
                policy_bundle_version=self._policy.policy_id,
                policy_version=self._policy.version,
                execution_time_ms=elapsed_ms,
            ),
            enforcement=Enforcement(
                action_halted=status == "DENY",
                user_facing_error=(
                    match.rule.remediation_message if match and status == "DENY" else None
                ),
            ),
            cryptographic_receipt=receipt,
        )

    def close(self) -> None:
        """No background work to stop in local mode. Safe to always call."""


def create_mizara_client(
    policy_path: Optional[str] = None,
    policy: Optional[Policy] = None,
    api_key: Optional[str] = None,
    client_id: Optional[str] = None,
    base_url: Optional[str] = None,
    sync_interval_s: float = 10.0,
    on_sync_error: Optional[Callable[[Exception], None]] = None,
    receipt_log_path: Optional[str] = None,
) -> MizaraClient | ResilientHostedClient:
    """
    Create a Mizara client.

    Hosted mode (requires API key from mizara.ai/signup) evaluates
    locally against a policy snapshot refreshed in the background every
    sync_interval_s seconds, so a Mizara outage doesn't fail every
    authorize() call -- it keeps using the last policy successfully
    fetched. Receipts are generated locally and flushed to the hosted API
    asynchronously; pass receipt_log_path to back that queue with a local
    file so a process crash between a decision and its flush doesn't lose
    the receipt.

        client = create_mizara_client(api_key="mizara_live_...", client_id="acme_corp")

    Local mode:
        client = create_mizara_client(policy_path="./policy.json")
    """
    if api_key is not None:
        if not client_id:
            raise ValueError("create_mizara_client with api_key requires client_id")
        return ResilientHostedClient(
            api_key=api_key,
            client_id=client_id,
            base_url=base_url or _HOSTED_URL,
            sync_interval_s=sync_interval_s,
            on_sync_error=on_sync_error,
            receipt_log_path=receipt_log_path,
        )

    if policy is None:
        if policy_path is None:
            raise ValueError("create_mizara_client requires api_key or policy_path")
        policy = _load_policy(policy_path)
    return MizaraClient(policy=policy)
