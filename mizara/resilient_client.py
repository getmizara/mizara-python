from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.request
from dataclasses import asdict
from typing import Any, Callable, Optional

from .engine import resolve_rule
from .receipt_log import QueuedReceipt, ReceiptLog
from .receipts import create_receipt
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

_DEFAULT_SYNC_INTERVAL_S = 10.0
_SYNC_FAILURE_WARNING_THRESHOLD = 3
_DEFAULT_APPROVAL_POLL_S = 3.0
_DEFAULT_APPROVAL_TIMEOUT_S = 25 * 60.0


def _request(
    url: str,
    api_key: str,
    method: str = "GET",
    body: Optional[dict[str, Any]] = None,
    extra_headers: Optional[dict[str, str]] = None,
):
    headers = {"Authorization": f"Bearer {api_key}"}
    if extra_headers:
        headers.update(extra_headers)
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    return urllib.request.urlopen(req, timeout=10)


class ResilientHostedClient:
    """
    Hosted mode, resilient by default: policy is fetched once and then
    refreshed in the background on an interval, so evaluation happens
    locally, in-process, the same as local mode. A Mizara outage degrades
    to "keep using the last policy successfully fetched," not "every
    authorize() call fails." Receipts are generated locally and flushed
    to the hosted API asynchronously, backed by a disk write-ahead log so
    a process crash between the decision and the flush doesn't lose one.

    Construction blocks briefly (bounded by a 10s network timeout) for the
    first policy sync to settle, since this client has no async equivalent
    to return immediately and resolve later. Every subsequent sync happens
    on a background thread and never blocks authorize().
    """

    def __init__(
        self,
        api_key: str,
        client_id: str,
        base_url: str,
        sync_interval_s: float = _DEFAULT_SYNC_INTERVAL_S,
        on_sync_error: Optional[Callable[[Exception], None]] = None,
        receipt_log_path: Optional[str] = None,
    ) -> None:
        self._api_key = api_key
        self._client_id = client_id
        self._base_url = base_url
        self._sync_interval_s = sync_interval_s
        self._on_sync_error = on_sync_error

        self._lock = threading.Lock()
        self._policy: Optional[Policy] = None
        self._policy_version: Optional[str] = None
        self._consecutive_sync_failures = 0

        self._receipt_log = ReceiptLog(receipt_log_path) if receipt_log_path else None
        self._stopped = threading.Event()

        self._retry_sweep()
        self._sync_policy()

        self._sync_thread = threading.Thread(target=self._sync_loop, daemon=True)
        self._sync_thread.start()

        self._retry_thread: Optional[threading.Thread] = None
        if self._receipt_log:
            self._retry_thread = threading.Thread(target=self._retry_loop, daemon=True)
            self._retry_thread.start()

    def _sync_loop(self) -> None:
        while not self._stopped.wait(self._sync_interval_s):
            self._sync_policy()

    def _retry_loop(self) -> None:
        while not self._stopped.wait(self._sync_interval_s):
            self._retry_sweep()

    def _sync_policy(self) -> None:
        try:
            headers = {}
            if self._policy_version:
                headers["If-None-Match"] = self._policy_version

            resp = _request(f"{self._base_url}/api/v1/policies/{self._client_id}", self._api_key, extra_headers=headers)
            body = json.loads(resp.read().decode("utf-8"))
            policy = Policy(
                policy_id=body["policy_id"],
                client_id=body["client_id"],
                rules=[
                    PolicyRule(
                        id=r["id"],
                        target_action=r["target_action"],
                        condition=r["condition"],
                        effect=r["effect"],
                        fallback_effect=r["fallback_effect"],
                        remediation_message=r.get("remediation_message"),
                    )
                    for r in body["rules"]
                ],
                version=body["version"],
            )
            with self._lock:
                self._policy = policy
                self._policy_version = str(body["version"])
                self._consecutive_sync_failures = 0
        except urllib.error.HTTPError as e:
            if e.code == 304:
                with self._lock:
                    self._consecutive_sync_failures = 0
                return
            self._record_sync_failure(e)
        except Exception as e:  # noqa: BLE001 - a background loop must never raise
            self._record_sync_failure(e)

    def _record_sync_failure(self, err: Exception) -> None:
        with self._lock:
            self._consecutive_sync_failures += 1
            count = self._consecutive_sync_failures
        if count == _SYNC_FAILURE_WARNING_THRESHOLD and self._on_sync_error:
            self._on_sync_error(err)

    def _fetch_session_total(self, session_id: str) -> Optional[float]:
        try:
            resp = _request(f"{self._base_url}/api/v1/sessions/{session_id}", self._api_key)
            body = json.loads(resp.read().decode("utf-8"))
            return float(body["total"])
        except Exception:
            return None

    def _increment_session_total(self, session_id: str, amount: float) -> None:
        try:
            _request(f"{self._base_url}/api/v1/sessions/{session_id}", self._api_key, method="POST", body={"amount": amount})
        except Exception:
            pass

    def _flush_receipt(self, receipt_id: str, payload: dict[str, Any]) -> None:
        try:
            resp = _request(f"{self._base_url}/api/v1/receipts", self._api_key, method="POST", body=payload)
            if 200 <= resp.status < 300 and self._receipt_log:
                self._receipt_log.append_ack(receipt_id)
        except Exception:
            pass  # stays unacked; retried on the next sweep or process start

    def _retry_sweep(self) -> None:
        if not self._receipt_log:
            return
        for queued in self._receipt_log.load_unacked():
            threading.Thread(target=self._flush_receipt, args=(queued.receipt_id, queued.payload), daemon=True).start()

    # The input is included alongside the result, matching what the
    # synchronous hosted endpoint stores, since a receipt with no record
    # of what was being decided can't support a human approval review.
    def _queue_and_flush(self, policy_bundle_version: str, input_data: AuthorizeInput, result: AuthorizeResult) -> None:
        payload = {
            "id": result.cryptographic_receipt.id,
            "policy_id": policy_bundle_version,
            "status": result.status,
            "triggered_rule_id": result.evaluation_metadata.triggered_rule_id,
            "hash": result.cryptographic_receipt.hash,
            "signature": result.cryptographic_receipt.signature,
            "payload": {
                "input": {
                    "actor": asdict(input_data.actor),
                    "action": asdict(input_data.action),
                    "resource": asdict(input_data.resource),
                    "context": input_data.context or {},
                },
                "result": {
                    "status": result.status,
                    "evaluation_metadata": asdict(result.evaluation_metadata),
                    "enforcement": asdict(result.enforcement),
                    "cryptographic_receipt": asdict(result.cryptographic_receipt),
                },
            },
        }
        if self._receipt_log:
            self._receipt_log.append_pending(QueuedReceipt(receipt_id=result.cryptographic_receipt.id, payload=payload))
        threading.Thread(target=self._flush_receipt, args=(result.cryptographic_receipt.id, payload), daemon=True).start()

    def _deny_closed(self, input_data: AuthorizeInput, message: str, policy_bundle_version: str) -> AuthorizeResult:
        receipt = create_receipt(input_data, "DENY", None)
        with self._lock:
            current_policy_version = self._policy.version if self._policy else None
        result = AuthorizeResult(
            status="DENY",
            evaluation_metadata=EvaluationMetadata(
                triggered_rule_id=None,
                policy_bundle_version=policy_bundle_version,
                policy_version=current_policy_version,
                execution_time_ms=0.0,
            ),
            enforcement=Enforcement(action_halted=True, user_facing_error=message),
            cryptographic_receipt=receipt,
        )
        self._queue_and_flush(policy_bundle_version, input_data, result)
        return result

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

        merged_context: dict[str, Any] = {"client_id": self._client_id, **(context or {})}
        input_data = AuthorizeInput(actor=actor, action=action, resource=resource, context=merged_context)

        with self._lock:
            policy = self._policy

        if policy is None:
            return self._deny_closed(input_data, "Mizara policy has not been loaded yet.", "unsynced")

        session_id = merged_context.get("session_id")
        session_id = session_id if isinstance(session_id, str) else None
        session_total: Optional[float] = None

        if session_id:
            session_total = self._fetch_session_total(session_id)
            if session_total is None:
                return self._deny_closed(
                    input_data,
                    "Session-gated policy could not be evaluated: session store unreachable.",
                    policy.policy_id,
                )
            merged_context = {**merged_context, "session_total": session_total}
            input_data = AuthorizeInput(actor=actor, action=action, resource=resource, context=merged_context)

        start = time.perf_counter()
        match = resolve_rule(input_data, policy)
        elapsed_ms = round((time.perf_counter() - start) * 1000, 3)

        status = match.status if match else "DENY"
        receipt = create_receipt(input_data, status, match.rule.id if match else None)

        result = AuthorizeResult(
            status=status,
            evaluation_metadata=EvaluationMetadata(
                triggered_rule_id=match.rule.id if match else None,
                policy_bundle_version=policy.policy_id,
                policy_version=policy.version,
                execution_time_ms=elapsed_ms,
            ),
            enforcement=Enforcement(
                action_halted=status == "DENY",
                user_facing_error=(match.rule.remediation_message if match and status == "DENY" else None),
            ),
            cryptographic_receipt=receipt,
        )

        if session_id and status == "ALLOW":
            amount = resource.attributes.get("amount") if resource.attributes else None
            if isinstance(amount, (int, float)):
                threading.Thread(target=self._increment_session_total, args=(session_id, amount), daemon=True).start()

        self._queue_and_flush(policy.policy_id, input_data, result)

        return result

    def wait_for_approval(
        self,
        receipt_id: str,
        poll_interval_s: float = _DEFAULT_APPROVAL_POLL_S,
        timeout_s: float = _DEFAULT_APPROVAL_TIMEOUT_S,
    ) -> str:
        """
        Blocks until a RE_ROUTE decision's receipt is approved or denied,
        or the timeout elapses. Returns "APPROVED", "DENIED", or "TIMEOUT".

        Only meaningful in hosted mode: local mode has no server to hold
        pending approval state.
        """
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            try:
                resp = _request(f"{self._base_url}/api/v1/approvals/{receipt_id}", self._api_key)
                body = json.loads(resp.read().decode("utf-8"))
                status = body.get("status")
                if status in ("APPROVED", "DENIED"):
                    return status
            except Exception:
                pass  # transient network failure or not-yet-created: keep polling
            time.sleep(poll_interval_s)

        return "TIMEOUT"

    def close(self) -> None:
        self._stopped.set()
        if self._receipt_log:
            self._receipt_log.compact()
