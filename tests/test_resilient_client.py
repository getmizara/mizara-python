from __future__ import annotations

import json
import os
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from mizara import create_mizara_client

POLICY_RULES = [
    {
        "id": "rule_max_refund",
        "target_action": "execute_refund",
        "condition": "resource.attributes.amount <= 50.00",
        "effect": "ALLOW",
        "fallback_effect": "DENY",
        "remediation_message": "Over the limit.",
    }
]


class _MockState:
    def __init__(self) -> None:
        self.failing = False
        self.policy_version = 1
        self.received_receipts: list[dict] = []
        self.seen_receipt_ids: set[str] = set()
        self.session_total = 0.0
        self.approval_status: dict[str, str] = {}


def _make_handler(state: _MockState):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):  # silence test output
            pass

        def _send_json(self, status: int, body: dict) -> None:
            payload = json.dumps(body).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("ETag", str(state.policy_version))
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self):
            if state.failing:
                self.send_response(503)
                self.end_headers()
                return

            if self.path.startswith("/api/v1/policies/"):
                if self.headers.get("If-None-Match") == str(state.policy_version):
                    self.send_response(304)
                    self.send_header("ETag", str(state.policy_version))
                    self.end_headers()
                    return
                self._send_json(
                    200,
                    {
                        "policy_id": "pol_test_v1",
                        "client_id": "test_client",
                        "version": state.policy_version,
                        "rules": POLICY_RULES,
                    },
                )
                return

            if self.path.startswith("/api/v1/sessions/"):
                self._send_json(200, {"total": state.session_total})
                return

            if self.path.startswith("/api/v1/approvals/"):
                receipt_id = self.path[len("/api/v1/approvals/"):]
                status = state.approval_status.get(receipt_id)
                if status is None:
                    self.send_response(404)
                    self.end_headers()
                    return
                self._send_json(200, {"status": status})
                return

            self.send_response(404)
            self.end_headers()

        def do_POST(self):
            if state.failing:
                self.send_response(503)
                self.end_headers()
                return

            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length) or b"{}")

            if self.path == "/api/v1/receipts":
                if body["id"] not in state.seen_receipt_ids:
                    state.seen_receipt_ids.add(body["id"])
                    state.received_receipts.append(body)
                self._send_json(201, {"ok": True})
                return

            if self.path.startswith("/api/v1/sessions/"):
                state.session_total += body["amount"]
                self._send_json(200, {"ok": True})
                return

            self.send_response(404)
            self.end_headers()

    return Handler


@pytest.fixture
def mock_server():
    state = _MockState()
    server = HTTPServer(("127.0.0.1", 0), _make_handler(state))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{server.server_port}"
    yield state, base_url
    server.shutdown()
    server.server_close()


@pytest.fixture
def tmp_log_path():
    with tempfile.TemporaryDirectory() as d:
        yield os.path.join(d, "receipts.log")


def test_fails_closed_before_first_sync_ever_succeeds(mock_server):
    state, base_url = mock_server
    state.failing = True

    client = create_mizara_client(api_key="k", client_id="test_client", base_url=base_url, sync_interval_s=0.05)
    result = client.authorize(
        actor={"id": "a1", "type": "agent"},
        action={"name": "execute_refund"},
        resource={"type": "monetary_transaction", "id": "tx1", "attributes": {"amount": 25}},
    )
    client.close()

    assert result.status == "DENY"
    assert result.evaluation_metadata.policy_bundle_version == "unsynced"


def test_evaluates_locally_once_synced(mock_server):
    state, base_url = mock_server

    client = create_mizara_client(api_key="k", client_id="test_client", base_url=base_url, sync_interval_s=0.05)
    result = client.authorize(
        actor={"id": "a1", "type": "agent"},
        action={"name": "execute_refund"},
        resource={"type": "monetary_transaction", "id": "tx1", "attributes": {"amount": 25}},
    )
    client.close()

    assert result.status == "ALLOW"
    assert result.evaluation_metadata.policy_bundle_version == "pol_test_v1"
    assert result.evaluation_metadata.policy_version == 1


def test_keeps_using_last_known_good_policy_through_an_outage(mock_server):
    state, base_url = mock_server

    client = create_mizara_client(api_key="k", client_id="test_client", base_url=base_url, sync_interval_s=0.03)

    before = client.authorize(
        actor={"id": "a1", "type": "agent"},
        action={"name": "execute_refund"},
        resource={"type": "monetary_transaction", "id": "tx1", "attributes": {"amount": 25}},
    )
    assert before.status == "ALLOW"

    state.failing = True
    time.sleep(0.1)

    during = client.authorize(
        actor={"id": "a1", "type": "agent"},
        action={"name": "execute_refund"},
        resource={"type": "monetary_transaction", "id": "tx2", "attributes": {"amount": 25}},
    )
    client.close()

    assert during.status == "ALLOW"
    assert during.evaluation_metadata.policy_bundle_version == "pol_test_v1"


def test_flushes_receipt_asynchronously(mock_server):
    state, base_url = mock_server

    client = create_mizara_client(api_key="k", client_id="test_client", base_url=base_url, sync_interval_s=0.05)
    client.authorize(
        actor={"id": "a1", "type": "agent"},
        action={"name": "execute_refund"},
        resource={"type": "monetary_transaction", "id": "tx1", "attributes": {"amount": 25}},
    )
    time.sleep(0.1)
    client.close()

    assert len(state.received_receipts) == 1


def test_replays_unflushed_receipt_from_a_previous_process(mock_server, tmp_log_path):
    state, base_url = mock_server
    state.failing = True

    first = create_mizara_client(
        api_key="k", client_id="test_client", base_url=base_url, sync_interval_s=0.05, receipt_log_path=tmp_log_path
    )
    first.authorize(
        actor={"id": "a1", "type": "agent"},
        action={"name": "execute_refund"},
        resource={"type": "monetary_transaction", "id": "tx1", "attributes": {"amount": 25}},
    )
    first.close()
    assert len(state.received_receipts) == 0

    state.failing = False
    second = create_mizara_client(
        api_key="k", client_id="test_client", base_url=base_url, sync_interval_s=0.05, receipt_log_path=tmp_log_path
    )
    time.sleep(0.15)
    second.close()

    assert len(state.received_receipts) == 1


def test_fails_closed_on_session_gated_action_when_session_store_unreachable(mock_server):
    state, base_url = mock_server

    client = create_mizara_client(api_key="k", client_id="test_client", base_url=base_url, sync_interval_s=0.05)
    client.authorize(
        actor={"id": "a1", "type": "agent"},
        action={"name": "execute_refund"},
        resource={"type": "monetary_transaction", "id": "tx1", "attributes": {"amount": 25}},
    )

    state.failing = True
    time.sleep(0.06)

    result = client.authorize(
        actor={"id": "a1", "type": "agent"},
        action={"name": "cumulative_test"},
        resource={"type": "monetary_transaction", "id": "tx2", "attributes": {"amount": 25}},
        context={"session_id": "sess_1"},
    )
    client.close()

    assert result.status == "DENY"
    assert "session store unreachable" in (result.enforcement.user_facing_error or "")


def test_wait_for_approval_resolves_once_hosted_api_reports_a_decision(mock_server):
    state, base_url = mock_server
    state.approval_status["rcpt_pending"] = "PENDING"

    client = create_mizara_client(api_key="k", client_id="test_client", base_url=base_url, sync_interval_s=0.05)

    def flip_status():
        time.sleep(0.05)
        state.approval_status["rcpt_pending"] = "APPROVED"

    threading.Thread(target=flip_status, daemon=True).start()

    outcome = client.wait_for_approval("rcpt_pending", poll_interval_s=0.02, timeout_s=2.0)
    client.close()

    assert outcome == "APPROVED"


def test_wait_for_approval_times_out_if_no_decision_arrives(mock_server):
    state, base_url = mock_server
    state.approval_status["rcpt_stuck"] = "PENDING"

    client = create_mizara_client(api_key="k", client_id="test_client", base_url=base_url, sync_interval_s=0.05)
    outcome = client.wait_for_approval("rcpt_stuck", poll_interval_s=0.02, timeout_s=0.06)
    client.close()

    assert outcome == "TIMEOUT"
