"""
Mizara Python SDK - local authorization demo

Run: python demo/simulate.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from mizara import create_mizara_client

mizara = create_mizara_client(
    policy_path=str(Path(__file__).parent / "demo_policy.json")
)

scenarios = [
    {
        "name": "Scenario A - Refund $25.00",
        "expected": "ALLOW",
        "actor": {"id": "agent_support_eu_v4", "type": "autonomous_agent", "framework": "langgraph"},
        "action": {"name": "execute_refund", "risk_profile": "medium"},
        "resource": {"type": "monetary_transaction", "id": "tx_1001", "attributes": {"amount": 25.0, "currency": "USD"}},
        "context": {"client_id": "demo_customer"},
    },
    {
        "name": "Scenario B - Refund $75.00",
        "expected": "DENY",
        "actor": {"id": "agent_support_eu_v4", "type": "autonomous_agent", "framework": "langgraph"},
        "action": {"name": "execute_refund", "risk_profile": "high_irreversible"},
        "resource": {"type": "monetary_transaction", "id": "tx_1002", "attributes": {"amount": 75.0, "currency": "USD"}},
        "context": {"client_id": "demo_customer"},
    },
    {
        "name": "Scenario C - Transmit raw health metrics to unauthorized endpoint",
        "expected": "REDACT",
        "actor": {"id": "agent_support_eu_v4", "type": "autonomous_agent", "framework": "langgraph"},
        "action": {"name": "transmit_data", "risk_profile": "high_irreversible"},
        "resource": {"type": "health_record", "id": "rec_5001", "attributes": {"authorized_endpoint": False}},
        "context": {"client_id": "demo_customer", "data_classification": ["PII", "PHI"], "target_jurisdiction": "EU"},
    },
]

print("Mizara Python SDK - Local Authorization Demo\n")

for s in scenarios:
    result = mizara.authorize(
        actor=s["actor"],
        action=s["action"],
        resource=s["resource"],
        context=s.get("context"),
    )
    passed = result.status == s["expected"]
    print(f"{'✓' if passed else '✗'} {s['name']}")
    print(f"  status:   {result.status} (expected {s['expected']})")
    print(f"  rule:     {result.evaluation_metadata.triggered_rule_id or 'none'}")
    print(f"  time:     {result.evaluation_metadata.execution_time_ms}ms")
    print(f"  receipt:  {result.cryptographic_receipt.id}")
    if result.enforcement.user_facing_error:
        print(f"  message:  {result.enforcement.user_facing_error}")
    print()
