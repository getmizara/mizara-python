#!/usr/bin/env python3
"""
pip install mizara
python demo.py
"""

from mizara import create_mizara_client, Policy, PolicyRule

policy = Policy(
    policy_id="pol_demo",
    client_id="demo",
    rules=[
        PolicyRule(
            id="rule_small_refund",
            target_action="execute_refund",
            condition="resource.attributes.amount <= 50",
            effect="ALLOW",
            fallback_effect="DENY",
            remediation_message="Refunds over $50 require human approval.",
        ),
        PolicyRule(
            id="rule_pii_access",
            target_action="read_customer_data",
            condition="context.data_classification == 'public'",
            effect="ALLOW",
            fallback_effect="REDACT",
            remediation_message="PII fields have been removed from the response.",
        ),
        PolicyRule(
            id="rule_send_email",
            target_action="send_email",
            condition="context.recipient_verified == true",
            effect="ALLOW",
            fallback_effect="DENY",
            remediation_message="Cannot send to unverified recipients.",
        ),
    ],
)

mizara = create_mizara_client(policy=policy)


def show(label, result):
    icon = "✓" if result.status == "ALLOW" else "✗"
    print(f"\n  {icon} {result.status:<8}  {label}")
    print(f"    rule    : {result.evaluation_metadata.triggered_rule_id}")
    print(f"    time    : {result.evaluation_metadata.execution_time_ms:.3f}ms")
    print(f"    receipt : {result.cryptographic_receipt.id}")
    print(f"    hash    : {result.cryptographic_receipt.hash[:32]}...")
    reason = result.enforcement.user_facing_error if result.enforcement else None
    if reason:
        print(f"    reason  : {reason}")


print()
print("  Mizara - authorize() before every agent action")
print("  " + "─" * 50)

show(
    "execute_refund  amount=$25",
    mizara.authorize(
        actor={"id": "agent_support_v3", "type": "autonomous_agent"},
        action={"name": "execute_refund"},
        resource={"type": "transaction", "id": "tx_8821",
                  "attributes": {"amount": 25, "currency": "USD"}},
    ),
)

show(
    "execute_refund  amount=$150",
    mizara.authorize(
        actor={"id": "agent_support_v3", "type": "autonomous_agent"},
        action={"name": "execute_refund"},
        resource={"type": "transaction", "id": "tx_8822",
                  "attributes": {"amount": 150, "currency": "USD"}},
    ),
)

show(
    "read_customer_data  classification=PII",
    mizara.authorize(
        actor={"id": "agent_support_v3", "type": "autonomous_agent"},
        action={"name": "read_customer_data"},
        resource={"type": "customer_record", "id": "cust_4491", "attributes": {}},
        context={"data_classification": "PII"},
    ),
)

show(
    "send_email  recipient_verified=false",
    mizara.authorize(
        actor={"id": "agent_comms_v1", "type": "autonomous_agent"},
        action={"name": "send_email"},
        resource={"type": "email", "id": "msg_221", "attributes": {}},
        context={"recipient_verified": False},
    ),
)

print()
print("  " + "─" * 50)
print("  Every decision - including ALLOWs - gets a signed receipt.")
print("  Stateless. No database. Policy-as-data.")
print()
print("  Docs   : https://mizara.ai/docs")
print("  GitHub : https://github.com/getmizara/mizara-python")
print()
