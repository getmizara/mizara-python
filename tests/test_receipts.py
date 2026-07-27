import base64
from dataclasses import replace

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from mizara.receipts import create_receipt, verify_receipt
from mizara.types import Actor, Action, AuthorizeInput, Resource


INPUT = AuthorizeInput(
    actor=Actor(id="a1", type="autonomous_agent"),
    action=Action(name="execute_payout"),
    resource=Resource(type="monetary_transaction", id="tx_1", attributes={"amount": 75}),
)


def test_deterministic_hash_for_identical_decisions():
    r1 = create_receipt(INPUT, "DENY", "rule_x")
    r2 = create_receipt(INPUT, "DENY", "rule_x")
    assert r1.hash == r2.hash
    assert r1.id != r2.id  # unique ids


def test_different_hash_for_different_status():
    r1 = create_receipt(INPUT, "DENY", "rule_x")
    r2 = create_receipt(INPUT, "ALLOW", "rule_x")
    assert r1.hash != r2.hash


def test_signs_with_ed25519_and_includes_public_key():
    r = create_receipt(INPUT, "DENY", "rule_x")
    assert r.algorithm == "ed25519"
    assert r.public_key
    assert r.signature


def test_verifies_independently_with_the_public_key():
    r = create_receipt(INPUT, "DENY", "rule_x")
    assert verify_receipt(r, r.public_key) is True


def test_fails_verification_if_tampered_with():
    r = create_receipt(INPUT, "DENY", "rule_x")
    tampered = replace(r, hash="a" * 64)
    assert verify_receipt(tampered, r.public_key) is False


def test_fails_verification_against_an_unrelated_public_key():
    r = create_receipt(INPUT, "DENY", "rule_x")
    unrelated_public_key = base64.b64encode(
        Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    ).decode()
    assert verify_receipt(r, unrelated_public_key) is False
