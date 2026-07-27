from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import sys
from dataclasses import asdict
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .types import AuthorizationStatus, AuthorizeInput, CryptographicReceipt

_key_pair: Optional[tuple[Ed25519PrivateKey, str]] = None


def _load_or_generate_key_pair() -> tuple[Ed25519PrivateKey, str]:
    env_key = os.environ.get("MIZARA_SIGNING_PRIVATE_KEY")
    if not env_key:
        sys.stderr.write(
            "[mizara] MIZARA_SIGNING_PRIVATE_KEY is not set. Receipts are being signed with "
            "a key generated fresh for this process and are not verifiable after it exits. "
            "Set MIZARA_SIGNING_PRIVATE_KEY (base64, 32-byte Ed25519 seed) before relying on "
            "receipts for audit.\n"
        )
    seed = base64.b64decode(env_key) if env_key else secrets.token_bytes(32)
    private_key = Ed25519PrivateKey.from_private_bytes(seed)
    public_key_b64 = base64.b64encode(private_key.public_key().public_bytes_raw()).decode()
    return private_key, public_key_b64


def _get_key_pair() -> tuple[Ed25519PrivateKey, str]:
    global _key_pair
    if _key_pair is None:
        _key_pair = _load_or_generate_key_pair()
    return _key_pair


def create_receipt(
    input_data: AuthorizeInput,
    status: AuthorizationStatus,
    triggered_rule_id: Optional[str],
) -> CryptographicReceipt:
    payload = json.dumps(
        {
            "actor": asdict(input_data.actor),
            "action": asdict(input_data.action),
            "resource": asdict(input_data.resource),
            "context": input_data.context or {},
            "status": status,
            "triggered_rule_id": triggered_rule_id,
        },
        sort_keys=True,
    )

    hash_value = hashlib.sha256(payload.encode()).hexdigest()
    private_key, public_key_b64 = _get_key_pair()
    signature = private_key.sign(hash_value.encode())

    return CryptographicReceipt(
        id=f"rcpt_{secrets.token_hex(8)}",
        hash=hash_value,
        signature=base64.b64encode(signature).decode(),
        algorithm="ed25519",
        public_key=public_key_b64,
    )


def get_public_key() -> str:
    """
    The current signing key's public half, so a host process (the hosted
    API) can expose it for offline verification without duplicating the
    key-loading logic above.
    """
    return _get_key_pair()[1]


def verify_receipt(receipt: CryptographicReceipt, public_key_b64: str) -> bool:
    """
    Independent, offline verification: checks a receipt's signature
    against a public key without any call back to Mizara. This is what
    makes a receipt actually verifiable rather than just "Mizara says
    it's valid" - a customer or auditor can check it with only the
    public key.
    """
    if receipt.algorithm != "ed25519" or not receipt.public_key:
        return False
    try:
        public_key = Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key_b64))
        public_key.verify(base64.b64decode(receipt.signature), receipt.hash.encode())
        return True
    except InvalidSignature:
        return False
