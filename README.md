<p align="center">
  <img src="assets/logo-banner.svg" width="340" alt="mizara">
</p>

<p align="center">
  <a href="https://github.com/getmizara/mizara-python/actions/workflows/ci.yml"><img src="https://github.com/getmizara/mizara-python/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://pypi.org/project/mizara/"><img src="https://img.shields.io/pypi/v/mizara?color=3776ab" alt="PyPI"></a>
  <a href="https://pypi.org/project/mizara/"><img src="https://img.shields.io/pypi/pyversions/mizara" alt="Python"></a>
  <a href="LICENSE.md"><img src="https://img.shields.io/badge/license-Apache%202.0-blue" alt="License"></a>
</p>

Authorization layer for AI agents. Call `authorize()` before any consequential action. Sub-2ms evaluation, policy-as-data, cryptographic receipt on every decision.

Also available for TypeScript/Node.js: [`@mizara/sdk`](https://github.com/getmizara/mizara-node)

## Install

```bash
pip install mizara
```

## Quickstart

**Local policy file**

```python
from mizara import create_mizara_client

mizara = create_mizara_client(policy_path="./policy.json")

result = mizara.authorize(
    actor={"id": "agent_ops_v4", "type": "autonomous_agent"},
    action={"name": "delete_production_resource"},
    resource={"type": "cloud_resource", "id": "res_9c21",
              "attributes": {"environment": "production"}},
)

if result.status == "DENY":
    raise Exception(result.enforcement.user_facing_error)
# result.status                   -> 'ALLOW' | 'DENY' | 'REDACT' | 'RE_ROUTE'
# result.cryptographic_receipt.id -> 'rcpt_8f3c...'
```

**Hosted API** - sign up at [mizara.ai/signup](https://mizara.ai/signup), skip the local file:

```python
import os
from mizara import create_mizara_client

mizara = create_mizara_client(
    api_key=os.environ["MIZARA_API_KEY"],
    client_id="acme_corp",
)

result = mizara.authorize(
    actor={"id": "agent_1", "type": "autonomous_agent"},
    action={"name": "delete_production_resource"},
    resource={"type": "cloud_resource", "id": "res_1",
              "attributes": {"environment": "production"}},
)
```

Hosted mode evaluates locally against a policy snapshot that's refreshed in the background (every 10 seconds by default). A Mizara outage doesn't fail every `authorize()` call, it keeps using the last policy successfully fetched. Receipts are generated locally and flushed to the hosted API asynchronously. For zero-loss delivery across a process crash, pass `receipt_log_path`:

```python
mizara = create_mizara_client(
    api_key=os.environ["MIZARA_API_KEY"],
    client_id="acme_corp",
    receipt_log_path="./mizara-receipts.log",
    on_sync_error=lambda err: print(f"[mizara] policy sync failing: {err}"),
)
```

Call `mizara.close()` before your process exits to stop the background sync thread (a no-op in local mode, safe to always call). Construction blocks briefly for the first policy sync to settle (bounded by a 10-second network timeout) since Python has no async equivalent to return immediately and resolve later.

**Waiting on a RE_ROUTE decision** - a `RE_ROUTE` result means the action is held pending human approval. In hosted mode, `wait_for_approval` blocks until it's approved, denied, or the timeout elapses:

```python
result = mizara.authorize(...)

if result.status == "RE_ROUTE":
    outcome = mizara.wait_for_approval(result.cryptographic_receipt.id)
    # outcome: "APPROVED" | "DENIED" | "TIMEOUT"
```

Only available on the hosted client; local mode has no server to hold pending approval state. Defaults to polling every 3 seconds for up to 25 minutes.

**Verifying receipts** - every receipt is signed with Ed25519, an asymmetric algorithm. Verification only needs the public key, not a call back to Mizara or the signing secret:

```python
from mizara import verify_receipt, get_public_key

public_key = get_public_key()  # or fetch from GET /api/v1/public-key in hosted mode
is_valid = verify_receipt(result.cryptographic_receipt, public_key)
```

Set `MIZARA_SIGNING_PRIVATE_KEY` (a base64-encoded 32-byte Ed25519 seed) so the same key persists across restarts. Without it, a fresh key is generated per process and receipts stop being verifiable once it exits.

## Policy format

Plain JSON. No Rego, no Cedar syntax.

```json
{
  "policy_id": "pol_infra_guard_v1",
  "client_id": "acme_corp",
  "rules": [
    {
      "id": "rule_block_prod_delete",
      "target_action": "delete_production_resource",
      "condition": "resource.attributes.environment == 'production'",
      "effect": "DENY",
      "fallback_effect": "ALLOW",
      "remediation_message": "Production deletion requires approval."
    }
  ]
}
```

Condition expressions support comparisons, boolean logic, arithmetic, and `.contains()`:

```text
resource.attributes.amount <= 50.00
context.jurisdiction == 'EU' && context.data_classification.contains('PII')
context.session_total + resource.attributes.amount <= 500
```

## Integrations

| Framework | Example |
| --- | --- |
| LangGraph | [`examples/langgraph/`](examples/langgraph/) |
| OpenAI Agents SDK | [`examples/openai-agents/`](examples/openai-agents/) |
| Hosted API | [`examples/hosted-api/`](examples/hosted-api/) |

## Design choices

**Fail closed.** No matching rule returns `DENY`, not `ALLOW`.

**Most restrictive wins.** When more than one rule matches an action, the most restrictive triggered outcome wins - `DENY` > `RE_ROUTE` > `REDACT` > `ALLOW` - regardless of rule order.

**Resilient by default, with one honest exception.** Hosted mode evaluates locally against a synced policy, so a Mizara outage doesn't stop your agent. A rule that uses `context.session_total` is the one case that can't get this guarantee: cumulative tracking is inherently centralized state, so if the session store is unreachable, that specific request fails closed rather than silently trusting a stale total.

**Policy as data.** Rules live in a JSON file that non-engineers can edit without a deploy.

**No Cedar or Rego.** Conditions are plain boolean expressions. The engine compiles them safely without `eval()`.

**Receipt on every call.** Even `ALLOW` decisions are signed and stored. The audit trail is part of the product, not an afterthought.

## License

Apache-2.0
