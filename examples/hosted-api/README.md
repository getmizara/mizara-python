# Using the Mizara Hosted API

The fastest way to start - no local policy file needed. Sign up at mizara.ai/signup,
get your API key, and call the hosted endpoint directly.

## 1. Get an API key

```
https://mizara.ai/signup
```

Paste your email, get a key instantly. Looks like: `mizara_live_...`

## 2. Try it with curl

```bash
curl -X POST https://mizara-services.vercel.app/api/v1/authorize \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "actor":    { "id": "agent_1", "type": "autonomous_agent" },
    "action":   { "name": "delete_production_resource" },
    "resource": { "type": "cloud_resource", "id": "res_1",
                  "attributes": { "environment": "production" } },
    "context":  { "client_id": "demo_customer" }
  }'
```

The response includes `status` (ALLOW/DENY/REDACT/RE_ROUTE) and a signed receipt.

## 3. Python

```python
# pip install mizara
import os
from mizara import create_mizara_client

mizara = create_mizara_client(
    api_key=os.environ["MIZARA_API_KEY"],
    client_id="acme_corp",  # your client_id from signup
)

result = mizara.authorize(
    actor={"id": "agent_ops", "type": "autonomous_agent"},
    action={"name": "delete_production_resource", "risk_profile": "high_irreversible"},
    resource={"type": "cloud_resource", "id": "res_9c21",
              "attributes": {"environment": "production"}},
)

if result.status == "DENY":
    raise Exception(result.enforcement.user_facing_error or "Blocked by policy")
# proceed with action
```

## 4. TypeScript

```typescript
// npm install @mizara/sdk
import { createMizaraClient } from '@mizara/sdk';

const mizara = createMizaraClient({
  apiKey: process.env.MIZARA_API_KEY,
  clientId: 'acme_corp',
});

const result = await mizara.authorize({
  actor:    { id: 'agent_ops', type: 'autonomous_agent' },
  action:   { name: 'delete_production_resource', risk_profile: 'high_irreversible' },
  resource: { type: 'cloud_resource', id: 'res_9c21',
               attributes: { environment: 'production' } },
});

if (result.status === 'DENY') {
  throw new Error(result.enforcement.user_facing_error ?? 'Blocked by policy');
}
// proceed with action
```

## 5. Manage your policy

The default starter policy allows actions up to a $100 amount attribute when one is present.
Change it anytime:

```bash
curl -X PUT https://mizara-services.vercel.app/api/v1/policies/YOUR_CLIENT_ID \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "policy_id": "pol_YOUR_CLIENT_ID_v1",
    "rules": [
      {
        "id": "rule_block_prod_delete",
        "target_action": "delete_production_resource",
        "condition": "resource.attributes.environment == '\''production'\''",
        "effect": "DENY",
        "fallback_effect": "ALLOW",
        "remediation_message": "Production deletion requires approval."
      }
    ]
  }'
```

## 6. Verify a receipt

```bash
curl https://mizara-services.vercel.app/api/v1/receipts/RECEIPT_ID \
  -H "Authorization: Bearer YOUR_API_KEY"
```

Returns the full decision payload with cryptographic hash and signature.
Verifiable: if the hash doesn't match a recalculation, the record was tampered with.
