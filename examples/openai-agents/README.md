# Mizara + OpenAI Agents SDK

Shows how to add `mizara.authorize()` as a function tool so the agent
evaluates it before executing any consequential action.

## Setup

```bash
pip install mizara openai-agents
export OPENAI_API_KEY=sk-...
```

## Run

```bash
python examples/openai-agents/demo.py
```

## How it works

`mizara_authorize` is registered as a `@function_tool`. The agent's
instructions require calling it before any payment. OpenAI's model handles
tool orchestration - Mizara handles the policy decision.

```python
@function_tool
def mizara_authorize(actor_id, action_name, resource_type, resource_id, amount=None):
    result = mizara.authorize(...)
    return json.dumps({"status": result.status, "receipt": ...})

agent = Agent(
    name="finance-agent",
    instructions="Before any payment, call mizara_authorize first...",
    tools=[mizara_authorize, approve_payment],
)
```

**Expected output:**

```
─── Scenario A - Approve $1,200 payment (under the limit) ─────
ALLOW - payment approved.

─── Scenario B - Approve $25,000 payment (over the limit) ──────
DENY - Amount exceeds the autonomous approval limit.
```

## Adapting to your setup

Replace `approve_payment` with your actual business tool. The Mizara
policy file (`policy.json`) controls what the agent can do - change
thresholds there without modifying code.
