#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path

from .evaluator import _tokenize, _Parser
from .safety_test import run_safety_test
from .sdk import _load_policy


_VALID_EFFECTS = {"ALLOW", "DENY", "REDACT", "RE_ROUTE"}


def _validate_policy(data: object) -> list[str]:
    errors: list[str] = []
    if not isinstance(data, dict):
        return ["policy must be a JSON object"]

    if not isinstance(data.get("policy_id"), str):
        errors.append("policy_id must be a string")
    if not isinstance(data.get("client_id"), str):
        errors.append("client_id must be a string")

    rules = data.get("rules")
    if not isinstance(rules, list):
        errors.append("rules must be an array")
        return errors

    for i, rule in enumerate(rules):
        prefix = f"rules[{i}]"
        if not isinstance(rule.get("id"), str):
            errors.append(f"{prefix}.id must be a string")
        if not isinstance(rule.get("target_action"), str):
            errors.append(f"{prefix}.target_action must be a string")

        condition = rule.get("condition")
        if not isinstance(condition, str):
            errors.append(f"{prefix}.condition must be a string")
        else:
            try:
                _tokenize(condition)
            except Exception as exc:
                errors.append(f"{prefix}.condition is not valid: {exc}")

        if rule.get("effect") not in _VALID_EFFECTS:
            errors.append(f"{prefix}.effect must be one of: {', '.join(sorted(_VALID_EFFECTS))}")
        if rule.get("fallback_effect") not in _VALID_EFFECTS:
            errors.append(f"{prefix}.fallback_effect must be one of: {', '.join(sorted(_VALID_EFFECTS))}")

    return errors


def _run_validate(path: Path) -> None:
    try:
        data = json.loads(path.read_text())
    except Exception as exc:
        print(f"Failed to read policy: {exc}", file=sys.stderr)
        sys.exit(1)

    errors = _validate_policy(data)
    if errors:
        print(f"Policy validation failed for {path}:", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        sys.exit(1)

    print(f"Policy {data['policy_id']} is valid ({len(data['rules'])} rules).")


_VERDICT_MARKER = {"PROTECTED": "PASS", "DEFAULT-DENIED": "WARN", "FAIL": "FAIL"}


def _run_safety_test(path: Path, json_output: bool) -> None:
    try:
        policy = _load_policy(str(path))
    except Exception as exc:
        print(f"Failed to load policy: {exc}", file=sys.stderr)
        sys.exit(1)

    results = run_safety_test(policy)

    if json_output:
        print(
            json.dumps(
                [
                    {
                        "id": r.scenario.id,
                        "category": r.scenario.category,
                        "description": r.scenario.description,
                        "status": r.status,
                        "verdict": r.verdict,
                        "triggered_rule_id": r.triggered_rule_id,
                    }
                    for r in results
                ],
                indent=2,
            )
        )
    else:
        print(f"Mizara Safety Test - {policy.policy_id} ({len(policy.rules)} rules)\n")
        for r in results:
            marker = _VERDICT_MARKER[r.verdict]
            print(f"  {marker:<5}  {r.scenario.id:<30}  {r.verdict:<15}  {r.scenario.description}")

        protected = sum(1 for r in results if r.verdict == "PROTECTED")
        warned = sum(1 for r in results if r.verdict == "DEFAULT-DENIED")
        failed = sum(1 for r in results if r.verdict == "FAIL")
        print(
            f"\n{protected} protected, {warned} default-denied (no explicit rule), "
            f"{failed} unprotected - of {len(results)} common risk scenarios"
        )

    sys.exit(1 if any(r.verdict == "FAIL" for r in results) else 0)


def main() -> None:
    args = sys.argv[1:]
    usage = "Usage: mizara validate <policy.json>\n       mizara test <policy.json> [--json]"

    if len(args) >= 2 and args[0] == "validate":
        _run_validate(Path(args[1]))
    elif len(args) >= 2 and args[0] == "test":
        _run_safety_test(Path(args[1]), json_output="--json" in args[2:])
    else:
        print(usage, file=sys.stderr)
        sys.exit(1)
