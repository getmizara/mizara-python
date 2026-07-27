#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path

from .evaluator import _tokenize, _Parser


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


def main() -> None:
    args = sys.argv[1:]
    if len(args) < 2 or args[0] != "validate":
        print("Usage: mizara validate <policy.json>", file=sys.stderr)
        sys.exit(1)

    path = Path(args[1])
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
