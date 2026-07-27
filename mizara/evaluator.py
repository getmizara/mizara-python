"""
Safe condition evaluator for Mizara policy expressions.
Never calls eval() or exec().

Supported syntax:
  Arithmetic:   +  -  *  /
  Comparisons:  <=  >=  <  >  ==  !=
  Logical:      &&  ||  (JavaScript operators, matches the JSON policy format)
  Field access: resource.attributes.amount
  Array check:  context.data_classification.contains('PII')
  Literals:     numbers (42, 3.14)  strings ('EU'  "EU")
"""

from __future__ import annotations

import re
from typing import Any

_TOKEN_SPEC: list[tuple[str, str]] = [
    ("AND",    r"&&"),
    ("OR",     r"\|\|"),
    ("LTE",    r"<="),
    ("GTE",    r">="),
    ("EQ",     r"=="),
    ("NEQ",    r"!="),
    ("LT",     r"<"),
    ("GT",     r">"),
    ("PLUS",   r"\+"),
    ("MINUS",  r"-"),
    ("STAR",   r"\*"),
    ("SLASH",  r"/"),
    ("LPAREN", r"\("),
    ("RPAREN", r"\)"),
    ("NUMBER", r"\d+(?:\.\d+)?"),
    ("STRING", r"'[^']*'|\"[^\"]*\""),
    ("DOT",    r"\."),
    ("IDENT",  r"[a-zA-Z_][a-zA-Z0-9_]*"),
    ("SKIP",   r"\s+"),
]

_TOKEN_RE = re.compile(
    "|".join(f"(?P<{name}>{pat})" for name, pat in _TOKEN_SPEC)
)


def _tokenize(text: str) -> list[tuple[str, str]]:
    return [
        (m.lastgroup, m.group())
        for m in _TOKEN_RE.finditer(text)
        if m.lastgroup != "SKIP"
    ]


class _Parser:
    def __init__(self, tokens: list[tuple[str, str]], scope: dict[str, Any]):
        self.tokens = tokens
        self.pos = 0
        self.scope = scope

    def _peek(self) -> tuple[str, str] | None:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def _consume(self, *kinds: str) -> tuple[str, str]:
        tok = self._peek()
        if tok is None or tok[0] not in kinds:
            raise ValueError(f"Expected {kinds}, got {tok!r}")
        self.pos += 1
        return tok

    def parse(self) -> Any:
        result = self._or()
        if self._peek() is not None:
            raise ValueError(f"Unexpected token: {self._peek()!r}")
        return result

    def _or(self) -> Any:
        left = self._and()
        while self._peek() and self._peek()[0] == "OR":
            self._consume("OR")
            right = self._and()
            left = left or right
        return left

    def _and(self) -> Any:
        left = self._comparison()
        while self._peek() and self._peek()[0] == "AND":
            self._consume("AND")
            right = self._comparison()
            left = left and right
        return left

    def _comparison(self) -> Any:
        left = self._arithmetic()
        tok = self._peek()
        if tok and tok[0] in ("EQ", "NEQ", "LTE", "GTE", "LT", "GT"):
            self.pos += 1
            right = self._arithmetic()
            # Python raises TypeError comparing None with <, <=, >, >= (a
            # missing field resolves to None); a missing value fails an
            # ordering comparison rather than crashing the evaluation.
            if tok[0] in ("LTE", "GTE", "LT", "GT") and (left is None or right is None):
                return False
            match tok[0]:
                case "EQ":  return left == right
                case "NEQ": return left != right
                case "LTE": return left <= right   # type: ignore[operator]
                case "GTE": return left >= right   # type: ignore[operator]
                case "LT":  return left < right    # type: ignore[operator]
                case "GT":  return left > right    # type: ignore[operator]
        return left

    def _arithmetic(self) -> Any:
        left = self._primary()
        while self._peek() and self._peek()[0] in ("PLUS", "MINUS", "STAR", "SLASH"):
            tok = self._peek()
            self.pos += 1
            right = self._primary()
            match tok[0]:  # type: ignore[union-attr]
                case "PLUS":  left = (left or 0) + (right or 0)   # type: ignore[operator]
                case "MINUS": left = (left or 0) - (right or 0)   # type: ignore[operator]
                case "STAR":  left = (left or 0) * (right or 0)   # type: ignore[operator]
                case "SLASH": left = (left or 0) / (right or 0)   # type: ignore[operator]
        return left

    def _primary(self) -> Any:
        tok = self._peek()
        if tok is None:
            raise ValueError("Unexpected end of expression")

        if tok[0] == "LPAREN":
            self._consume("LPAREN")
            val = self._or()
            self._consume("RPAREN")
            return val

        if tok[0] == "NUMBER":
            self.pos += 1
            return float(tok[1]) if "." in tok[1] else int(tok[1])

        if tok[0] == "STRING":
            self.pos += 1
            return tok[1][1:-1]

        if tok[0] == "IDENT":
            return self._path()

        raise ValueError(f"Unexpected token: {tok!r}")

    def _path(self) -> Any:
        parts: list[str] = [self._consume("IDENT")[1]]

        while self._peek() and self._peek()[0] == "DOT":
            self._consume("DOT")
            name = self._consume("IDENT")[1]

            if self._peek() and self._peek()[0] == "LPAREN":
                self._consume("LPAREN")
                arg = self._primary()
                self._consume("RPAREN")
                obj = self._resolve(parts)
                if name == "contains":
                    if isinstance(obj, (list, tuple)):
                        return arg in obj
                    if isinstance(obj, str):
                        return str(arg) in obj
                    return False
                raise ValueError(f"Unsupported method call: {name}()")

            parts.append(name)

        return self._resolve(parts)

    def _resolve(self, parts: list[str]) -> Any:
        # Handle JSON/JavaScript boolean literals (true/false appear as IDENT tokens)
        if len(parts) == 1:
            if parts[0] == "true":
                return True
            if parts[0] == "false":
                return False
        obj: Any = self.scope
        for part in parts:
            if obj is None:
                return None
            obj = obj.get(part) if isinstance(obj, dict) else getattr(obj, part, None)
        return obj


def evaluate_condition(condition: str, scope: dict[str, Any]) -> bool:
    """
    Safely evaluate a policy condition string against the authorize input scope.

    The scope must have the shape:
        {"actor": {...}, "action": {...}, "resource": {...}, "context": {...}}
    """
    tokens = _tokenize(condition)
    return bool(_Parser(tokens, scope).parse())
