"""
Compiles a Mizara condition string into a Cedar boolean expression.
Returns None for anything Cedar can't express (division, unsupported
operators) rather than a partial or incorrect translation.

Reuses the tokenizer from evaluator.py so both parsers agree on what a
token is; this module's parser builds an AST instead of evaluating
directly, since Cedar compilation needs a tree to walk, not a value.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Union

from .evaluator import _tokenize

_ROOT_IDENTIFIER_MAP = {"actor": "principal"}

_COMPARISON_OPS = {"EQ": "==", "NEQ": "!=", "LTE": "<=", "GTE": ">=", "LT": "<", "GT": ">"}
_ARITHMETIC_OPS = {"PLUS": "+", "MINUS": "-", "STAR": "*", "SLASH": "/"}


@dataclass
class Literal:
    value: object


@dataclass
class Identifier:
    name: str


@dataclass
class Member:
    obj: "Node"
    key: str


@dataclass
class Binary:
    op: str
    left: "Node"
    right: "Node"


@dataclass
class Unary:
    op: str
    arg: "Node"


@dataclass
class Call:
    obj: "Node"
    method: str
    args: list["Node"]


Node = Union[Literal, Identifier, Member, Binary, Unary, Call]


class UnsupportedConditionError(Exception):
    pass


class _AstParser:
    def __init__(self, tokens: list[tuple[str, str]]):
        self.tokens = tokens
        self.pos = 0

    def _peek(self) -> tuple[str, str] | None:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def _consume(self, *kinds: str) -> tuple[str, str]:
        tok = self._peek()
        if tok is None or tok[0] not in kinds:
            raise UnsupportedConditionError(f"Expected {kinds}, got {tok!r}")
        self.pos += 1
        return tok

    def parse(self) -> Node:
        result = self._or()
        if self._peek() is not None:
            raise UnsupportedConditionError(f"Unexpected token: {self._peek()!r}")
        return result

    def _or(self) -> Node:
        left = self._and()
        while self._peek() and self._peek()[0] == "OR":
            self._consume("OR")
            left = Binary("||", left, self._and())
        return left

    def _and(self) -> Node:
        left = self._comparison()
        while self._peek() and self._peek()[0] == "AND":
            self._consume("AND")
            left = Binary("&&", left, self._comparison())
        return left

    def _comparison(self) -> Node:
        left = self._arithmetic()
        tok = self._peek()
        if tok and tok[0] in _COMPARISON_OPS:
            self.pos += 1
            return Binary(_COMPARISON_OPS[tok[0]], left, self._arithmetic())
        return left

    def _arithmetic(self) -> Node:
        left = self._primary()
        while self._peek() and self._peek()[0] in _ARITHMETIC_OPS:
            tok = self._peek()
            self.pos += 1
            left = Binary(_ARITHMETIC_OPS[tok[0]], left, self._primary())  # type: ignore[index]
        return left

    def _primary(self) -> Node:
        tok = self._peek()
        if tok is None:
            raise UnsupportedConditionError("Unexpected end of expression")

        if tok[0] == "LPAREN":
            self._consume("LPAREN")
            val = self._or()
            self._consume("RPAREN")
            return val

        if tok[0] == "NUMBER":
            self.pos += 1
            return Literal(float(tok[1]) if "." in tok[1] else int(tok[1]))

        if tok[0] == "STRING":
            self.pos += 1
            return Literal(tok[1][1:-1])

        if tok[0] == "IDENT":
            return self._path()

        raise UnsupportedConditionError(f"Unexpected token: {tok!r}")

    def _path(self) -> Node:
        name = self._consume("IDENT")[1]
        if name == "true":
            return Literal(True)
        if name == "false":
            return Literal(False)

        node: Node = Identifier(name)
        while self._peek() and self._peek()[0] == "DOT":
            self._consume("DOT")
            prop = self._consume("IDENT")[1]

            if self._peek() and self._peek()[0] == "LPAREN":
                self._consume("LPAREN")
                arg = self._primary()
                self._consume("RPAREN")
                if prop != "contains":
                    raise UnsupportedConditionError(f"Unsupported method: {prop}")
                return Call(node, prop, [arg])

            node = Member(node, prop)

        return node


def _translate(node: Node) -> str:
    if isinstance(node, Literal):
        if isinstance(node.value, bool):
            return "true" if node.value else "false"
        if isinstance(node.value, str):
            return f'"{node.value}"'
        if isinstance(node.value, float):
            # Cedar's numeric type is integer-only - no bare decimal
            # literal syntax. A whole-number float (100.0, from "100.00"
            # in a condition) converts cleanly; a genuinely fractional
            # one has no safe translation, so it's unsupported.
            if node.value != int(node.value):
                raise UnsupportedConditionError("Cedar has no bare decimal literal syntax")
            return str(int(node.value))
        return str(node.value)

    if isinstance(node, Identifier):
        return _ROOT_IDENTIFIER_MAP.get(node.name, node.name)

    if isinstance(node, Member):
        return f"{_translate(node.obj)}.{node.key}"

    if isinstance(node, Binary):
        if node.op == "/":
            raise UnsupportedConditionError("Cedar does not support division")
        return f"({_translate(node.left)} {node.op} {_translate(node.right)})"

    if isinstance(node, Unary):
        return f"{node.op}({_translate(node.arg)})"

    if isinstance(node, Call):
        if node.method != "contains":
            raise UnsupportedConditionError(f"Unsupported method: {node.method}")
        return f"{_translate(node.obj)}.contains({_translate(node.args[0])})"

    raise UnsupportedConditionError(f"Unsupported node: {node!r}")


def _collect_member_paths(node: Node, paths: set[str]) -> None:
    if isinstance(node, Member):
        paths.add(_translate(node))
        _collect_member_paths(node.obj, paths)
    elif isinstance(node, Binary):
        _collect_member_paths(node.left, paths)
        _collect_member_paths(node.right, paths)
    elif isinstance(node, Unary):
        _collect_member_paths(node.arg, paths)
    elif isinstance(node, Call):
        _collect_member_paths(node.obj, paths)
        for arg in node.args:
            _collect_member_paths(arg, paths)


def _has_guard_for(path: str) -> str:
    # "resource.attributes.amount" -> "resource has attributes &&
    # resource.attributes has amount" - has only checks one level, so a
    # multi-level path needs one guard per level, not just the leaf.
    parts = path.split(".")
    guards = [f"{'.'.join(parts[:i])} has {parts[i]}" for i in range(1, len(parts))]
    return " && ".join(guards)


def compile_condition_to_cedar(condition: str) -> str | None:
    try:
        ast = _AstParser(_tokenize(condition)).parse()
        translated = _translate(ast)
        paths: set[str] = set()
        _collect_member_paths(ast, paths)
        guards = [g for g in (_has_guard_for(p) for p in paths) if g]
        if not guards:
            return translated
        return f"({' && '.join(guards)}) && {translated}"
    except UnsupportedConditionError:
        return None
    except Exception:
        return None
