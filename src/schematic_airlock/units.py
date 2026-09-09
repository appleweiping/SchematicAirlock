"""SPICE numeric literals and a deliberately small expression evaluator."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from decimal import (
    ROUND_HALF_EVEN,
    Context,
    Decimal,
    DecimalException,
    DivisionByZero,
    Inexact,
    InvalidOperation,
    Overflow,
    Underflow,
    localcontext,
)

from schematic_airlock.domain import InputError

_NUMBER = re.compile(
    r"(?P<number>[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?)"
    r"(?P<suffix>[A-Za-z]*)",
    re.ASCII,
)
_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_.$]*")
_MULTIPLIERS: tuple[tuple[str, Decimal], ...] = (
    ("meg", Decimal("1e6")),
    ("mil", Decimal("25.4e-6")),
    ("t", Decimal("1e12")),
    ("g", Decimal("1e9")),
    ("k", Decimal("1e3")),
    ("m", Decimal("1e-3")),
    ("u", Decimal("1e-6")),
    ("n", Decimal("1e-9")),
    ("p", Decimal("1e-12")),
    ("f", Decimal("1e-15")),
)
_UNIT_ONLY = ("v", "a", "ohm", "hz", "s", "h", "w")
_MAX_MAGNITUDE = Decimal("1e100")
_MIN_MAGNITUDE = Decimal("1e-100")
_MAX_DIGITS = 1_024
_CONTEXT = Context(
    prec=_MAX_DIGITS + 4,
    rounding=ROUND_HALF_EVEN,
    Emin=-1_000,
    Emax=1_000,
    traps=[InvalidOperation, DivisionByZero, Overflow, Underflow],
)


def _supported(value: Decimal) -> Decimal:
    # copy_abs() and Decimal comparisons do not round through the caller's
    # context. Check before fixed-point formatting or subsequent arithmetic.
    if not isinstance(value, Decimal) or not value.is_finite():
        raise ValueError("numeric value must be a finite Decimal")
    magnitude = value.copy_abs()
    if (
        len(value.as_tuple().digits) > _MAX_DIGITS
        or magnitude > _MAX_MAGNITUDE
        or (magnitude != 0 and magnitude < _MIN_MAGNITUDE)
    ):
        raise ValueError("numeric value is outside the supported finite range or digit budget")
    return value


def parse_number(text: str) -> Decimal:
    """Parse a finite SPICE number without applying Python evaluation rules."""

    if not isinstance(text, str) or len(text) > _MAX_DIGITS:
        raise ValueError("SPICE literal exceeds the 1024-character budget")
    candidate = text.strip()
    if len(candidate) >= 2 and (candidate[0], candidate[-1]) in (("{", "}"), ("'", "'")):
        candidate = candidate[1:-1]
    match = _NUMBER.fullmatch(candidate)
    if match is None:
        raise ValueError(f"not a SPICE number: {text!r}")

    suffix = match.group("suffix").lower()
    multiplier = Decimal(1)
    if suffix and suffix not in _UNIT_ONLY:
        for prefix, factor in _MULTIPLIERS:
            if suffix.startswith(prefix):
                multiplier = factor
                suffix = suffix[len(prefix) :]
                break
        if suffix and suffix not in _UNIT_ONLY:
            raise ValueError(f"unknown SPICE suffix in {text!r}")

    try:
        with localcontext(_CONTEXT) as context:
            context.traps[Inexact] = True
            value = Decimal(match.group("number")) * multiplier
    except DecimalException as exc:
        raise ValueError(f"invalid SPICE number: {text!r}") from exc
    return _supported(value)


def _expression_tokens(expression: str, max_tokens: int) -> list[str]:
    text = expression.strip()
    if (text.startswith("{") and text.endswith("}")) or (
        text.startswith("'") and text.endswith("'")
    ):
        text = text[1:-1]

    tokens: list[str] = []
    index = 0
    while index < len(text):
        if text[index].isspace():
            index += 1
            continue
        if text[index] in "+-*/()":
            tokens.append(text[index])
            index += 1
        else:
            number_match = _NUMBER.match(text, index)
            if number_match is not None:
                tokens.append(number_match.group(0))
                index = number_match.end()
            else:
                name_match = _NAME.match(text, index)
                if name_match is not None:
                    tokens.append(name_match.group(0))
                    index = name_match.end()
                else:
                    raise ValueError(f"unsupported character {text[index]!r} in expression")
        if len(tokens) > max_tokens:
            raise ValueError(f"expression exceeds the {max_tokens}-token budget")
    return tokens


class _ExpressionParser:
    def __init__(
        self,
        tokens: Sequence[str],
        parameters: Mapping[str, Decimal],
        max_depth: int,
        exact: bool,
    ) -> None:
        self.tokens = tokens
        self.parameters = {name.lower(): value for name, value in parameters.items()}
        self.max_depth = max_depth
        self.index = 0
        self.exact = exact

    def parse(self) -> Decimal:
        if not self.tokens:
            raise ValueError("expression is empty")
        try:
            with localcontext(_CONTEXT) as context:
                context.prec = _MAX_DIGITS if self.exact else 50
                context.traps[Inexact] = self.exact
                value = self._sum(0)
        except DecimalException as exc:
            raise ValueError("expression is inexact or exceeds the arithmetic range") from exc
        if self.index != len(self.tokens):
            raise ValueError(f"unexpected token {self.tokens[self.index]!r}")
        return _supported(value)

    def _sum(self, depth: int) -> Decimal:
        value = self._product(depth + 1)
        while self._peek() in {"+", "-"}:
            operator = self._take()
            operand = self._product(depth + 1)
            value = value + operand if operator == "+" else value - operand
        return value

    def _product(self, depth: int) -> Decimal:
        value = self._atom(depth + 1)
        while self._peek() in {"*", "/"}:
            operator = self._take()
            operand = self._atom(depth + 1)
            try:
                value = value * operand if operator == "*" else value / operand
            except (DivisionByZero, InvalidOperation) as exc:
                raise ValueError("invalid division in expression") from exc
        return value

    def _atom(self, depth: int) -> Decimal:
        if depth > self.max_depth:
            raise ValueError(f"expression exceeds the depth budget of {self.max_depth}")
        token = self._take()
        if token in {"+", "-"}:
            value = self._atom(depth + 1)
            # Bandit mistakes this arithmetic operator comparison for a credential.
            return value if token == "+" else -value  # nosec B105
        # Bandit mistakes this expression delimiter comparison for a credential.
        if token == "(":  # nosec B105
            value = self._sum(depth + 1)
            if self._take() != ")":
                raise ValueError("unbalanced parentheses in expression")
            return value
        # Bandit mistakes this expression delimiter comparison for a credential.
        if token == ")":  # nosec B105
            raise ValueError("unexpected closing parenthesis")
        if _NAME.fullmatch(token):
            try:
                return self.parameters[token.lower()]
            except KeyError as exc:
                raise ValueError(f"unknown parameter {token!r}") from exc
        return parse_number(token)

    def _peek(self) -> str | None:
        return self.tokens[self.index] if self.index < len(self.tokens) else None

    def _take(self) -> str:
        if self.index >= len(self.tokens):
            raise ValueError("unexpected end of expression")
        token = self.tokens[self.index]
        self.index += 1
        return token


def evaluate_expression(
    expression: str,
    parameters: Mapping[str, Decimal] | None = None,
    *,
    max_tokens: int = 128,
    max_depth: int = 32,
    exact: bool = False,
) -> Decimal:
    """Evaluate the supported arithmetic subset with explicit resource limits."""

    if not isinstance(expression, str) or len(expression) > 16_384:
        raise ValueError("expression exceeds the 16384-character budget")
    if type(max_tokens) is not int or not 1 <= max_tokens <= 128:
        raise ValueError("token budget must be an integer between 1 and 128")
    if type(max_depth) is not int or not 1 <= max_depth <= 32:
        raise ValueError("depth budget must be an integer between 1 and 32")
    if type(exact) is not bool:
        raise ValueError("exact must be a bool")
    _validate_parameters(parameters)
    tokens = _expression_tokens(expression, max_tokens)
    return _ExpressionParser(tokens, parameters or {}, max_depth, exact).parse()


def _validate_parameters(parameters: Mapping[str, Decimal] | None) -> None:
    if parameters is None:
        return
    if not isinstance(parameters, Mapping) or len(parameters) > 128:
        raise ValueError("parameters must be a mapping of at most 128 values")
    for name, value in parameters.items():
        if not isinstance(name, str) or len(name) > 1_024 or _NAME.fullmatch(name) is None:
            raise ValueError("invalid expression parameter name")
        _supported(value)


def parameter_assignments(
    tokens: Sequence[str],
    inherited: Mapping[str, Decimal] | None = None,
    *,
    exact: bool = False,
) -> dict[str, Decimal]:
    """Evaluate ``name=value`` tokens from left to right."""

    if isinstance(tokens, str | bytes) or not isinstance(tokens, Sequence) or len(tokens) > 128:
        raise ValueError("parameter assignments require a sequence of at most 128 tokens")
    if type(exact) is not bool:
        raise ValueError("exact must be a bool")
    _validate_parameters(inherited)
    names = {name.lower() for name in inherited or {}}
    for token in tokens:
        name, _expression = parameter_assignment_parts(token)
        names.add(name.lower())
        if len(names) > 128:
            raise ValueError("parameter assignments support at most 128 distinct names")
    values = {name.lower(): value for name, value in (inherited or {}).items()}
    for token in tokens:
        name, expression = token.split("=", 1)
        values[name.lower()] = evaluate_expression(expression, values, exact=exact)
    return values


def parameter_assignment_parts(token: str) -> tuple[str, str]:
    """Validate declaration syntax without evaluating or consulting a scope."""
    if not isinstance(token, str) or len(token) > 17_409:
        raise ValueError("parameter assignment token must be bounded text")
    if "=" not in token:
        raise ValueError("parameter assignment requires name=value")
    name, expression = token.split("=", 1)
    if len(name) > 1_024 or _NAME.fullmatch(name) is None:
        raise InputError(f"invalid parameter name {name[:80]!r}")
    if not expression or len(expression) > 16_384:
        raise ValueError("parameter assignment expression must be bounded nonempty text")
    return name, expression


def decimal_text(value: Decimal) -> str:
    """Return a stable, non-exponential representation where practical."""

    _supported(value)
    if value == 0:
        return "0"
    rendered = format(value, "f")
    return rendered.rstrip("0").rstrip(".") if "." in rendered else rendered
