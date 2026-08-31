"""Location-preserving lexical utilities for a portable SPICE subset."""

from __future__ import annotations

from dataclasses import dataclass

from schematic_airlock.domain import SourceLocation, SyntaxFailure


@dataclass(frozen=True, slots=True)
class LogicalLine:
    path: str
    line: int
    text: str
    evidence: str

    @property
    def location(self) -> SourceLocation:
        return SourceLocation(self.path, self.line, 1)


@dataclass(frozen=True, slots=True)
class Token:
    value: str
    column: int


def _strip_comment(line: str, location: SourceLocation) -> str:
    quote: str | None = None
    brace_depth = 0
    for index, character in enumerate(line):
        if quote is not None:
            if character == quote:
                quote = None
            continue
        if character in {'"', "'"}:
            quote = character
        elif character == "{":
            brace_depth += 1
        elif character == "}":
            brace_depth -= 1
            if brace_depth < 0:
                raise SyntaxFailure("unexpected closing brace", location, line)
        elif character in {"$", ";"} and brace_depth == 0:
            return line[:index]
    if quote is not None:
        raise SyntaxFailure("unterminated quoted string", location, line)
    if brace_depth:
        raise SyntaxFailure("unterminated braced expression", location, line)
    return line


def logical_lines(
    text: str,
    path: str,
    *,
    max_physical_line: int = 16_384,
    max_logical_lines: int = 100_000,
) -> tuple[LogicalLine, ...]:
    """Remove comments and join ``+`` continuation lines."""

    result: list[LogicalLine] = []
    for line_number, physical in enumerate(text.splitlines(), start=1):
        if len(physical) > max_physical_line:
            location = SourceLocation(path, line_number, 1)
            raise SyntaxFailure(
                f"physical line exceeds {max_physical_line} characters", location, physical[:160]
            )
        stripped = physical.lstrip()
        if not stripped or stripped.startswith("*"):
            continue
        location = SourceLocation(path, line_number, len(physical) - len(stripped) + 1)
        content = _strip_comment(physical, location).strip()
        if not content:
            continue
        if content.startswith("+"):
            if not result:
                raise SyntaxFailure("continuation line has no predecessor", location, physical)
            previous = result[-1]
            continuation = content[1:].strip()
            result[-1] = LogicalLine(
                path=previous.path,
                line=previous.line,
                text=f"{previous.text} {continuation}".rstrip(),
                evidence=f"{previous.evidence}\n{physical}",
            )
        else:
            result.append(LogicalLine(path, line_number, content, physical))
            if len(result) > max_logical_lines:
                raise SyntaxFailure(
                    f"file exceeds {max_logical_lines} logical lines", location, physical
                )
    return tuple(result)


def tokenize(line: LogicalLine, *, max_tokens: int = 512) -> tuple[Token, ...]:
    """Split a logical line while preserving quotes and braced expressions."""

    tokens: list[Token] = []
    start: int | None = None
    quote: str | None = None
    brace_depth = 0
    characters: list[str] = []

    def flush() -> None:
        nonlocal start
        if start is not None:
            tokens.append(Token("".join(characters), start + 1))
            characters.clear()
            start = None
            if len(tokens) > max_tokens:
                raise SyntaxFailure(
                    f"logical line exceeds {max_tokens} tokens", line.location, line.evidence
                )

    for index, character in enumerate(line.text):
        if quote is not None:
            if character == quote:
                quote = None
            else:
                characters.append(character)
            continue
        if character in {'"', "'"}:
            if start is None:
                start = index
            quote = character
        elif character == "{":
            if start is None:
                start = index
            brace_depth += 1
            characters.append(character)
        elif character == "}":
            brace_depth -= 1
            characters.append(character)
        elif character.isspace() and brace_depth == 0:
            flush()
        else:
            if start is None:
                start = index
            characters.append(character)
    flush()
    return tuple(tokens)
