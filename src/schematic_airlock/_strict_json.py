"""Bounded, deterministic decoding for untrusted JSON documents."""

from __future__ import annotations

import json
import math
from collections.abc import Callable
from pathlib import Path
from typing import Any, Never

from schematic_airlock.domain import InputError

MAX_JSON_BYTES = 1_048_576
MAX_JSON_DEPTH = 64
MAX_JSON_NODES = 10_000
MAX_NUMBER_CHARACTERS = 128


def _object_pairs(context: str) -> Callable[[list[tuple[str, Any]]], dict[str, Any]]:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise InputError(f"{context} contains duplicate key {key!r}")
            result[key] = value
        return result

    return reject_duplicates


def _reject_constant(context: str) -> Callable[[str], Never]:
    def reject(token: str) -> Never:
        raise InputError(f"{context} contains non-finite number {token!r}")

    return reject


def _parse_int(context: str) -> Callable[[str], int]:
    def parse(token: str) -> int:
        if len(token) > MAX_NUMBER_CHARACTERS:
            raise InputError(f"{context} contains an oversized number")
        return int(token)

    return parse


def _parse_float(context: str) -> Callable[[str], float]:
    def parse(token: str) -> float:
        if len(token) > MAX_NUMBER_CHARACTERS:
            raise InputError(f"{context} contains an oversized number")
        value = float(token)
        if not math.isfinite(value):
            raise InputError(f"{context} contains a non-finite number")
        return value

    return parse


def _check_complexity(value: object, context: str) -> None:
    pending: list[tuple[object, int]] = [(value, 0)]
    nodes = 0
    while pending:
        item, depth = pending.pop()
        nodes += 1
        if depth > MAX_JSON_DEPTH or nodes > MAX_JSON_NODES:
            raise InputError(f"{context} exceeds complexity limits")
        if isinstance(item, dict):
            pending.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            pending.extend((child, depth + 1) for child in item)


def load_strict_json(text: str, *, context: str) -> object:
    """Decode one size- and complexity-bounded JSON document."""

    try:
        if len(text.encode("utf-8")) > MAX_JSON_BYTES:
            raise InputError(f"{context} exceeds {MAX_JSON_BYTES} byte input limit")
        value = json.loads(
            text,
            object_pairs_hook=_object_pairs(context),
            parse_constant=_reject_constant(context),
            parse_int=_parse_int(context),
            parse_float=_parse_float(context),
        )
    except InputError:
        raise
    except (RecursionError, OverflowError, UnicodeError, ValueError) as exc:
        raise InputError(f"invalid {context}: {exc}") from exc
    _check_complexity(value, context)
    return value


def load_strict_json_path(path: str | Path, *, context: str) -> object:
    """Read and decode one JSON file without first allocating an unbounded payload."""

    source = Path(path)
    try:
        with source.open("rb") as stream:
            payload = stream.read(MAX_JSON_BYTES + 1)
    except OSError as exc:
        raise InputError(f"cannot read {context} {source}: {exc}") from exc
    if len(payload) > MAX_JSON_BYTES:
        raise InputError(f"{context} exceeds {MAX_JSON_BYTES} byte input limit")
    try:
        text = payload.decode("utf-8")
    except UnicodeError as exc:
        raise InputError(f"invalid {context}: {exc}") from exc
    return load_strict_json(text, context=context)
