"""Versioned, explicit voltage-envelope assumptions and terminal ratings."""

from __future__ import annotations

import json
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any

from schematic_airlock._strict_json import load_strict_json, load_strict_json_path
from schematic_airlock.voltage_constraints import (
    DEFAULT_VOLTAGE_LIMITS,
    VoltageConstraintError,
    VoltageInterval,
    VoltageLimits,
    volts,
)

MOS_PAIRS = {"gs": (1, 2), "gd": (1, 0), "gb": (1, 3), "ds": (0, 2), "bs": (3, 2), "bd": (3, 0)}
DIODE_PAIRS = {"ak": (0, 1)}


@dataclass(frozen=True, slots=True)
class ExpectedVoltage:
    name: str
    positive: str
    negative: str
    interval: VoltageInterval


@dataclass(frozen=True, slots=True)
class ModelVoltageRating:
    model: str
    kind: str
    pairs: tuple[tuple[str, VoltageInterval], ...]


@dataclass(frozen=True, slots=True)
class VoltageRules:
    """Validated rules; public entry points revalidate even direct construction."""

    net_envelopes: tuple[tuple[str, VoltageInterval], ...] = ()
    source_envelopes: tuple[tuple[str, VoltageInterval], ...] = ()
    expected: tuple[ExpectedVoltage, ...] = ()
    models: tuple[ModelVoltageRating, ...] = ()
    limits: VoltageLimits = DEFAULT_VOLTAGE_LIMITS

    def as_dict(self) -> dict[str, object]:
        def interval(value: VoltageInterval) -> dict[str, str]:
            # Input endpoints are finite decimal rationals, so the original
            # exact value has a finite decimal representation as well.
            return {"min": _decimal(value.lower), "max": _decimal(value.upper)}

        return {
            "schema": "org.schematic-airlock.voltage-rules",
            "version": 1,
            "net_envelopes": {name: interval(value) for name, value in self.net_envelopes},
            "source_envelopes": {name: interval(value) for name, value in self.source_envelopes},
            "expected": [
                {
                    "name": item.name,
                    "positive": item.positive,
                    "negative": item.negative,
                    **interval(item.interval),
                }
                for item in self.expected
            ],
            "models": {
                item.model: {
                    "kind": item.kind,
                    "limits": {pair: interval(value) for pair, value in item.pairs},
                }
                for item in self.models
            },
            "limits": {
                "max_nodes": self.limits.max_nodes,
                "max_constraints": self.limits.max_constraints,
                "max_edge_visits": self.limits.max_edge_visits,
                "max_queries": self.limits.max_queries,
            },
        }

    def fingerprint(self) -> str:
        return sha256(
            json.dumps(self.as_dict(), sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()


def _decimal(value: object) -> str:
    from fractions import Fraction

    if not isinstance(value, Fraction):
        raise VoltageConstraintError("rules require finite exact voltage endpoints")
    numerator, denominator = value.numerator, value.denominator
    twos = fives = 0
    while denominator % 2 == 0:
        denominator //= 2
        twos += 1
    while denominator % 5 == 0:
        denominator //= 5
        fives += 1
    if denominator != 1 or max(twos, fives) > 100:
        raise VoltageConstraintError(
            "rule endpoint requires a finite bounded decimal representation"
        )
    places = max(twos, fives)
    integer = numerator * 2 ** (places - twos) * 5 ** (places - fives)
    sign = "-" if integer < 0 else ""
    digits = str(abs(integer)).zfill(places + 1)
    return f"{sign}{digits[:-places]}.{digits[-places:]}" if places else f"{sign}{digits}"


def _object(value: object, allowed: set[str], location: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise VoltageConstraintError(f"{location} must be an object with string keys")
    if set(value) - allowed:
        raise VoltageConstraintError(f"{location} contains unknown fields")
    return value


def _identifier(value: object, location: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 1_024
        or unicodedata.normalize("NFC", value) != value
        or any(
            char.isspace() or unicodedata.category(char) in {"Cc", "Cf", "Cs", "Zl", "Zp"}
            for char in value
        )
    ):
        raise VoltageConstraintError(f"{location} must be a nonblank bounded name")
    folded = value.casefold()
    if unicodedata.normalize("NFC", folded) != folded:
        raise VoltageConstraintError(f"{location} case folding produces a noncanonical name")
    return folded


def _interval(value: object, location: str) -> VoltageInterval:
    item = _object(value, {"min", "max"}, location)
    if set(item) != {"min", "max"}:
        raise VoltageConstraintError(f"{location} requires both min and max decimal strings")
    return VoltageInterval(volts(item["min"]), volts(item["max"]))


def _envelopes(value: object, location: str) -> tuple[tuple[str, VoltageInterval], ...]:
    if not isinstance(value, Mapping) or len(value) > 1_000:
        raise VoltageConstraintError(f"{location} must be an object of at most 1000 envelopes")
    result: dict[str, VoltageInterval] = {}
    for name, interval in value.items():
        normalized = _identifier(name, location)
        if normalized in result:
            raise VoltageConstraintError(f"{location} contains duplicate normalized names")
        result[normalized] = _interval(interval, f"{location}.{normalized}")
    return tuple(sorted(result.items()))


def voltage_rules_from_mapping(value: object) -> VoltageRules:
    item = _object(
        value,
        {"schema", "version", "net_envelopes", "source_envelopes", "expected", "models", "limits"},
        "voltage rules",
    )
    if (
        item.get("schema") != "org.schematic-airlock.voltage-rules"
        or type(item.get("version")) is not int
        or item["version"] != 1
    ):
        raise VoltageConstraintError(
            "voltage rules require schema org.schematic-airlock.voltage-rules version 1"
        )
    net_envelopes = _envelopes(item.get("net_envelopes", {}), "net_envelopes")
    source_envelopes = _envelopes(item.get("source_envelopes", {}), "source_envelopes")
    raw_expected = item.get("expected", [])
    if not isinstance(raw_expected, list) or len(raw_expected) > 1_000:
        raise VoltageConstraintError("expected must be an array of at most 1000 voltage checks")
    expected = []
    seen: set[str] = set()
    for raw in raw_expected:
        entry = _object(raw, {"name", "positive", "negative", "min", "max"}, "expected voltage")
        name = _identifier(entry.get("name"), "expected name")
        if name in seen:
            raise VoltageConstraintError("duplicate expected voltage name")
        seen.add(name)
        expected.append(
            ExpectedVoltage(
                name,
                _identifier(entry.get("positive"), "positive net"),
                _identifier(entry.get("negative"), "negative net"),
                _interval({"min": entry.get("min"), "max": entry.get("max")}, name),
            )
        )
    raw_models = item.get("models", {})
    if not isinstance(raw_models, Mapping) or len(raw_models) > 1_000:
        raise VoltageConstraintError("models must be an object of at most 1000 ratings")
    models = []
    seen.clear()
    for name, raw in raw_models.items():
        model = _identifier(name, "model")
        if model in seen:
            raise VoltageConstraintError("duplicate normalized model name")
        seen.add(model)
        entry = _object(raw, {"kind", "limits"}, model)
        kind = entry.get("kind")
        if kind not in ("M", "D"):
            raise VoltageConstraintError("voltage model kind must be M or D")
        pairs = MOS_PAIRS if kind == "M" else DIODE_PAIRS
        ratings = _object(entry.get("limits"), set(pairs), f"{model}.limits")
        if set(ratings) != set(pairs):
            raise VoltageConstraintError(f"{model} requires ratings for {', '.join(sorted(pairs))}")
        models.append(
            ModelVoltageRating(
                model,
                kind,
                tuple(
                    (pair, _interval(ratings[pair], f"{model}.{pair}")) for pair in sorted(pairs)
                ),
            )
        )
    raw_limits = _object(item.get("limits", {}), set(VoltageLimits.__dataclass_fields__), "limits")
    return VoltageRules(
        net_envelopes,
        source_envelopes,
        tuple(sorted(expected, key=lambda entry: entry.name)),
        tuple(sorted(models, key=lambda rating: rating.model)),
        VoltageLimits(**raw_limits),
    )


def load_voltage_rules(path: str | Path) -> VoltageRules:
    return voltage_rules_from_mapping(load_strict_json_path(path, context="voltage rules"))


def parse_voltage_rules(text: str) -> VoltageRules:
    return voltage_rules_from_mapping(load_strict_json(text, context="voltage rules"))
