"""Strictly validated policy configuration."""

from __future__ import annotations

import json
import math
import tomllib
from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
from hashlib import sha256
from pathlib import Path
from typing import Any

from schematic_airlock.domain import PolicyError, Severity


@dataclass(frozen=True, slots=True)
class Limits:
    max_files: int = 128
    max_total_bytes: int = 10_000_000
    max_file_bytes: int = 2_000_000
    max_include_depth: int = 16
    max_expanded_instances: int = 100_000
    max_analysis_points: int = 1_000_000
    max_pwl_points: int = 10_000


@dataclass(frozen=True, slots=True)
class ElectricalPolicy:
    required_ports: tuple[str, ...] = ()
    ground_nets: tuple[str, ...] = ("0", "gnd", "vss")
    power_nets: tuple[str, ...] = ("vcc", "vdd")
    max_abs_source_voltage: float = 20.0


@dataclass(frozen=True, slots=True)
class RulePolicy:
    unknown_directive: Severity = Severity.REVIEW
    unknown_element: Severity = Severity.REVIEW
    behavioral_source: Severity = Severity.DENY
    severity_overrides: Mapping[str, Severity] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class AuditPolicy:
    """All behavior that may vary between audit environments."""

    limits: Limits = field(default_factory=Limits)
    electrical: ElectricalPolicy = field(default_factory=ElectricalPolicy)
    rules: RulePolicy = field(default_factory=RulePolicy)

    @classmethod
    def from_toml(cls, path: str | Path) -> AuditPolicy:
        try:
            with Path(path).open("rb") as stream:
                data = tomllib.load(stream)
        except (OSError, tomllib.TOMLDecodeError) as exc:
            raise PolicyError(f"cannot load policy {path}: {exc}") from exc
        return cls.from_mapping(data)

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> AuditPolicy:
        _reject_unknown(value, {"schema_version", "limits", "electrical", "rules"}, "policy")
        schema_version = value.get("schema_version", 1)
        if (
            isinstance(schema_version, bool)
            or not isinstance(schema_version, int)
            or schema_version != 1
        ):
            raise PolicyError("policy schema_version must be 1")
        limits_data = _section(value, "limits")
        electrical_data = _section(value, "electrical")
        rules_data = _section(value, "rules")
        _reject_unknown(limits_data, set(Limits.__dataclass_fields__), "limits")
        _reject_unknown(electrical_data, set(ElectricalPolicy.__dataclass_fields__), "electrical")
        _reject_unknown(
            rules_data,
            {"unknown_directive", "unknown_element", "behavioral_source", "severity_overrides"},
            "rules",
        )

        try:
            converted_limits: dict[str, int] = {}
            for key, item in limits_data.items():
                if isinstance(item, bool) or not isinstance(item, int):
                    raise PolicyError(f"limits.{key} must be a positive integer")
                converted_limits[key] = item
            limits = Limits(**converted_limits)
            electrical_values = dict(electrical_data)
            for key in ("required_ports", "ground_nets", "power_nets"):
                if key in electrical_values:
                    electrical_values[key] = _string_tuple(
                        electrical_values[key], f"electrical.{key}"
                    )
            if "max_abs_source_voltage" in electrical_values:
                raw_voltage = electrical_values["max_abs_source_voltage"]
                if isinstance(raw_voltage, bool) or not isinstance(raw_voltage, int | float):
                    raise PolicyError("max_abs_source_voltage must be a positive finite number")
                electrical_values["max_abs_source_voltage"] = float(raw_voltage)
            electrical = ElectricalPolicy(**electrical_values)

            overrides_raw = rules_data.get("severity_overrides", {})
            if not isinstance(overrides_raw, Mapping):
                raise PolicyError("rules.severity_overrides must be a table")
            _require_string_keys(overrides_raw, "rules.severity_overrides")
            if any(not code for code in overrides_raw):
                raise PolicyError("severity override codes must be non-empty strings")
            normalized_codes = [code.upper() for code in overrides_raw]
            if len(normalized_codes) != len(set(normalized_codes)):
                raise PolicyError("severity override codes must be unique case-insensitively")
            overrides = {
                code.upper(): _severity(item, f"severity override {code}")
                for code, item in overrides_raw.items()
            }
            rules = RulePolicy(
                unknown_directive=_severity(
                    rules_data.get("unknown_directive", Severity.REVIEW), "unknown_directive"
                ),
                unknown_element=_severity(
                    rules_data.get("unknown_element", Severity.REVIEW), "unknown_element"
                ),
                behavioral_source=_severity(
                    rules_data.get("behavioral_source", Severity.DENY), "behavioral_source"
                ),
                severity_overrides=overrides,
            )
        except (TypeError, ValueError, OverflowError) as exc:
            if isinstance(exc, PolicyError):
                raise
            raise PolicyError(f"invalid policy value: {exc}") from exc

        policy = cls(limits, electrical, rules)
        policy.validate()
        return policy

    def validate(self) -> None:
        for name, value in asdict(self.limits).items():
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise PolicyError(f"limits.{name} must be a positive integer")
        if self.limits.max_file_bytes > self.limits.max_total_bytes:
            raise PolicyError("max_file_bytes cannot exceed max_total_bytes")
        if not math.isfinite(self.electrical.max_abs_source_voltage) or (
            self.electrical.max_abs_source_voltage <= 0
        ):
            raise PolicyError("max_abs_source_voltage must be positive and finite")
        ground = {item.lower() for item in self.electrical.ground_nets} | {"0"}
        power = {item.lower() for item in self.electrical.power_nets}
        if ground & power:
            raise PolicyError("ground_nets and power_nets must not overlap")

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "limits": asdict(self.limits),
            "electrical": {
                "required_ports": list(self.electrical.required_ports),
                "ground_nets": list(self.electrical.ground_nets),
                "power_nets": list(self.electrical.power_nets),
                "max_abs_source_voltage": self.electrical.max_abs_source_voltage,
            },
            "rules": {
                "unknown_directive": self.rules.unknown_directive.value,
                "unknown_element": self.rules.unknown_element.value,
                "behavioral_source": self.rules.behavioral_source.value,
                "severity_overrides": {
                    code: severity.value
                    for code, severity in sorted(self.rules.severity_overrides.items())
                },
            },
        }

    def fingerprint(self) -> str:
        payload = json.dumps(self.as_dict(), sort_keys=True, separators=(",", ":")).encode()
        return sha256(payload).hexdigest()

    def severity_for(self, code: str, default: Severity) -> Severity:
        return self.rules.severity_overrides.get(code.upper(), default)


def _section(value: Mapping[str, Any], name: str) -> Mapping[str, Any]:
    section = value.get(name, {})
    if not isinstance(section, Mapping):
        raise PolicyError(f"policy {name} must be a table")
    return section


def _reject_unknown(value: Mapping[str, Any], allowed: set[str], context: str) -> None:
    _require_string_keys(value, context)
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise PolicyError(f"unknown {context} fields: {', '.join(unknown)}")


def _require_string_keys(value: Mapping[str, Any], context: str) -> None:
    if not all(isinstance(key, str) for key in value):
        raise PolicyError(f"{context} field names must be strings")


def _severity(value: object, context: str) -> Severity:
    try:
        return value if isinstance(value, Severity) else Severity(str(value).lower())
    except ValueError as exc:
        raise PolicyError(f"{context} must be info, review, or deny") from exc


def _string_tuple(value: object, context: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise PolicyError(f"{context} must be an array of non-empty strings")
    return tuple(value)


def load_policy(policy: AuditPolicy | str | Path | None) -> AuditPolicy:
    if policy is None:
        return AuditPolicy()
    if isinstance(policy, AuditPolicy):
        policy.validate()
        return policy
    return AuditPolicy.from_toml(policy)
