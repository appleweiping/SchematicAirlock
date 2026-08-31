"""Confinement and deterministic hashing for local artifact bundles."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path, PureWindowsPath
from typing import Protocol, runtime_checkable

from schematic_airlock._strict_json import load_strict_json
from schematic_airlock.domain import FileDigest, InputError

_NETLIST_EXTENSIONS = {".sp", ".spi", ".cir", ".ckt", ".net"}


@dataclass(frozen=True, slots=True)
class BundleLimits:
    max_files: int = 128
    max_total_bytes: int = 10_000_000
    max_file_bytes: int = 2_000_000


@runtime_checkable
class BundleSource(Protocol):
    entry: str
    manifest: dict[str, object]
    root_display: str

    def read_text(self, relative: str) -> str: ...

    def resolve_reference(self, source: str, target: str) -> str: ...

    def digests(self) -> tuple[FileDigest, ...]: ...

    def bundle_hash(self) -> str: ...


class ArtifactBundle:
    """A lazily read directory whose references cannot escape its root."""

    def __init__(self, root: Path, entry: str, limits: BundleLimits) -> None:
        self.root = root.resolve(strict=True)
        self.root_display = str(self.root)
        self.entry = entry
        self.limits = limits
        self.manifest: dict[str, object] = {}
        self._texts: dict[str, str] = {}
        self._digests: dict[str, FileDigest] = {}
        self._total_bytes = 0

    @classmethod
    def open(
        cls,
        path: str | Path,
        *,
        entry: str | None = None,
        limits: BundleLimits | None = None,
    ) -> ArtifactBundle:
        candidate = Path(path)
        if not candidate.exists():
            raise InputError(f"artifact path does not exist: {candidate}")
        limits = limits or BundleLimits()
        if candidate.is_file():
            bundle = cls(candidate.parent, candidate.name, limits)
            bundle.entry = bundle._canonical_existing(candidate)
            return bundle
        if not candidate.is_dir():
            raise InputError(f"artifact path is neither a regular file nor directory: {candidate}")

        bundle = cls(candidate, entry or "", limits)
        manifest_path = bundle.root / "manifest.json"
        if manifest_path.exists():
            manifest_text = bundle.read_text("manifest.json")
            manifest = load_strict_json(manifest_text, context="manifest JSON")
            bundle.manifest = _validate_manifest(manifest)
        manifest_entry = bundle.manifest.get("entry")
        selected = entry or (manifest_entry if isinstance(manifest_entry, str) else None)
        if selected is None:
            netlists = sorted(
                item.name
                for item in bundle.root.iterdir()
                if item.is_file() and item.suffix.lower() in _NETLIST_EXTENSIONS
            )
            if len(netlists) != 1:
                raise InputError(
                    "directory audits need --entry or manifest.json when there is not exactly "
                    "one top-level netlist"
                )
            selected = netlists[0]
        bundle.entry = bundle._canonical_existing(bundle.root / selected)
        return bundle

    def _canonical_existing(self, candidate: Path) -> str:
        try:
            resolved = candidate.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise InputError(f"referenced file cannot be resolved: {candidate}") from exc
        if not resolved.is_relative_to(self.root):
            raise InputError(f"path escapes the artifact root: {candidate}")
        if not resolved.is_file():
            raise InputError(f"referenced path is not a regular file: {candidate}")
        return resolved.relative_to(self.root).as_posix()

    def read_text(self, relative: str) -> str:
        canonical = self._canonical_existing(self.root / Path(relative))
        if canonical in self._texts:
            return self._texts[canonical]
        if len(self._texts) >= self.limits.max_files:
            raise InputError(f"bundle exceeds the {self.limits.max_files}-file read budget")
        path = self.root / canonical
        remaining_total = max(0, self.limits.max_total_bytes - self._total_bytes)
        read_budget = min(max(0, self.limits.max_file_bytes), remaining_total)
        try:
            with path.open("rb") as stream:
                data = stream.read(read_budget + 1)
        except OSError as exc:
            raise InputError(f"cannot read {canonical}: {exc}") from exc
        if len(data) > self.limits.max_file_bytes:
            raise InputError(
                f"{canonical} exceeds the {self.limits.max_file_bytes}-byte per-file budget"
            )
        if self._total_bytes + len(data) > self.limits.max_total_bytes:
            raise InputError(
                f"bundle exceeds the {self.limits.max_total_bytes}-byte total read budget"
            )
        if b"\0" in data:
            raise InputError(f"{canonical} contains NUL bytes and is not accepted as text")
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise InputError(f"{canonical} is not valid UTF-8") from exc
        digest = FileDigest(canonical, len(data), sha256(data).hexdigest())
        self._texts[canonical] = text
        self._digests[canonical] = digest
        self._total_bytes += len(data)
        return text

    def resolve_reference(self, source: str, target: str) -> str:
        if not target or "\0" in target or "://" in target:
            raise InputError(f"invalid include target {target!r}")
        if Path(target).is_absolute() or PureWindowsPath(target).is_absolute():
            raise InputError(f"absolute include target is outside the bundle contract: {target}")
        if ".." in Path(target).parts or ".." in PureWindowsPath(target).parts:
            raise InputError(f"include target escapes the artifact root: {target}")
        source_path = self.root / source
        try:
            return self._canonical_existing(source_path.parent / target)
        except InputError as exc:
            raise InputError(
                f"include target is unavailable within the artifact bundle: {target}"
            ) from exc

    def digests(self) -> tuple[FileDigest, ...]:
        return tuple(self._digests[path] for path in sorted(self._digests))

    def bundle_hash(self) -> str:
        digest = sha256()
        for item in self.digests():
            digest.update(item.path.encode())
            digest.update(b"\0")
            digest.update(str(item.size).encode())
            digest.update(b"\0")
            digest.update(item.sha256.encode())
            digest.update(b"\n")
        return digest.hexdigest()


class MemoryBundle:
    """Single-file bundle used by :func:`audit_text` without temporary files."""

    def __init__(self, text: str, virtual_name: str) -> None:
        if not virtual_name or any(mark in virtual_name for mark in ("/", "\\", "\0")):
            raise InputError("virtual_name must be one safe file name")
        data = text.encode("utf-8")
        self.entry = virtual_name
        self.root_display = "<memory>"
        self.manifest: dict[str, object] = {}
        self._text = text
        self._digest = FileDigest(virtual_name, len(data), sha256(data).hexdigest())

    def read_text(self, relative: str) -> str:
        if relative != self.entry:
            raise InputError(f"in-memory audit cannot open include target {relative!r}")
        return self._text

    def resolve_reference(self, source: str, target: str) -> str:
        raise InputError(f"in-memory audit cannot follow include target {target!r}")

    def digests(self) -> tuple[FileDigest, ...]:
        return (self._digest,)

    def bundle_hash(self) -> str:
        digest = sha256()
        digest.update(self._digest.path.encode())
        digest.update(b"\0")
        digest.update(str(self._digest.size).encode())
        digest.update(b"\0")
        digest.update(self._digest.sha256.encode())
        digest.update(b"\n")
        return digest.hexdigest()


def _validate_manifest(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise InputError("manifest.json must contain a JSON object")
    allowed = {"schema_version", "entry", "intended_ports", "description"}
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise InputError(f"manifest.json has unknown fields: {', '.join(unknown)}")
    if "schema_version" not in value:
        raise InputError("manifest.json schema_version is required")
    schema_version = value["schema_version"]
    if (
        isinstance(schema_version, bool)
        or not isinstance(schema_version, int)
        or schema_version != 1
    ):
        raise InputError("manifest.json schema_version must be 1")
    entry = value.get("entry")
    if entry is not None and (not isinstance(entry, str) or not entry.strip()):
        raise InputError("manifest entry must be a non-empty string")
    description = value.get("description")
    if description is not None and (not isinstance(description, str) or not description.strip()):
        raise InputError("manifest description must be a non-empty string")
    ports = value.get("intended_ports", {})
    if not isinstance(ports, dict):
        raise InputError("manifest intended_ports must be an object")
    valid_roles = {"input", "output", "inout", "supply", "ground", "bias"}
    for name, role in ports.items():
        if not isinstance(name, str) or not name:
            raise InputError("manifest port names must be non-empty strings")
        if role not in valid_roles:
            raise InputError(f"manifest port {name!r} has unsupported role {role!r}")
    folded_ports = [str(name).casefold() for name in ports]
    if len(folded_ports) != len(set(folded_ports)):
        raise InputError("manifest intended_ports contains case-insensitive duplicate names")
    return dict(value)
