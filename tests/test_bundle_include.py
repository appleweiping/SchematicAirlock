from __future__ import annotations

import json
from pathlib import Path

import pytest

from schematic_airlock.bundle import ArtifactBundle, BundleLimits, MemoryBundle
from schematic_airlock.domain import InputError
from schematic_airlock.include_graph import load_include_graph


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")


def test_open_single_file_reads_and_hashes_once(tmp_path: Path) -> None:
    source = tmp_path / "a.sp"
    write(source, "R1 a 0 1k\n")
    bundle = ArtifactBundle.open(source)
    assert bundle.entry == "a.sp"
    assert bundle.read_text("a.sp") == "R1 a 0 1k\n"
    assert bundle.read_text("a.sp") == "R1 a 0 1k\n"
    assert len(bundle.digests()) == 1
    assert bundle.digests()[0].size == len(b"R1 a 0 1k\n")
    assert len(bundle.bundle_hash()) == 64


def test_directory_uses_strict_manifest(tmp_path: Path) -> None:
    manifest = {
        "schema_version": 1,
        "entry": "nets/top.sp",
        "description": "fixture",
        "intended_ports": {"vdd": "supply", "0": "ground"},
    }
    write(tmp_path / "manifest.json", json.dumps(manifest))
    write(tmp_path / "nets" / "top.sp", "V1 vdd 0 1\n")
    bundle = ArtifactBundle.open(tmp_path)
    assert bundle.entry == "nets/top.sp"
    assert bundle.manifest == manifest
    assert {digest.path for digest in bundle.digests()} == {"manifest.json"}


def test_directory_infers_exactly_one_top_level_netlist(tmp_path: Path) -> None:
    write(tmp_path / "only.cir", "R1 a 0 1\n")
    write(tmp_path / "notes.txt", "not selected")
    assert ArtifactBundle.open(tmp_path).entry == "only.cir"
    write(tmp_path / "other.sp", "R2 b 0 2\n")
    with pytest.raises(InputError, match="exactly one"):
        ArtifactBundle.open(tmp_path)
    assert ArtifactBundle.open(tmp_path, entry="other.sp").entry == "other.sp"


@pytest.mark.parametrize(
    "manifest",
    [
        [],
        {"schema_version": 2, "entry": "a.sp"},
        {"schema_version": True, "entry": "a.sp"},
        {"entry": "a.sp"},
        {"entry": ""},
        {"schema_version": 1, "entry": "a.sp", "description": 7},
        {"entry": "a.sp", "unknown": True},
        {"entry": "a.sp", "intended_ports": []},
        {"entry": "a.sp", "intended_ports": {"": "input"}},
        {"entry": "a.sp", "intended_ports": {"x": "clock"}},
        {"entry": "a.sp", "intended_ports": {"VOUT": "output", "vout": "output"}},
    ],
)
def test_manifest_validation_rejects_ambiguous_contract(tmp_path: Path, manifest: object) -> None:
    write(tmp_path / "manifest.json", json.dumps(manifest))
    write(tmp_path / "a.sp", "R1 a 0 1\n")
    with pytest.raises(InputError):
        ArtifactBundle.open(tmp_path)


def test_invalid_manifest_json_is_input_error(tmp_path: Path) -> None:
    write(tmp_path / "manifest.json", "{")
    with pytest.raises(InputError, match="invalid manifest JSON"):
        ArtifactBundle.open(tmp_path)


def test_manifest_rejects_duplicate_and_nonfinite_json(tmp_path: Path) -> None:
    write(tmp_path / "a.sp", "R1 a 0 1\n")
    write(
        tmp_path / "manifest.json",
        '{"schema_version":1,"entry":"a.sp","entry":"other.sp"}',
    )
    with pytest.raises(InputError, match="duplicate"):
        ArtifactBundle.open(tmp_path)

    write(
        tmp_path / "manifest.json",
        '{"schema_version":1,"entry":"a.sp","description":NaN}',
    )
    with pytest.raises(InputError, match="non-finite"):
        ArtifactBundle.open(tmp_path)


def test_bundle_rejects_missing_root_and_non_file(tmp_path: Path) -> None:
    with pytest.raises(InputError, match="does not exist"):
        ArtifactBundle.open(tmp_path / "missing")
    with pytest.raises(InputError):
        ArtifactBundle.open(tmp_path, entry="missing.sp")


@pytest.mark.parametrize("target", ["/etc/passwd", "C:\\Windows\\win.ini", "https://x/a.lib", ""])
def test_reference_rejects_absolute_url_and_empty_targets(tmp_path: Path, target: str) -> None:
    write(tmp_path / "top.sp", "R1 a 0 1\n")
    bundle = ArtifactBundle.open(tmp_path / "top.sp")
    with pytest.raises(InputError):
        bundle.resolve_reference("top.sp", target)


def test_reference_cannot_escape_root(tmp_path: Path) -> None:
    root = tmp_path / "bundle"
    write(root / "top.sp", "R1 a 0 1\n")
    write(tmp_path / "secret.lib", "secret")
    bundle = ArtifactBundle.open(root / "top.sp")
    with pytest.raises(InputError, match="escapes"):
        bundle.resolve_reference("top.sp", "../secret.lib")


def test_bundle_rejects_nul_invalid_utf8_and_size_budgets(tmp_path: Path) -> None:
    (tmp_path / "nul.sp").write_bytes(b"R1\0a")
    with pytest.raises(InputError, match="NUL"):
        ArtifactBundle.open(tmp_path / "nul.sp").read_text("nul.sp")
    (tmp_path / "bad.sp").write_bytes(b"\xff")
    with pytest.raises(InputError, match="UTF-8"):
        ArtifactBundle.open(tmp_path / "bad.sp").read_text("bad.sp")
    write(tmp_path / "large.sp", "12345")
    limited = ArtifactBundle.open(tmp_path / "large.sp", limits=BundleLimits(1, 4, 4))
    with pytest.raises(InputError, match="per-file"):
        limited.read_text("large.sp")


def test_bundle_stops_reading_at_the_smallest_byte_budget(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "large.sp"
    source.write_bytes(b"x" * 100)
    requested_sizes: list[int] = []
    original_open = Path.open

    class TrackedReader:
        def __init__(self, stream: object) -> None:
            self.stream = stream

        def __enter__(self) -> TrackedReader:
            return self

        def __exit__(self, *args: object) -> None:
            self.stream.close()  # type: ignore[attr-defined]

        def read(self, size: int = -1) -> bytes:
            requested_sizes.append(size)
            return self.stream.read(size)  # type: ignore[attr-defined,no-any-return]

    def tracked_open(path: Path, *args: object, **kwargs: object) -> TrackedReader:
        return TrackedReader(original_open(path, *args, **kwargs))

    monkeypatch.setattr(Path, "open", tracked_open)
    bundle = ArtifactBundle.open(source, limits=BundleLimits(1, 50, 4))
    with pytest.raises(InputError, match="per-file"):
        bundle.read_text("large.sp")
    assert requested_sizes == [5]


def test_bundle_enforces_total_and_file_count_budgets(tmp_path: Path) -> None:
    write(tmp_path / "top.sp", ".include a.lib\n.include b.lib\n")
    write(tmp_path / "a.lib", "R1 a 0 1\n")
    write(tmp_path / "b.lib", "R2 b 0 2\n")
    count_limited = ArtifactBundle.open(
        tmp_path, entry="top.sp", limits=BundleLimits(1, 1000, 1000)
    )
    graph = load_include_graph(count_limited)
    assert any("file read budget" in issue.message for issue in graph.issues)
    total_limits = BundleLimits(10, 40, 1000)
    total_limited = ArtifactBundle.open(tmp_path, entry="top.sp", limits=total_limits)
    graph = load_include_graph(total_limited)
    assert any("total read budget" in issue.message for issue in graph.issues)


def test_include_graph_loads_relative_dag_once(tmp_path: Path) -> None:
    write(tmp_path / "top.sp", ".include lib/a.lib\n.include lib/b.lib\n")
    write(tmp_path / "lib" / "a.lib", ".include common.lib\nR1 a 0 1\n")
    write(tmp_path / "lib" / "b.lib", ".include common.lib\nR2 b 0 2\n")
    write(tmp_path / "lib" / "common.lib", "R3 c 0 3\n")
    graph = load_include_graph(ArtifactBundle.open(tmp_path, entry="top.sp"))
    assert [deck.path for deck in graph.decks] == [
        "lib/a.lib",
        "lib/b.lib",
        "lib/common.lib",
        "top.sp",
    ]
    assert len(graph.edges) == 4
    assert [issue.code for issue in graph.issues] == ["INCL003"]


def test_include_cycle_is_reported_not_followed_forever(tmp_path: Path) -> None:
    write(tmp_path / "a.sp", ".include b.sp\n")
    write(tmp_path / "b.sp", ".include a.sp\n")
    graph = load_include_graph(ArtifactBundle.open(tmp_path, entry="a.sp"))
    assert len(graph.decks) == 2
    assert [issue.code for issue in graph.issues] == ["INCL001"]


def test_include_depth_and_parse_failure_are_findings(tmp_path: Path) -> None:
    write(tmp_path / "a.sp", ".include b.sp\n")
    write(tmp_path / "b.sp", ".include c.sp\n")
    write(tmp_path / "c.sp", ".subckt broken x\n")
    depth = load_include_graph(ArtifactBundle.open(tmp_path, entry="a.sp"), max_depth=1)
    assert [issue.code for issue in depth.issues] == ["INCL002"]
    parsed = load_include_graph(ArtifactBundle.open(tmp_path, entry="a.sp"), max_depth=4)
    assert [issue.code for issue in parsed.issues] == ["PARSE001"]


def test_memory_bundle_refuses_ambient_includes() -> None:
    bundle = MemoryBundle(".include x.lib\n", "memory.sp")
    graph = load_include_graph(bundle)
    assert graph.decks[0].path == "memory.sp"
    assert [issue.code for issue in graph.issues] == ["PATH001"]
    assert bundle.digests()[0].path == "memory.sp"


def test_include_depth_is_checked_per_path_even_when_target_was_visited(tmp_path: Path) -> None:
    write(tmp_path / "top.sp", ".include common.lib\n.include a.lib\n")
    write(tmp_path / "a.lib", ".include b.lib\n")
    write(tmp_path / "b.lib", ".include common.lib\n")
    write(tmp_path / "common.lib", "R1 a 0 1\n")
    graph = load_include_graph(ArtifactBundle.open(tmp_path, entry="top.sp"), max_depth=2)
    assert "INCL002" in [issue.code for issue in graph.issues]


def test_missing_include_message_does_not_embed_checkout_path(tmp_path: Path) -> None:
    write(tmp_path / "top.sp", ".include missing.lib\n")
    issue = load_include_graph(ArtifactBundle.open(tmp_path, entry="top.sp")).issues[0]
    assert str(tmp_path) not in issue.message
    assert issue.location.path == "top.sp"


@pytest.mark.parametrize("name", ["", "../a.sp", "dir/a.sp", "C:\\a.sp", "nul\0.sp"])
def test_memory_bundle_requires_safe_virtual_name(name: str) -> None:
    with pytest.raises(InputError):
        MemoryBundle("", name)
