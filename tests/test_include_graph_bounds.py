from __future__ import annotations

from pathlib import Path

from schematic_airlock.bundle import ArtifactBundle
from schematic_airlock.include_graph import load_include_graph


def _write_repeated_chain(root: Path, depth: int) -> ArtifactBundle:
    for index in range(depth):
        (root / f"f{index}.sp").write_text(
            f".include f{index + 1}.sp\n.include f{index + 1}.sp\n",
            encoding="utf-8",
        )
    (root / f"f{depth}.sp").write_text("R1 a 0 1\n", encoding="utf-8")
    return ArtifactBundle.open(root, entry="f0.sp")


def test_repeated_include_dag_is_reported_without_exponential_reexpansion(tmp_path: Path) -> None:
    depth = 8
    graph = load_include_graph(_write_repeated_chain(tmp_path, depth))

    assert len(graph.decks) == depth + 1
    assert len(graph.edges) == 2 * depth
    assert [issue.code for issue in graph.issues] == ["INCL003"] * depth


def test_repeat_short_circuit_does_not_hide_an_active_include_cycle(tmp_path: Path) -> None:
    (tmp_path / "a.sp").write_text(".include b.sp\n", encoding="utf-8")
    (tmp_path / "b.sp").write_text(".include a.sp\n", encoding="utf-8")

    graph = load_include_graph(ArtifactBundle.open(tmp_path, entry="a.sp"))

    assert [issue.code for issue in graph.issues] == ["INCL001"]
    assert [(edge.source, edge.target) for edge in graph.edges] == [
        ("a.sp", "b.sp"),
        ("b.sp", "a.sp"),
    ]


def test_unique_include_chain_is_still_fully_loaded(tmp_path: Path) -> None:
    (tmp_path / "a.sp").write_text(".include b.sp\n", encoding="utf-8")
    (tmp_path / "b.sp").write_text(".include c.sp\n", encoding="utf-8")
    (tmp_path / "c.sp").write_text("R1 a 0 1\n", encoding="utf-8")

    graph = load_include_graph(ArtifactBundle.open(tmp_path, entry="a.sp"))

    assert tuple(deck.path for deck in graph.decks) == ("a.sp", "b.sp", "c.sp")
    assert not graph.issues
