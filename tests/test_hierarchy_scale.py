from __future__ import annotations

import json
import runpy
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from schematic_airlock import AuditPolicy, Decision, audit_path

ROOT = Path(__file__).parents[1]
HARNESS = ROOT / "benchmarks" / "hierarchy_scale.py"
NATIVE_MEMORY_SUPPORTED = sys.platform == "win32" or sys.platform.startswith("linux")


@pytest.fixture(scope="module")
def harness() -> dict[str, Any]:
    return runpy.run_path(str(HARNESS))


def test_canonical_profile_has_independent_closed_form_counts(
    harness: dict[str, Any],
) -> None:
    counts = harness["closed_form_counts"](10, 6, 10)
    assert counts.as_dict() == {
        "resistors": 1_000_000,
        "subcircuit_calls": 111_111,
        "voltage_sources": 1,
        "expanded_instances": 1_111_112,
        "static_devices": 62,
        "subcircuits": 6,
        "static_nets": 14,
    }


def test_generated_source_stays_small_and_has_no_expanded_line_materialization(
    harness: dict[str, Any],
) -> None:
    deck = harness["hierarchy_deck"](10, 6, 10)
    assert len(deck.encode("utf-8")) < 2_000
    assert len(deck.splitlines()) == 74
    assert sum(line.startswith("R") for line in deck.splitlines()) == 10
    assert sum(line.startswith("X") for line in deck.splitlines()) == 51
    assert deck == harness["hierarchy_deck"](10, 6, 10)


def test_small_worker_runs_real_audit_path_and_checks_all_expected_facts(
    harness: dict[str, Any],
) -> None:
    result = harness["_worker_payload"](2, 3, 3)
    assert result["known_expected_passed"] is True
    assert result["closed_form"] == {
        "resistors": 12,
        "subcircuit_calls": 7,
        "voltage_sources": 1,
        "expanded_instances": 20,
        "static_devices": 9,
        "subcircuits": 3,
        "static_nets": 8,
    }
    assert result["observed"] == {
        "files": 1,
        "bytes": result["deck_bytes"],
        "static_devices": 9,
        "static_nets": 8,
        "subcircuits": 3,
        "expanded_instances": 20,
        "materialized_instances": 20,
        "materialized_element_families": {"R": 12, "V": 1, "X": 7},
        "static_element_families": [["R", 3], ["V", 1], ["X", 5]],
        "findings": 0,
        "decision": "allow",
    }


@pytest.mark.skipif(not NATIVE_MEMORY_SUPPORTED, reason="native RSS monitor supports Windows/Linux")
def test_public_run_uses_a_real_monitored_child(harness: dict[str, Any]) -> None:
    result = harness["run"](
        fanout=2,
        depth=2,
        leaf_primitives=2,
        timeout_seconds=30,
        rss_limit_bytes=512 * 1024**2,
    )
    assert result["known_expected_passed"] is True
    assert result["closed_form"]["expanded_instances"] == 8
    measurement = result["measurement"]
    assert measurement["peak_resident_bytes"] > 0
    assert measurement["peak_resident_bytes"] < measurement["rss_limit_bytes"]
    expected_metric = "PeakWorkingSetSize" if sys.platform == "win32" else "VmHWM"
    assert measurement["memory_metric"] == expected_metric
    assert Path(measurement["worker_executable"]) == Path(sys._base_executable).resolve()


def test_parent_rejects_forged_materialization_evidence(harness: dict[str, Any]) -> None:
    result = harness["_worker_payload"](2, 2, 2)
    observed = dict(result["observed"])
    observed["materialized_instances"] = observed["expanded_instances"] - 1
    result["observed"] = observed
    with pytest.raises(harness["HierarchyScaleError"], match="observations"):
        harness["_validate_worker_payload"](
            result,
            fanout=2,
            depth=2,
            leaf_primitives=2,
        )


def test_internal_worker_cannot_be_started_without_parent_token() -> None:
    result = subprocess.run(
        [sys.executable, "-I", str(HARNESS), "--worker", "--depth", "1"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode != 0
    assert "must be launched by the monitored parent" in result.stderr


class _FakeProcess:
    pid = 123

    def __init__(self) -> None:
        self.terminated = False

    def poll(self) -> None:
        return None

    def terminate(self) -> None:
        self.terminated = True

    def wait(self, timeout: int) -> int:
        assert timeout == 5
        return -1

    def kill(self) -> None:
        raise AssertionError("cooperative fake process should not need kill")

    def communicate(self, timeout: int | None = None) -> tuple[str, str]:
        assert timeout in {None, 5}
        return "", ""


def test_monitor_stops_at_equal_resident_limit(harness: dict[str, Any]) -> None:
    process = _FakeProcess()
    # Some Windows samples briefly expose current WorkingSet above the
    # PeakWorkingSet field; current RSS remains a valid lower bound on peak.
    sample = harness["MemorySample"](100, 99, "test-peak")
    with pytest.raises(harness["HierarchyScaleLimitError"], match="resident-memory limit"):
        harness["_monitor_process"](
            process,
            timeout_seconds=180,
            rss_limit_bytes=100,
            memory_reader=lambda _pid: sample,
            clock=lambda: 0.0,
            sleeper=lambda _seconds: None,
        )
    assert process.terminated


def test_monitor_stops_at_wall_time_limit(harness: dict[str, Any]) -> None:
    process = _FakeProcess()
    clock_values = iter((0.0, 180.0))
    sample = harness["MemorySample"](1, 1, "test-peak")
    with pytest.raises(harness["HierarchyScaleLimitError"], match="wall-time limit"):
        harness["_monitor_process"](
            process,
            timeout_seconds=180,
            rss_limit_bytes=100,
            memory_reader=lambda _pid: sample,
            clock=lambda: next(clock_values),
            sleeper=lambda _seconds: None,
        )
    assert process.terminated


def test_monitor_terminates_worker_when_memory_reader_fails(harness: dict[str, Any]) -> None:
    process = _FakeProcess()

    def fail(_pid: int) -> None:
        raise OSError("counter unavailable")

    with pytest.raises(OSError, match="counter unavailable"):
        harness["_monitor_process"](
            process,
            timeout_seconds=180,
            rss_limit_bytes=100,
            memory_reader=fail,
            clock=lambda: 0.0,
            sleeper=lambda _seconds: None,
        )
    assert process.terminated


@pytest.mark.parametrize(
    ("arguments", "match"),
    [
        ({"fanout": True}, "fanout"),
        ({"fanout": 0}, "fanout"),
        ({"depth": 0}, "depth"),
        ({"depth": 9}, "depth"),
        ({"leaf_primitives": 0}, "leaf primitives"),
        ({"fanout": 100, "depth": 8, "leaf_primitives": 1_000}, "ceiling"),
        ({"timeout_seconds": True}, "timeout seconds"),
        ({"timeout_seconds": 181}, "timeout seconds"),
        ({"rss_limit_bytes": 0}, "RSS limit bytes"),
        ({"rss_limit_bytes": 3 * 1024**3 + 1}, "RSS limit bytes"),
    ],
)
def test_public_run_rejects_unbounded_or_ambiguous_inputs(
    harness: dict[str, Any], arguments: dict[str, object], match: str
) -> None:
    with pytest.raises(ValueError, match=match):
        harness["run"](**arguments)


def test_mixed_primitive_smoke_runs_the_complete_audit(tmp_path: Path) -> None:
    deck = tmp_path / "mixed.sp"
    deck.write_text(
        "V1 vdd 0 1\n"
        "Xroot vdd 0 leaf\n"
        ".subckt leaf p n\n"
        "R1 p n 1k\n"
        "C1 p n 1p\n"
        "M1 p p n n nch\n"
        ".ends\n",
        encoding="utf-8",
    )
    policy = AuditPolicy.from_mapping({"limits": {"max_expanded_instances": 5}})
    report = audit_path(deck, policy=policy)
    assert report.decision is Decision.ALLOW
    assert report.findings == ()
    assert report.stats.expanded_instances == 5
    assert dict(report.structure.element_families) == {"C": 1, "M": 1, "R": 1, "V": 1, "X": 1}


@pytest.mark.skipif(not NATIVE_MEMORY_SUPPORTED, reason="native RSS monitor supports Windows/Linux")
def test_cli_returns_one_valid_json_document(harness: dict[str, Any]) -> None:
    completed = subprocess.run(
        [
            sys.executable,
            "-I",
            str(HARNESS),
            "--fanout",
            "2",
            "--depth",
            "2",
            "--leaf-primitives",
            "2",
            "--timeout-seconds",
            "30",
            "--rss-limit-mib",
            "512",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=40,
        check=True,
    )
    parsed = json.loads(completed.stdout)
    assert parsed["schema"] == "org.schematic-airlock.hierarchy-scale-benchmark"
    assert parsed["known_expected_passed"] is True
    assert not completed.stderr
