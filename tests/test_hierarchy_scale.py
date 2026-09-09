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


@pytest.mark.parametrize("state", ["R (running)", "Z (zombie)", "X (dead)"])
def test_linux_memory_reader_leaves_exit_confirmation_to_the_monitor(
    harness: dict[str, Any], monkeypatch: pytest.MonkeyPatch, state: str
) -> None:
    # Linux may release the address space before publishing a zombie state.
    monkeypatch.setattr(Path, "read_text", lambda *_args, **_kwargs: f"State:\t{state}\n")
    assert harness["_linux_process_memory"](123) is None


class _ClosingProcess:
    pid = 123

    def __init__(self, *, exits: bool) -> None:
        self.exits = exits
        self.returncode: int | None = None
        self.terminated = False
        self.wait_timeouts: list[float] = []

    def poll(self) -> int | None:
        return self.returncode

    def wait(self, timeout: float) -> int:
        self.wait_timeouts.append(timeout)
        if self.exits or self.terminated:
            self.returncode = 0 if self.exits else -1
            return self.returncode
        raise subprocess.TimeoutExpired("still-live-worker", timeout)

    def terminate(self) -> None:
        self.terminated = True

    def communicate(self, timeout: float | None = None) -> tuple[str, str]:
        assert self.returncode is not None
        return "payload", ""


def test_monitor_confirms_exit_after_linux_tears_down_memory_before_wait_status(
    harness: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    process = _ClosingProcess(exits=True)
    samples = iter((harness["MemorySample"](80, 90, "VmHWM"), None))
    monkeypatch.setattr(Path, "read_text", lambda *_args, **_kwargs: "State:\tR (running)\n")

    def memory_reader(pid: int) -> Any:
        sample = next(samples)
        return sample if sample is not None else harness["_linux_process_memory"](pid)

    result = harness["_monitor_process"](
        process,
        timeout_seconds=180,
        rss_limit_bytes=100,
        memory_reader=memory_reader,
        clock=lambda: 0.0,
        sleeper=lambda _seconds: None,
    )
    assert result.return_code == 0
    assert result.peak_resident_bytes == 90
    assert result.memory_metric == "VmHWM"
    assert result.stdout == "payload"
    assert process.wait_timeouts == [harness["_POLL_SECONDS"]]
    assert not process.terminated


def test_missing_memory_cannot_extend_live_worker_past_one_exit_confirmation(
    harness: dict[str, Any],
) -> None:
    process = _ClosingProcess(exits=False)
    samples = iter((harness["MemorySample"](80, 90, "VmHWM"), None))
    with pytest.raises(harness["HierarchyScaleError"], match="live worker"):
        harness["_monitor_process"](
            process,
            timeout_seconds=180,
            rss_limit_bytes=100,
            memory_reader=lambda _pid: next(samples),
            clock=lambda: 0.0,
            sleeper=lambda _seconds: None,
        )
    assert process.terminated
    assert process.wait_timeouts == [harness["_POLL_SECONDS"], 5]


def test_missing_memory_without_a_previous_sample_never_gets_exit_grace(
    harness: dict[str, Any],
) -> None:
    process = _ClosingProcess(exits=False)
    with pytest.raises(harness["HierarchyScaleError"], match="live worker"):
        harness["_monitor_process"](
            process,
            timeout_seconds=180,
            rss_limit_bytes=100,
            memory_reader=lambda _pid: None,
            clock=lambda: 0.0,
            sleeper=lambda _seconds: None,
        )
    assert process.terminated
    assert process.wait_timeouts == [5]


def test_exit_confirmation_is_clipped_to_remaining_wall_time(harness: dict[str, Any]) -> None:
    process = _ClosingProcess(exits=True)
    samples = iter((harness["MemorySample"](80, 90, "VmHWM"), None))
    times = iter((0.0, 0.0, 179.995, 179.997, 179.998))
    result = harness["_monitor_process"](
        process,
        timeout_seconds=180,
        rss_limit_bytes=100,
        memory_reader=lambda _pid: next(samples),
        clock=lambda: next(times),
        sleeper=lambda _seconds: None,
    )
    assert result.return_code == 0
    assert process.wait_timeouts == [pytest.approx(0.005)]
    assert result.wall_ms == pytest.approx(179_998)


@pytest.mark.parametrize("expires_before_wait", [True, False])
def test_exit_confirmation_cannot_accept_an_expired_wall_deadline(
    harness: dict[str, Any], expires_before_wait: bool
) -> None:
    process = _ClosingProcess(exits=True)
    samples = iter((harness["MemorySample"](80, 90, "VmHWM"), None))
    times = iter((0.0, 0.0, 180.0) if expires_before_wait else (0.0, 0.0, 179.995, 180.0))
    with pytest.raises(harness["HierarchyScaleLimitError"], match="wall-time limit"):
        harness["_monitor_process"](
            process,
            timeout_seconds=180,
            rss_limit_bytes=100,
            memory_reader=lambda _pid: next(samples),
            clock=lambda: next(times),
            sleeper=lambda _seconds: None,
        )
    if expires_before_wait:
        assert process.terminated
        assert process.wait_timeouts == [5]
    else:
        assert not process.terminated
        assert process.wait_timeouts == [pytest.approx(0.005)]


def test_malformed_linux_memory_field_remains_an_error(
    harness: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(Path, "read_text", lambda *_args, **_kwargs: "VmRSS:\t1 MB\n")
    with pytest.raises(harness["HierarchyScaleError"], match="unexpected /proc memory field"):
        harness["_linux_process_memory"](123)


@pytest.mark.parametrize("expires_after_collection", [True, False])
def test_ordinary_exit_cannot_return_at_or_after_wall_limit(
    harness: dict[str, Any], expires_after_collection: bool
) -> None:
    process = _ClosingProcess(exits=True)
    process.returncode = 0
    times = iter((0.0, 179.99, 180.0) if expires_after_collection else (0.0, 180.0))
    with pytest.raises(harness["HierarchyScaleLimitError"], match="wall-time limit"):
        harness["_monitor_process"](
            process,
            timeout_seconds=180,
            rss_limit_bytes=100,
            memory_reader=lambda _pid: harness["MemorySample"](80, 90, "VmHWM"),
            clock=lambda: next(times),
            sleeper=lambda _seconds: None,
        )
    assert not process.terminated
    assert process.wait_timeouts == []


def test_ordinary_exit_within_wall_limit_keeps_its_observed_peak(harness: dict[str, Any]) -> None:
    process = _ClosingProcess(exits=True)
    process.returncode = 0
    times = iter((0.0, 179.9, 179.95))
    result = harness["_monitor_process"](
        process,
        timeout_seconds=180,
        rss_limit_bytes=100,
        memory_reader=lambda _pid: harness["MemorySample"](80, 90, "VmHWM"),
        clock=lambda: next(times),
        sleeper=lambda _seconds: None,
    )
    assert result.return_code == 0
    assert result.wall_ms == pytest.approx(179_950)
    assert result.peak_resident_bytes == 90
    assert not process.terminated
    assert process.wait_timeouts == []


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
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    parsed = json.loads(completed.stdout)
    assert parsed["schema"] == "org.schematic-airlock.hierarchy-scale-benchmark"
    assert parsed["known_expected_passed"] is True
    assert not completed.stderr
