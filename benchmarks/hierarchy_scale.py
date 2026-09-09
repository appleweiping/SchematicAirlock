"""End-to-end bounded hierarchy-expansion benchmark through ``audit_path``.

The source deck stays small.  A closed-form fan-out hierarchy makes the audit
materialize and inspect many primitive and subcircuit-call instances.  A parent
process measures the operating-system resident high-water mark of the worker
and terminates it at the configured time or memory boundary.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import math
import os
import platform
import secrets
import subprocess
import sys
import sysconfig
import time
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
from importlib.metadata import version
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

import schematic_airlock
import schematic_airlock.engine as audit_engine
from schematic_airlock import AuditPolicy, Decision
from schematic_airlock.circuit_graph import CircuitGraph
from schematic_airlock.include_graph import IncludeGraph

_SCHEMA = "org.schematic-airlock.hierarchy-scale-benchmark"
_SCHEMA_VERSION = 1
_WORKER_ENV = "SCHEMATIC_AIRLOCK_HIERARCHY_BENCHMARK_WORKER"
_MAX_EXPANDED_INSTANCES = 1_500_000
_MAX_RSS_BYTES = 3 * 1024**3
_MAX_TIMEOUT_SECONDS = 180
_POLL_SECONDS = 0.01
_SCOPE = (
    "complete audit_path parse, hierarchy materialization, and all built-in rules for one "
    "synthetic grounded resistor hierarchy; not arbitrary million-node, nonlinear, simulator, "
    "PDK, or full-ERC performance; elapsed and RSS include one transparent post-build Counter "
    "scan that verifies the exact graph supplied to the rules"
)


class HierarchyScaleError(RuntimeError):
    """The benchmark input, worker result, or resource measurement is invalid."""


class HierarchyScaleLimitError(HierarchyScaleError):
    """The benchmark worker reached a fail-closed time or resident-memory limit."""


@dataclass(frozen=True, slots=True)
class HierarchyCounts:
    """Independent closed-form counts for one generated hierarchy."""

    resistors: int
    subcircuit_calls: int
    voltage_sources: int
    expanded_instances: int
    static_devices: int
    subcircuits: int
    static_nets: int

    def as_dict(self) -> dict[str, int]:
        return {
            "resistors": self.resistors,
            "subcircuit_calls": self.subcircuit_calls,
            "voltage_sources": self.voltage_sources,
            "expanded_instances": self.expanded_instances,
            "static_devices": self.static_devices,
            "subcircuits": self.subcircuits,
            "static_nets": self.static_nets,
        }


@dataclass(frozen=True, slots=True)
class MemorySample:
    """One operating-system measurement for the direct worker process."""

    resident_bytes: int
    peak_resident_bytes: int
    metric: str


@dataclass(frozen=True, slots=True)
class MonitorResult:
    """Completed worker output and its externally observed resource use."""

    stdout: str
    stderr: str
    return_code: int
    wall_ms: float
    peak_resident_bytes: int
    memory_metric: str


def _require_int(name: str, value: object, low: int, high: int) -> int:
    if type(value) is not int or not low <= value <= high:
        raise ValueError(f"{name} must be an integer in {low}..{high}")
    return value


def closed_form_counts(
    fanout: int = 10, depth: int = 6, leaf_primitives: int = 10
) -> HierarchyCounts:
    """Return exact counts without parsing or expanding the generated deck.

    ``depth`` counts the root call and every nested call level down to the leaf.
    The leaf has ``leaf_primitives`` resistors.  Thus the requested canonical
    profile (fanout 10, depth 6, ten leaf resistors) contains 1,000,000
    resistors, 111,111 calls, and one independent top-level voltage source.
    """

    fanout = _require_int("fanout", fanout, 1, 100)
    depth = _require_int("depth", depth, 1, 8)
    leaf_primitives = _require_int("leaf primitives", leaf_primitives, 1, 1_000)
    leaf_copies = fanout ** (depth - 1)
    resistors = leaf_primitives * leaf_copies
    calls = sum(fanout**level for level in range(depth))
    total = resistors + calls + 1
    if total > _MAX_EXPANDED_INSTANCES:
        raise ValueError(
            f"closed-form expansion {total} exceeds benchmark ceiling {_MAX_EXPANDED_INSTANCES}"
        )
    return HierarchyCounts(
        resistors=resistors,
        subcircuit_calls=calls,
        voltage_sources=1,
        expanded_instances=total,
        static_devices=leaf_primitives + 1 + fanout * (depth - 1) + 1,
        subcircuits=depth,
        static_nets=2 * (depth + 1),
    )


def hierarchy_deck(fanout: int = 10, depth: int = 6, leaf_primitives: int = 10) -> str:
    """Build the compact source deck for a validated closed-form workload."""

    closed_form_counts(fanout, depth, leaf_primitives)
    lines = ["V1 vdd 0 1", f"Xroot vdd 0 {'leaf' if depth == 1 else f'level{depth - 1}'}"]
    lines.extend((".subckt leaf p n",))
    lines.extend(f"R{index} p n 1k" for index in range(leaf_primitives))
    lines.append(".ends")
    for level in range(1, depth):
        child = "leaf" if level == 1 else f"level{level - 1}"
        lines.append(f".subckt level{level} p n")
        lines.extend(f"X{index} p n {child}" for index in range(fanout))
        lines.append(".ends")
    return "\n".join(lines) + "\n"


def _package_tree_sha256() -> str:
    if schematic_airlock.__file__ is None:
        raise HierarchyScaleError("cannot locate the imported schematic_airlock package")
    package_root = Path(schematic_airlock.__file__).resolve().parent
    digest = hashlib.sha256()
    for source in sorted(package_root.rglob("*.py")):
        relative = source.relative_to(package_root).as_posix().encode()
        content = source.read_bytes()
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest()


def _policy(counts: HierarchyCounts) -> AuditPolicy:
    return AuditPolicy.from_mapping(
        {"limits": {"max_expanded_instances": counts.expanded_instances}}
    )


def _worker_payload(fanout: int, depth: int, leaf_primitives: int) -> dict[str, object]:
    """Run the production audit in the monitored worker and check its oracle."""

    counts = closed_form_counts(fanout, depth, leaf_primitives)
    deck = hierarchy_deck(fanout, depth, leaf_primitives)
    deck_bytes = deck.encode("utf-8")
    policy = _policy(counts)
    materialized: dict[str, object] = {}
    original_build = audit_engine.build_circuit_graph

    def observed_build(
        includes: IncludeGraph, *, max_expanded_instances: int = 100_000
    ) -> CircuitGraph:
        if materialized:
            raise HierarchyScaleError("audit unexpectedly built more than one circuit graph")
        graph = original_build(includes, max_expanded_instances=max_expanded_instances)
        materialized["instances"] = len(graph.expanded_devices)
        materialized["families"] = dict(
            sorted(Counter(item.element.kind for item in graph.expanded_devices).items())
        )
        return graph

    started = time.perf_counter_ns()
    audit_engine.build_circuit_graph = observed_build
    try:
        with TemporaryDirectory(prefix="schematic-airlock-hierarchy-") as directory:
            deck_path = Path(directory, "hierarchy.sp")
            deck_path.write_text(deck, encoding="utf-8", newline="\n")
            report = audit_engine.audit_path(deck_path, policy=policy)
    finally:
        audit_engine.build_circuit_graph = original_build
    audit_elapsed_ms = (time.perf_counter_ns() - started) / 1_000_000

    expected_families = (
        ("R", leaf_primitives),
        ("V", 1),
        ("X", 1 + fanout * (depth - 1)),
    )
    observed = {
        "files": report.stats.files,
        "bytes": report.stats.bytes,
        "static_devices": report.stats.devices,
        "static_nets": report.stats.nets,
        "subcircuits": report.stats.subcircuits,
        "expanded_instances": report.stats.expanded_instances,
        "materialized_instances": materialized.get("instances"),
        "materialized_element_families": materialized.get("families"),
        "static_element_families": [list(item) for item in report.structure.element_families],
        "findings": len(report.findings),
        "decision": report.decision.value,
    }
    known_expected = (
        report.stats.files == 1
        and report.stats.bytes == len(deck_bytes)
        and report.stats.devices == counts.static_devices
        and report.stats.nets == counts.static_nets
        and report.stats.subcircuits == counts.subcircuits
        and report.stats.expanded_instances == counts.expanded_instances
        and materialized.get("instances") == counts.expanded_instances
        and materialized.get("families")
        == {
            "R": counts.resistors,
            "V": counts.voltage_sources,
            "X": counts.subcircuit_calls,
        }
        and report.structure.element_families == expected_families
        and not report.findings
        and report.decision is Decision.ALLOW
        and report.policy_sha256 == policy.fingerprint()
    )
    if not known_expected:
        raise HierarchyScaleError(f"end-to-end hierarchy oracle failed: {observed!r}")

    return {
        "schema": _SCHEMA,
        "version": _SCHEMA_VERSION,
        "tool_version": version("schematic-airlock"),
        "workload": {
            "fanout": fanout,
            "depth": depth,
            "leaf_primitives": leaf_primitives,
            "profile": "parallel-grounded-resistor-hierarchy",
        },
        "closed_form": counts.as_dict(),
        "observed": observed,
        "known_expected_passed": True,
        "audit_elapsed_ms": audit_elapsed_ms,
        "deck_bytes": len(deck_bytes),
        "deck_sha256": hashlib.sha256(deck_bytes).hexdigest(),
        "bundle_sha256": report.bundle_sha256,
        "policy_sha256": report.policy_sha256,
        "source_tree_sha256": _package_tree_sha256(),
        "harness_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "scope": _SCOPE,
    }


def _linux_process_memory(pid: int) -> MemorySample | None:
    status = Path("/proc", str(pid), "status")
    try:
        lines = status.read_text(encoding="ascii").splitlines()
    except FileNotFoundError:
        return None
    values: dict[str, int] = {}
    for line in lines:
        key, separator, remainder = line.partition(":")
        if separator and key in {"VmRSS", "VmHWM"}:
            fields = remainder.split()
            if len(fields) != 2 or fields[1] != "kB":
                raise HierarchyScaleError(f"unexpected /proc memory field: {line!r}")
            values[key] = int(fields[0]) * 1024
    if "VmRSS" not in values:
        # Linux can release a dying process's address space before publishing
        # its zombie state or wait status.  Missing fields are not proof of
        # exit; the parent must independently confirm it within a fixed bound.
        return None
    return MemorySample(values["VmRSS"], values.get("VmHWM", values["VmRSS"]), "VmHWM")


def _windows_process_memory(pid: int) -> MemorySample | None:
    from ctypes import wintypes

    class ProcessMemoryCounters(ctypes.Structure):
        _fields_ = [
            ("cb", wintypes.DWORD),
            ("PageFaultCount", wintypes.DWORD),
            ("PeakWorkingSetSize", ctypes.c_size_t),
            ("WorkingSetSize", ctypes.c_size_t),
            ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
            ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
            ("PagefileUsage", ctypes.c_size_t),
            ("PeakPagefileUsage", ctypes.c_size_t),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    psapi = ctypes.WinDLL("psapi", use_last_error=True)
    open_process = kernel32.OpenProcess
    open_process.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    open_process.restype = wintypes.HANDLE
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = (wintypes.HANDLE,)
    close_handle.restype = wintypes.BOOL
    get_memory = psapi.GetProcessMemoryInfo
    get_memory.argtypes = (
        wintypes.HANDLE,
        ctypes.POINTER(ProcessMemoryCounters),
        wintypes.DWORD,
    )
    get_memory.restype = wintypes.BOOL
    handle = open_process(0x0400 | 0x0010, False, pid)
    if not handle:
        return None
    try:
        counters = ProcessMemoryCounters()
        counters.cb = ctypes.sizeof(counters)
        if not get_memory(handle, ctypes.byref(counters), counters.cb):
            error = ctypes.get_last_error()
            raise HierarchyScaleError(f"GetProcessMemoryInfo failed with Windows error {error}")
        return MemorySample(
            int(counters.WorkingSetSize),
            max(int(counters.WorkingSetSize), int(counters.PeakWorkingSetSize)),
            "PeakWorkingSetSize",
        )
    finally:
        close_handle(handle)


def _process_memory(pid: int) -> MemorySample | None:
    if os.name == "nt":
        return _windows_process_memory(pid)
    if sys.platform.startswith("linux"):
        return _linux_process_memory(pid)
    raise HierarchyScaleError("resident-memory enforcement supports Windows and Linux only")


def _terminate_process(process: subprocess.Popen[str]) -> None:
    if process.poll() is None:
        try:
            process.terminate()
        except OSError:
            process.kill()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
    try:
        process.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)
        process.communicate()


def _monitor_process(
    process: subprocess.Popen[str],
    *,
    timeout_seconds: int,
    rss_limit_bytes: int,
    memory_reader: Callable[[int], MemorySample | None] = _process_memory,
    clock: Callable[[], float] = time.monotonic,
    sleeper: Callable[[float], None] = time.sleep,
) -> MonitorResult:
    started = clock()
    peak = 0
    metric = ""
    try:
        while True:
            # Read before poll(): on POSIX, poll() can reap an exited child and
            # remove its final /proc high-water evidence.  A zombie cannot have
            # its PID reused until the subsequent poll reaps it.
            sample = memory_reader(process.pid)
            return_code = process.poll()
            if sample is not None:
                if sample.resident_bytes < 0 or sample.peak_resident_bytes < 0:
                    raise HierarchyScaleError("operating-system memory counters are negative")
                # Windows can briefly publish a current working set before its
                # PeakWorkingSetSize field catches up.  Current RSS is itself a
                # lower bound on the peak, so never discard the larger value.
                observed_peak = max(sample.resident_bytes, sample.peak_resident_bytes)
                peak = max(peak, observed_peak)
                metric = sample.metric
                if observed_peak >= rss_limit_bytes:
                    raise HierarchyScaleLimitError(
                        f"worker reached resident-memory limit {rss_limit_bytes} bytes "
                        f"(observed {observed_peak})"
                    )
            elif return_code is None:
                if peak <= 0 or not metric:
                    raise HierarchyScaleError("could not read resident memory for the live worker")
                remaining = timeout_seconds - (clock() - started)
                if remaining <= 0:
                    raise HierarchyScaleLimitError(
                        f"worker reached wall-time limit {timeout_seconds} seconds"
                    )
                try:
                    # One non-renewable poll interval handles the Linux
                    # address-space teardown race.  It is allowed only after
                    # a valid sample and only if wait() actually confirms exit.
                    return_code = process.wait(timeout=min(_POLL_SECONDS, remaining))
                except subprocess.TimeoutExpired as exc:
                    raise HierarchyScaleError(
                        "could not read resident memory for the live worker"
                    ) from exc
            if clock() - started >= timeout_seconds:
                raise HierarchyScaleLimitError(
                    f"worker reached wall-time limit {timeout_seconds} seconds"
                )
            if return_code is not None:
                break
            sleeper(_POLL_SECONDS)
        stdout, stderr = process.communicate()
    except BaseException:
        # Measurement and validation are fail-closed: never leave a potentially
        # million-instance worker alive when the monitor itself cannot proceed.
        _terminate_process(process)
        raise
    elapsed_ms = (clock() - started) * 1_000
    if elapsed_ms >= timeout_seconds * 1_000:
        raise HierarchyScaleLimitError(f"worker reached wall-time limit {timeout_seconds} seconds")
    if peak <= 0 or not metric:
        raise HierarchyScaleError("worker finished without an operating-system peak RSS sample")
    return MonitorResult(stdout, stderr, return_code, elapsed_ms, peak, metric)


def _validate_worker_payload(
    value: object,
    *,
    fanout: int,
    depth: int,
    leaf_primitives: int,
) -> dict[str, object]:
    if not isinstance(value, dict):
        raise HierarchyScaleError("worker output must be one JSON object")
    counts = closed_form_counts(fanout, depth, leaf_primitives)
    deck = hierarchy_deck(fanout, depth, leaf_primitives).encode("utf-8")
    policy = _policy(counts)
    required = {
        "schema",
        "version",
        "tool_version",
        "workload",
        "closed_form",
        "observed",
        "known_expected_passed",
        "audit_elapsed_ms",
        "deck_bytes",
        "deck_sha256",
        "bundle_sha256",
        "policy_sha256",
        "source_tree_sha256",
        "harness_sha256",
        "scope",
    }
    if set(value) != required:
        raise HierarchyScaleError("worker output fields do not match the benchmark contract")
    if value["schema"] != _SCHEMA or value["version"] != _SCHEMA_VERSION:
        raise HierarchyScaleError("worker output has an unsupported benchmark schema")
    if value["tool_version"] != version("schematic-airlock"):
        raise HierarchyScaleError("worker imported an unexpected distribution version")
    expected_workload = {
        "fanout": fanout,
        "depth": depth,
        "leaf_primitives": leaf_primitives,
        "profile": "parallel-grounded-resistor-hierarchy",
    }
    if value["workload"] != expected_workload:
        raise HierarchyScaleError("worker output describes an unexpected workload")
    if value["closed_form"] != counts.as_dict() or value["known_expected_passed"] is not True:
        raise HierarchyScaleError("worker did not satisfy the independent closed-form oracle")
    if value["deck_bytes"] != len(deck) or value["deck_sha256"] != hashlib.sha256(deck).hexdigest():
        raise HierarchyScaleError("worker audited an unexpected generated deck")
    if value["policy_sha256"] != policy.fingerprint():
        raise HierarchyScaleError("worker used an unexpected audit policy")
    expected_observed = {
        "files": 1,
        "bytes": len(deck),
        "static_devices": counts.static_devices,
        "static_nets": counts.static_nets,
        "subcircuits": counts.subcircuits,
        "expanded_instances": counts.expanded_instances,
        "materialized_instances": counts.expanded_instances,
        "materialized_element_families": {
            "R": counts.resistors,
            "V": counts.voltage_sources,
            "X": counts.subcircuit_calls,
        },
        "static_element_families": [
            ["R", leaf_primitives],
            ["V", 1],
            ["X", 1 + fanout * (depth - 1)],
        ],
        "findings": 0,
        "decision": "allow",
    }
    if value["observed"] != expected_observed:
        raise HierarchyScaleError("worker observations do not match the closed-form workload")
    if value["source_tree_sha256"] != _package_tree_sha256():
        raise HierarchyScaleError("worker imported a different source tree")
    expected_harness = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    if value["harness_sha256"] != expected_harness:
        raise HierarchyScaleError("worker executed a different benchmark harness")
    elapsed = value["audit_elapsed_ms"]
    if (
        isinstance(elapsed, bool)
        or not isinstance(elapsed, int | float)
        or not math.isfinite(elapsed)
    ):
        raise HierarchyScaleError("worker audit timing is invalid")
    if elapsed < 0:
        raise HierarchyScaleError("worker audit timing is negative")
    if value["scope"] != _SCOPE:
        raise HierarchyScaleError("worker output has an unexpected scope statement")
    for key in ("bundle_sha256", "source_tree_sha256", "harness_sha256"):
        digest = value[key]
        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
        ):
            raise HierarchyScaleError(f"worker output has an invalid {key}")
    return value


def run(
    *,
    fanout: int = 10,
    depth: int = 4,
    leaf_primitives: int = 10,
    timeout_seconds: int = _MAX_TIMEOUT_SECONDS,
    rss_limit_bytes: int = _MAX_RSS_BYTES,
) -> dict[str, object]:
    """Execute one monitored end-to-end benchmark in an isolated child."""

    closed_form_counts(fanout, depth, leaf_primitives)
    timeout_seconds = _require_int("timeout seconds", timeout_seconds, 1, _MAX_TIMEOUT_SECONDS)
    rss_limit_bytes = _require_int("RSS limit bytes", rss_limit_bytes, 1, _MAX_RSS_BYTES)
    token = secrets.token_hex(32)
    environment = os.environ.copy()
    environment[_WORKER_ENV] = token
    raw_base_executable = getattr(sys, "_base_executable", None)
    if not isinstance(raw_base_executable, str) or not Path(raw_base_executable).is_file():
        raise HierarchyScaleError("cannot locate the base Python executable for direct monitoring")
    base_executable = str(Path(raw_base_executable).resolve())
    site_packages = sysconfig.get_path("purelib")
    if not site_packages or not Path(site_packages).is_dir():
        raise HierarchyScaleError("cannot locate the active environment's site-packages")
    # A Windows venv python.exe can be a redirector that launches the base
    # interpreter.  Start that interpreter directly and explicitly add this
    # environment's trusted site-packages so the monitored PID owns the audit's
    # memory instead of merely waiting on an unmeasured descendant.
    bootstrap = (
        "import runpy,site,sys;"
        "site.addsitedir(sys.argv.pop(1));"
        "script=sys.argv.pop(1);"
        "sys.argv[0]=script;"
        "runpy.run_path(script,run_name='__main__')"
    )
    command = [
        base_executable,
        "-I",
        "-c",
        bootstrap,
        site_packages,
        str(Path(__file__).resolve()),
        "--worker",
        "--worker-token",
        token,
        "--fanout",
        str(fanout),
        "--depth",
        str(depth),
        "--leaf-primitives",
        str(leaf_primitives),
    ]
    process = subprocess.Popen(
        command,
        cwd=Path(__file__).resolve().parents[1],
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
    )
    monitored = _monitor_process(
        process,
        timeout_seconds=timeout_seconds,
        rss_limit_bytes=rss_limit_bytes,
    )
    if monitored.return_code != 0:
        detail = monitored.stderr.strip()[-4_000:]
        raise HierarchyScaleError(
            f"benchmark worker exited {monitored.return_code}: {detail or 'no diagnostic'}"
        )
    if monitored.stderr.strip():
        raise HierarchyScaleError("benchmark worker wrote unexpected standard error")
    try:
        decoded: Any = json.loads(monitored.stdout)
    except json.JSONDecodeError as exc:
        raise HierarchyScaleError(f"benchmark worker did not return valid JSON: {exc}") from exc
    result = _validate_worker_payload(
        decoded,
        fanout=fanout,
        depth=depth,
        leaf_primitives=leaf_primitives,
    )
    result["measurement"] = {
        "worker_wall_ms": monitored.wall_ms,
        "peak_resident_bytes": monitored.peak_resident_bytes,
        "memory_metric": monitored.memory_metric,
        "rss_limit_bytes": rss_limit_bytes,
        "timeout_seconds": timeout_seconds,
        "monitor_poll_ms": _POLL_SECONDS * 1_000,
        "platform": platform.platform(),
        "python": platform.python_version(),
        "worker_executable": base_executable,
    }
    return result


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fanout", type=int, default=10)
    parser.add_argument("--depth", type=int, default=4)
    parser.add_argument("--leaf-primitives", type=int, default=10)
    parser.add_argument("--timeout-seconds", type=int, default=_MAX_TIMEOUT_SECONDS)
    parser.add_argument("--rss-limit-mib", type=int, default=_MAX_RSS_BYTES // 1024**2)
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--worker-token", help=argparse.SUPPRESS)
    return parser


def main() -> None:
    args = _parser().parse_args()
    if args.worker:
        expected_token = os.environ.pop(_WORKER_ENV, None)
        supplied_token = args.worker_token
        if (
            expected_token is None
            or supplied_token is None
            or not secrets.compare_digest(expected_token, supplied_token)
        ):
            raise SystemExit("benchmark worker must be launched by the monitored parent")
        payload = _worker_payload(args.fanout, args.depth, args.leaf_primitives)
    else:
        if args.worker_token is not None:
            raise SystemExit("--worker-token is internal")
        payload = run(
            fanout=args.fanout,
            depth=args.depth,
            leaf_primitives=args.leaf_primitives,
            timeout_seconds=args.timeout_seconds,
            rss_limit_bytes=args.rss_limit_mib * 1024**2,
        )
    print(json.dumps(payload, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
