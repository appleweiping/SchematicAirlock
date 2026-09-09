from __future__ import annotations

import hashlib
import runpy
import shutil
import sys
import time
from pathlib import Path
from typing import Any

import pytest

from schematic_airlock._strict_json import load_strict_json_path

ROOT = Path(__file__).parents[1]
HARNESS = ROOT / "benchmarks" / "ngspice_rail_oracle.py"
RESULT = ROOT / "benchmarks" / "results" / "ngspice-42-windows-rail-oracle-20260909-v2.json"


@pytest.fixture(scope="module")
def harness() -> dict[str, Any]:
    return runpy.run_path(str(HARNESS))


def test_fixed_case_set_and_hashes_are_complete(harness: dict[str, Any]) -> None:
    records = harness["_case_sources"]()

    assert [record["name"] for record in records] == sorted(harness["CASE_SHA256"])
    assert sum(int(record["bytes"]) for record in records) == 2_576
    assert all(int(record["bytes"]) <= 4_096 for record in records)


def test_published_real_result_is_bound_to_current_harness_and_cases(
    harness: dict[str, Any],
) -> None:
    report = load_strict_json_path(RESULT, context="published ngspice rail oracle")
    assert isinstance(report, dict)
    assert report["schema"] == "org.schematic-airlock.ngspice-rail-oracle"
    assert report["schema_version"] == 1
    assert report["evidence_class"] == "real-executable"
    assert report["passed"] is True
    assert report["harness_sha256"] == hashlib.sha256(HARNESS.read_bytes()).hexdigest()
    assert {
        item["case"]: item["case_sha256"] for item in report["cases"] if isinstance(item, dict)
    } == harness["CASE_SHA256"]
    serialized = RESULT.read_text(encoding="utf-8")
    assert "D:\\" not in serialized
    assert "C:\\" not in serialized


def test_case_hash_mutation_fails_closed(harness: dict[str, Any], tmp_path: Path) -> None:
    cases = tmp_path / "cases"
    shutil.copytree(harness["CASE_DIRECTORY"], cases)
    (cases / "v-zero.cir").write_text("changed\n", encoding="ascii")

    with pytest.raises(harness["OracleError"], match="case hash mismatch"):
        harness["_case_sources"](cases)


def test_extra_case_entry_fails_closed(harness: dict[str, Any], tmp_path: Path) -> None:
    cases = tmp_path / "cases"
    shutil.copytree(harness["CASE_DIRECTORY"], cases)
    (cases / "extra.cir").write_text("extra\n", encoding="ascii")

    with pytest.raises(harness["OracleError"], match="file set"):
        harness["_case_sources"](cases)


def test_case_copy_rejects_mutation_after_inventory(
    harness: dict[str, Any], tmp_path: Path
) -> None:
    cases = tmp_path / "cases"
    shutil.copytree(harness["CASE_DIRECTORY"], cases)
    inventory = harness["_case_sources"](cases)
    record = next(item for item in inventory if item["name"] == "v-zero.cir")
    source = cases / "v-zero.cir"
    source.write_bytes(source.read_bytes() + b"* changed after inventory\n")
    copied = tmp_path / "copied.cir"

    with pytest.raises(harness["OracleError"], match="changed after inventory"):
        harness["_copy_verified_case"](source, copied, record["sha256"])
    assert not copied.exists()


def test_case_copy_rehashes_the_bytes_to_be_executed(
    harness: dict[str, Any], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = harness["CASE_DIRECTORY"] / "v-zero.cir"
    expected = harness["CASE_SHA256"][source.name]
    copied = tmp_path / "copied.cir"
    seen: list[Path] = []

    def reject_copy(path: Path) -> str:
        seen.append(path)
        return "0" * 64

    monkeypatch.setitem(harness["_copy_verified_case"].__globals__, "_sha256", reject_copy)
    with pytest.raises(harness["OracleError"], match="copied case hash mismatch"):
        harness["_copy_verified_case"](source, copied, expected)
    assert seen == [copied]
    assert copied.read_bytes() == source.read_bytes()


def test_case_copy_preserves_bytes_and_never_overwrites(
    harness: dict[str, Any], tmp_path: Path
) -> None:
    source = harness["CASE_DIRECTORY"] / "v-zero.cir"
    expected = harness["CASE_SHA256"][source.name]
    copied = tmp_path / "copied.cir"
    harness["_copy_verified_case"](source, copied, expected)
    assert copied.read_bytes() == source.read_bytes()
    with pytest.raises(FileExistsError):
        harness["_copy_verified_case"](source, copied, expected)
    assert hashlib.sha256(copied.read_bytes()).hexdigest() == expected


@pytest.mark.parametrize("target", ["executable", "archive", "case-directory"])
def test_final_symlink_is_rejected_before_resolving(
    harness: dict[str, Any], tmp_path: Path, monkeypatch: pytest.MonkeyPatch, target: str
) -> None:
    link = tmp_path / "unresolved-link"
    original_is_symlink = Path.is_symlink

    def is_symlink(path: Path) -> bool:
        return path == link or original_is_symlink(path)

    def never_resolve(path: Path, strict: bool = False) -> Path:
        assert path != link, "the final symlink was resolved before it was rejected"
        return path

    monkeypatch.setattr(Path, "is_symlink", is_symlink)
    monkeypatch.setattr(Path, "resolve", never_resolve)
    with pytest.raises(harness["OracleError"], match=r"regular file|real directory"):
        if target == "case-directory":
            harness["_case_sources"](link)
        elif target == "executable":
            harness["run"](link, "0" * 64)
        else:
            binary = Path(sys.executable)
            harness["run"](
                binary,
                hashlib.sha256(binary.read_bytes()).hexdigest(),
                distribution_archive=link,
                expected_archive_sha256="0" * 64,
            )


@pytest.mark.parametrize(
    ("case", "log", "expected"),
    [
        (
            "r-zero.cir",
            " resistance                 0.001\n0  1.000000e-03\n",
            {"op_v_n_volts": "1.000000e-03", "reported_resistance_ohms": "0.001"},
        ),
        (
            "r-zero-chain.cir",
            " resistance 0.001 0.001\n0 2.000000e-03 1.000000e-03\n",
            {
                "op_v_n_volts": "2.000000e-03",
                "op_v_mid_volts": "1.000000e-03",
                "reported_resistance_each_ohms": "0.001",
            },
        ),
        ("l-positive.cir", "0 0.000000e+00\n", {"op_v_n_volts": "0.000000e+00"}),
        (
            "v-dynamic.cir",
            "maximum = 1.000000e+00 at= 2.000000e-06\n0 0.000000e+00\n",
            {"op_v_n_volts": "0.000000e+00", "tran_max_v_n_volts": "1.000000e+00"},
        ),
        (
            "l-rser-unknown.cir",
            "unknown parameter (rser)\nno simulations run\n",
            {"simulation": "rejected", "unknown_parameter": "rser"},
        ),
        (
            "parameter-header-dependent.cir",
            " resistance                 5\n0  5.000000e+00\n",
            {
                "op_v_n_volts": "5.000000e+00",
                "reported_resistance_ohms": "5",
                "scope_boundary": "header-derived-sees-instance",
            },
        ),
    ],
)
def test_oracle_requires_complete_case_specific_observations(
    harness: dict[str, Any], case: str, log: str, expected: dict[str, object]
) -> None:
    assert harness["_observation"](case, log.encode("ascii")) == expected


def test_incomplete_output_fails_closed(harness: dict[str, Any]) -> None:
    with pytest.raises(harness["OracleError"], match="expected output pattern"):
        harness["_observation"]("v-dynamic.cir", b"0 0.000000e+00\n")


def test_binary_hash_is_checked_before_execution(harness: dict[str, Any]) -> None:
    with pytest.raises(harness["OracleError"], match="executable hash mismatch"):
        harness["run"](sys.executable, "0" * 64)


def test_empty_executable_is_rejected_before_hash_or_execution(
    harness: dict[str, Any], tmp_path: Path
) -> None:
    empty = tmp_path / "ngspice"
    empty.touch()

    with pytest.raises(harness["OracleError"], match="byte limit"):
        harness["run"](empty, hashlib.sha256(b"").hexdigest())


def test_non_ngspice_executable_fails_the_version_gate(harness: dict[str, Any]) -> None:
    executable = Path(sys.executable).resolve(strict=True)
    executable_hash = hashlib.sha256(executable.read_bytes()).hexdigest()

    with pytest.raises(harness["OracleError"], match="did not report ngspice-42"):
        harness["run"](executable, executable_hash)


def test_subprocess_output_limit_is_enforced(harness: dict[str, Any], tmp_path: Path) -> None:
    stdout = tmp_path / "stdout"
    stderr = tmp_path / "stderr"
    command = [
        sys.executable,
        "-I",
        "-S",
        "-c",
        f"import sys;sys.stdout.buffer.write(b'x'*{harness['MAX_OUTPUT_BYTES'] + 1})",
    ]

    with pytest.raises(harness["OracleError"], match="output exceeded"):
        harness["_run_bounded"](
            command,
            cwd=tmp_path,
            stdout_path=stdout,
            stderr_path=stderr,
        )


def test_subprocess_timeout_terminates_the_child(
    harness: dict[str, Any], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setitem(harness["_run_bounded"].__globals__, "TIMEOUT_SECONDS", 0.05)
    stdout = tmp_path / "stdout"
    stderr = tmp_path / "stderr"
    started = time.monotonic()

    with pytest.raises(harness["OracleError"], match="second limit"):
        harness["_run_bounded"](
            [sys.executable, "-I", "-S", "-c", "import time;time.sleep(5)"],
            cwd=tmp_path,
            stdout_path=stdout,
            stderr_path=stderr,
        )

    assert time.monotonic() - started < 4
