"""Replay bounded RAIL002 and parameter-scope oracles with caller-supplied ngspice 42.

This opt-in harness never downloads a simulator. It verifies the executable,
version output, and complete fixed deck set before running any case. The result
is external integration evidence, not part of the offline audit API.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import subprocess
import tempfile
import time
from pathlib import Path

EXPECTED_VERSION = "42"
CASE_DIRECTORY = Path(__file__).with_name("cases") / "ngspice-rail-v1"
MAX_OUTPUT_BYTES = 1024 * 1024
MAX_EXECUTABLE_BYTES = 64 * 1024 * 1024
MAX_ARCHIVE_BYTES = 128 * 1024 * 1024
TIMEOUT_SECONDS = 30.0
CASE_SHA256 = {
    "l-model.cir": "7cacbcab98a3aa690e91d55fd94d14295afe95d9f955ad36586ba6a0e1920b27",
    "l-positive.cir": "3756d003cde8b365bbf7abc2bd0c56cbef968ac038a62a5feaf1a397b1616d36",
    "l-rser-unknown.cir": "7a69dfdfe3ad42e3238e3a8dba240702165c01be64f73077e77610c1da891771",
    "l-zero-multiplier.cir": "6bfa07788d752d110b96dd4002b5229668ca2f940bf164e870cee795d4270a79",
    "parameter-all-levels.cir": "b27271a0f838b64162d0b43ee94fe04d1fb84be7fe1fc9d88110c8dcde57983b",
    "parameter-body-dependent.cir": (
        "b8c77d8a41f96d02228580635a7c81bb5058d506359221979e774ddbcc64e775"
    ),
    "parameter-body-shadowed.cir": (
        "df74cd68554d79592375a546bebdf214802b20c811f31fdb46c8589f7599a982"
    ),
    "parameter-global-only.cir": "330d411f8183060c5df9ee3e2397f740c381f80fdd81592aaf2bb30a648300f0",
    "parameter-header-dependent.cir": (
        "dfbf90839dc62af49c4a6c9aa77d66b09cd68edee651efaeb818fac800e7ce58"
    ),
    "parameter-no-body.cir": "c941f79e3e8fff29601a0b0a1325a67e800b7f4946822317fcca899b1666add2",
    "parameter-no-header.cir": "3a217d38b419899ca3ce3b7d3408906934d5bb8e1d88520d095aaf57fe98dfd4",
    "parameter-no-instance.cir": "bf077072f6a715badbc5b371414708cbea50e71da99b1ece0a51679522fd881c",
    "parameter-top-dependent-redefined.cir": (
        "cead497a034efc85b9cba72bb42750bc0317717dc33575edf509ad2d47c93a0c"
    ),
    "r-one-milliohm.cir": "40f6fc17a74af7e666f1b05f909ab1c27c560d57c0b8fe8dcdefcd70ae172f93",
    "r-zero-chain.cir": "cac3630db721ab166c50c7cf55ddb794e524478658a7f75752415f9c6813a515",
    "r-zero.cir": "66172d6a8ce8c350b6d7697ba22a5ca6b1b8499a851e34c86efa943967cedeb9",
    "v-dynamic.cir": "2515122c160a21065fcc42a8a25c393867a910aecb9c0633a4183cd8bf7742ba",
    "v-zero.cir": "494fbae55021581a399f46360e5921f73133c55844884d7754730a438d0ae31a",
}
EXPECTED_EXIT = {
    "l-model.cir": 1,
    "l-positive.cir": 0,
    "l-rser-unknown.cir": 1,
    "l-zero-multiplier.cir": 0,
    "parameter-all-levels.cir": 0,
    "parameter-body-dependent.cir": 0,
    "parameter-body-shadowed.cir": 0,
    "parameter-global-only.cir": 0,
    "parameter-header-dependent.cir": 0,
    "parameter-no-body.cir": 0,
    "parameter-no-header.cir": 0,
    "parameter-no-instance.cir": 0,
    "parameter-top-dependent-redefined.cir": 0,
    "r-one-milliohm.cir": 0,
    "r-zero-chain.cir": 0,
    "r-zero.cir": 0,
    "v-dynamic.cir": 0,
    "v-zero.cir": 0,
}
PARAMETER_OBSERVATIONS = {
    "parameter-all-levels.cir": ("4", "4.000000e+00", "instance-over-body-header-global"),
    "parameter-body-dependent.cir": ("5", "5.000000e+00", "body-derived-sees-instance"),
    "parameter-body-shadowed.cir": ("1", "1.000000e+00", "instance-over-body"),
    "parameter-global-only.cir": ("1", "1.000000e+00", "global-value"),
    "parameter-header-dependent.cir": ("5", "5.000000e+00", "header-derived-sees-instance"),
    "parameter-no-body.cir": ("2", "2.000000e+00", "header-over-global"),
    "parameter-no-header.cir": ("3", "3.000000e+00", "body-over-global"),
    "parameter-no-instance.cir": ("3", "3.000000e+00", "body-over-header-global"),
    "parameter-top-dependent-redefined.cir": (
        "1",
        "1.000000e+00",
        "top-derived-recomputed-after-final-override",
    ),
}


class OracleError(RuntimeError):
    """The executable, fixed inputs, or simulator output violated the contract."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _regular_file(path: Path, label: str, *, max_bytes: int | None = None) -> Path:
    if path.is_symlink() or not path.is_file():
        raise OracleError(f"{label} must be a regular file, not a symlink")
    if max_bytes is not None and not 0 < path.stat().st_size <= max_bytes:
        raise OracleError(f"{label} exceeds its byte limit")
    return path


def _read_output(path: Path) -> bytes:
    size = path.stat().st_size
    if size > MAX_OUTPUT_BYTES:
        raise OracleError(f"simulator output exceeds {MAX_OUTPUT_BYTES} bytes: {path.name}")
    return path.read_bytes()


def _stop(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=3)


def _run_bounded(
    command: list[str],
    *,
    cwd: Path,
    stdout_path: Path,
    stderr_path: Path,
    extra_output: Path | None = None,
) -> int:
    started = time.monotonic()
    with stdout_path.open("xb") as stdout, stderr_path.open("xb") as stderr:
        process = subprocess.Popen(
            command,
            cwd=cwd,
            stdin=subprocess.DEVNULL,
            stdout=stdout,
            stderr=stderr,
        )
        try:
            while process.poll() is None:
                paths = (stdout_path, stderr_path) + ((extra_output,) if extra_output else ())
                if any(path.exists() and path.stat().st_size > MAX_OUTPUT_BYTES for path in paths):
                    raise OracleError("simulator output exceeded the per-file byte limit")
                if time.monotonic() - started >= TIMEOUT_SECONDS:
                    raise OracleError(f"simulator exceeded the {TIMEOUT_SECONDS:g}-second limit")
                time.sleep(0.02)
            returncode = process.returncode
        finally:
            _stop(process)
    for path in (stdout_path, stderr_path) + ((extra_output,) if extra_output else ()):
        if path.exists() and path.stat().st_size > MAX_OUTPUT_BYTES:
            raise OracleError("simulator output exceeded the per-file byte limit")
    return returncode


def _require(pattern: str, text: str, label: str) -> None:
    if re.search(pattern, text, flags=re.IGNORECASE | re.MULTILINE) is None:
        raise OracleError(f"{label}: expected output pattern is absent")


def _observation(case: str, raw_log: bytes) -> dict[str, object]:
    try:
        log = raw_log.decode("utf-8", errors="strict").replace("\r\n", "\n")
    except UnicodeDecodeError as exc:
        raise OracleError(f"{case}: output is not UTF-8") from exc
    if case in PARAMETER_OBSERVATIONS:
        resistance, voltage, boundary = PARAMETER_OBSERVATIONS[case]
        _require(rf"^\s*resistance\s+{re.escape(resistance)}\s*$", log, case)
        _require(rf"^0\s+{re.escape(voltage)}\s*$", log, case)
        return {
            "op_v_n_volts": voltage,
            "reported_resistance_ohms": resistance,
            "scope_boundary": boundary,
        }
    if case in {"l-model.cir", "l-rser-unknown.cir"}:
        parameter = "inductor_model" if case == "l-model.cir" else "rser"
        _require(rf"unknown parameter \({parameter}\)", log, case)
        _require(r"no simulations run", log, case)
        return {"simulation": "rejected", "unknown_parameter": parameter}
    if case in {"l-positive.cir", "l-zero-multiplier.cir", "v-zero.cir"}:
        _require(r"^0\s+0\.000000e\+00\s*$", log, case)
        return {"op_v_n_volts": "0.000000e+00"}
    if case in {"r-one-milliohm.cir", "r-zero.cir"}:
        _require(r"^0\s+1\.000000e-03\s*$", log, case)
        _require(r"^\s*resistance\s+0\.001\s*$", log, case)
        return {"op_v_n_volts": "1.000000e-03", "reported_resistance_ohms": "0.001"}
    if case == "r-zero-chain.cir":
        _require(r"^0\s+2\.000000e-03\s+1\.000000e-03\s*$", log, case)
        _require(r"^\s*resistance\s+0\.001\s+0\.001\s*$", log, case)
        return {
            "op_v_n_volts": "2.000000e-03",
            "op_v_mid_volts": "1.000000e-03",
            "reported_resistance_each_ohms": "0.001",
        }
    if case == "v-dynamic.cir":
        _require(r"^maximum\s+=\s+1\.000000e\+00\s+at=\s+2\.000000e-06\s*$", log, case)
        _require(r"^0\s+0\.000000e\+00\s*$", log, case)
        return {"op_v_n_volts": "0.000000e+00", "tran_max_v_n_volts": "1.000000e+00"}
    raise AssertionError(case)


def _case_sources(directory: Path = CASE_DIRECTORY) -> list[dict[str, object]]:
    if directory.is_symlink():
        raise OracleError("case directory must be a real directory")
    resolved = directory.resolve(strict=True)
    if not resolved.is_dir():
        raise OracleError("case directory must be a real directory")
    files = {item.name: item for item in resolved.iterdir() if item.is_file()}
    entries = {item.name for item in resolved.iterdir()}
    if entries != set(CASE_SHA256) or set(files) != set(CASE_SHA256):
        raise OracleError("the fixed case file set is incomplete or contains extra entries")
    records: list[dict[str, object]] = []
    for name, expected in sorted(CASE_SHA256.items()):
        source = _regular_file(files[name], f"case {name}")
        if source.stat().st_size > 4096:
            raise OracleError(f"case exceeds its 4096-byte input limit: {name}")
        observed = _sha256(source)
        if observed != expected:
            raise OracleError(f"case hash mismatch: {name}")
        records.append({"name": name, "bytes": source.stat().st_size, "sha256": observed})
    return records


def _copy_verified_case(source: Path, destination: Path, expected_sha256: str) -> None:
    """Bind the bounded bytes actually supplied to ngspice, not an earlier stat."""

    _regular_file(source, "input case", max_bytes=4096)
    with source.open("rb") as stream:
        data = stream.read(4097)
    if len(data) > 4096:
        raise OracleError("input case changed beyond its 4096-byte limit")
    if hashlib.sha256(data).hexdigest() != expected_sha256:
        raise OracleError("input case changed after inventory validation")
    with destination.open("xb") as stream:
        stream.write(data)
    if _sha256(destination) != expected_sha256:
        raise OracleError("copied case hash mismatch before execution")


def _validated_hash(value: str, label: str) -> str:
    if re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise ValueError(f"{label} must be a lowercase SHA-256")
    return value


def run(
    executable: str | Path,
    expected_binary_sha256: str,
    *,
    distribution_archive: str | Path | None = None,
    expected_archive_sha256: str | None = None,
) -> dict[str, object]:
    expected_binary_sha256 = _validated_hash(expected_binary_sha256, "binary hash")
    if (distribution_archive is None) != (expected_archive_sha256 is None):
        raise ValueError("archive path and expected archive hash must be supplied together")
    expected_archive_sha256 = (
        _validated_hash(expected_archive_sha256, "archive hash")
        if expected_archive_sha256 is not None
        else None
    )
    binary = _regular_file(
        Path(executable),
        "ngspice executable",
        max_bytes=MAX_EXECUTABLE_BYTES,
    ).resolve(strict=True)
    binary_hash = _sha256(binary)
    if binary_hash != expected_binary_sha256:
        raise OracleError("ngspice executable hash mismatch")
    archive_record: dict[str, object] | None = None
    if distribution_archive is not None and expected_archive_sha256 is not None:
        archive = _regular_file(
            Path(distribution_archive),
            "release archive",
            max_bytes=MAX_ARCHIVE_BYTES,
        ).resolve(strict=True)
        archive_hash = _sha256(archive)
        if archive_hash != expected_archive_sha256:
            raise OracleError("ngspice release archive hash mismatch")
        archive_record = {
            "name": archive.name,
            "bytes": archive.stat().st_size,
            "sha256": archive_hash,
        }

    sources = _case_sources()
    records: list[dict[str, object]] = []
    with tempfile.TemporaryDirectory(prefix="airlock-ngspice-rail-oracle-") as temporary:
        root = Path(temporary)
        version_stdout = root / "version.stdout"
        version_stderr = root / "version.stderr"
        version_exit = _run_bounded(
            [os.fspath(binary), "-v"],
            cwd=binary.parent,
            stdout_path=version_stdout,
            stderr_path=version_stderr,
        )
        version_raw = _read_output(version_stdout) + _read_output(version_stderr)
        try:
            version_text = version_raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise OracleError("ngspice version output is not UTF-8") from exc
        if version_exit != 0 or re.search(r"\bngspice-42\b", version_text) is None:
            raise OracleError(f"executable did not report ngspice-{EXPECTED_VERSION}")

        for source_record in sources:
            name = str(source_record["name"])
            case_root = root / Path(name).stem
            case_root.mkdir()
            case = case_root / name
            _copy_verified_case(CASE_DIRECTORY / name, case, str(source_record["sha256"]))
            log = case_root / "ngspice.log"
            stdout = case_root / "stdout.bin"
            stderr = case_root / "stderr.bin"
            returncode = _run_bounded(
                [os.fspath(binary), "-n", "-b", "-o", log.name, case.name],
                cwd=case_root,
                stdout_path=stdout,
                stderr_path=stderr,
                extra_output=log,
            )
            if returncode != EXPECTED_EXIT[name]:
                raise OracleError(
                    f"{name}: expected exit {EXPECTED_EXIT[name]}, observed {returncode}"
                )
            raw_log = _read_output(log)
            raw_stdout = _read_output(stdout)
            raw_stderr = _read_output(stderr)
            records.append(
                {
                    "case": name,
                    "case_bytes": source_record["bytes"],
                    "case_sha256": source_record["sha256"],
                    "command": ["ngspice", "-n", "-b", "-o", log.name, case.name],
                    "exit_code": returncode,
                    "log": {"bytes": len(raw_log), "sha256": hashlib.sha256(raw_log).hexdigest()},
                    "stdout": {
                        "bytes": len(raw_stdout),
                        "sha256": hashlib.sha256(raw_stdout).hexdigest(),
                    },
                    "stderr": {
                        "bytes": len(raw_stderr),
                        "sha256": hashlib.sha256(raw_stderr).hexdigest(),
                    },
                    "observation": _observation(name, raw_log),
                }
            )

    script = _regular_file(Path(__file__).resolve(strict=True), "oracle harness")
    return {
        "schema": "org.schematic-airlock.ngspice-rail-oracle",
        "schema_version": 1,
        "evidence_class": "real-executable",
        "passed": True,
        "limits": {
            "archive_bytes": MAX_ARCHIVE_BYTES,
            "executable_bytes": MAX_EXECUTABLE_BYTES,
            "case_bytes": 4096,
            "output_bytes_per_file": MAX_OUTPUT_BYTES,
            "wall_seconds_per_process": TIMEOUT_SECONDS,
        },
        "simulator": {
            "expected_version": EXPECTED_VERSION,
            "binary_bytes": binary.stat().st_size,
            "binary_sha256": binary_hash,
            "version_output_sha256": hashlib.sha256(version_raw).hexdigest(),
        },
        "distribution_archive": archive_record,
        "harness_sha256": _sha256(script),
        "platform": {
            "architecture": platform.machine(),
            "implementation": platform.python_implementation(),
            "operating_system": platform.system(),
            "python": platform.python_version(),
            "release": platform.release(),
        },
        "cases": records,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ngspice", required=True, help="exact ngspice 42 executable path")
    parser.add_argument("--expected-sha256", required=True, help="expected executable SHA-256")
    parser.add_argument("--archive", help="optional exact distribution archive path")
    parser.add_argument("--expected-archive-sha256", help="expected archive SHA-256")
    parser.add_argument("--output", help="new JSON report path; stdout when omitted")
    return parser


if __name__ == "__main__":
    options = _parser().parse_args()
    rendered = json.dumps(
        run(
            options.ngspice,
            options.expected_sha256,
            distribution_archive=options.archive,
            expected_archive_sha256=options.expected_archive_sha256,
        ),
        sort_keys=True,
        indent=2,
        allow_nan=False,
    )
    if options.output is None:
        print(rendered)
    else:
        output = Path(options.output)
        with output.open("x", encoding="utf-8", newline="\n") as stream:
            stream.write(rendered + "\n")
        print(json.dumps({"output": os.fspath(output), "sha256": _sha256(output)}))
