from __future__ import annotations

import io
import json
import runpy
from hashlib import sha256
from importlib.metadata import version
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

import schematic_airlock
from schematic_airlock import (
    audit_path,
    compare_structural_summary,
    fuzz_smoke,
    load_structural_summary,
)
from schematic_airlock.cli import EXIT_INPUT, entrypoint, main
from schematic_airlock.domain import InputError

ROOT = Path(__file__).parents[1]
CORPUS = ROOT / "corpus" / "portable_analog"


def _imported_tree_sha256() -> str:
    assert schematic_airlock.__file__ is not None
    root = Path(schematic_airlock.__file__).resolve().parent
    digest = sha256()
    for path in sorted(root.rglob("*.py")):
        relative = path.relative_to(root).as_posix().encode()
        content = path.read_bytes()
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest()


def _summary() -> dict[str, object]:
    paths = [CORPUS / "primitives.lib", CORPUS / "two_stage_ota.sp"]
    return {
        "schema": "org.spice-tools.structural-summary",
        "schema_version": 1,
        "producer": {"name": "SpiceTrellis", "version": "0.1.0"},
        "files": [
            {
                "path": path.name,
                "bytes": len(path.read_bytes()),
                "sha256": sha256(path.read_bytes()).hexdigest(),
            }
            for path in paths
        ],
        "structure": {
            "files": 2,
            "includes": 1,
            "subcircuits": 3,
            "element_families": {"C": 1, "M": 5, "R": 4, "V": 3, "X": 3},
            "parameters": ["bias", "load", "rbias", "rload", "rout", "supply"],
            "models": ["nch", "pch"],
        },
    }


def test_clean_room_corpus_is_a_deterministic_audit_fixture() -> None:
    first = audit_path(CORPUS / "two_stage_ota.sp")
    second = audit_path(CORPUS / "two_stage_ota.sp")
    assert first.bundle_sha256 == second.bundle_sha256
    assert first.stats.devices == 16
    assert first.stats.subcircuits == 3


def test_structural_summary_matches_independent_audit() -> None:
    summary = load_structural_summary(json.dumps(_summary()))
    assert compare_structural_summary(audit_path(CORPUS / "two_stage_ota.sp"), summary) == ()


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda value: value["structure"].update(includes=999), "include counts"),
        (lambda value: value["structure"].update(element_families={"Z": 16}), "families"),
        (lambda value: value["structure"].update(parameters=["forged"]), "parameter"),
        (lambda value: value["structure"].update(models=["forged"]), "model"),
    ],
)
def test_interop_comparison_rejects_forged_structural_facts(mutation, message: str) -> None:
    value = _summary()
    mutation(value)
    mismatches = compare_structural_summary(
        audit_path(CORPUS / "two_stage_ota.sp"), load_structural_summary(json.dumps(value))
    )
    assert any(message in mismatch for mismatch in mismatches)


def test_consumer_publishes_a_valid_schema_for_the_interchange_boundary() -> None:
    contract_path = ROOT / "docs" / "schemas" / "structural-summary-v1.schema.json"
    contract = json.loads(contract_path.read_text(encoding="utf-8"))
    validator = Draft202012Validator(contract)
    validator.check_schema(contract)
    assert list(validator.iter_errors(_summary())) == []


def test_published_airlock_schemas_accept_generated_documents() -> None:
    manifest_contract = json.loads(
        (ROOT / "docs" / "schemas" / "bundle-manifest-v1.schema.json").read_text(encoding="utf-8")
    )
    report_contract = json.loads(
        (ROOT / "docs" / "schemas" / "audit-report-v1.schema.json").read_text(encoding="utf-8")
    )
    manifest = json.loads(
        (ROOT / "tests" / "fixtures" / "safe_bundle" / "manifest.json").read_text(encoding="utf-8")
    )
    report = audit_path(ROOT / "tests" / "fixtures" / "safe_bundle").as_dict()
    for contract, instance in ((manifest_contract, manifest), (report_contract, report)):
        validator = Draft202012Validator(contract)
        validator.check_schema(contract)
        assert list(validator.iter_errors(instance)) == []


@pytest.mark.parametrize(
    "replacement",
    [
        '"schema_version": true',
        '"schema_version": 1.0',
        '"schema_version": NaN',
        '"schema_version": 1, "schema_version": 1',
    ],
)
def test_structural_summary_rejects_ambiguous_json(replacement: str) -> None:
    text = json.dumps(_summary()).replace('"schema_version": 1', replacement)
    with pytest.raises(InputError):
        load_structural_summary(text)


def test_structural_summary_rejects_unsafe_paths() -> None:
    value = _summary()
    value["files"][0]["path"] = "../outside.lib"
    with pytest.raises(InputError, match="file entry"):
        load_structural_summary(json.dumps(value))


def test_structural_summary_rejects_deep_oversized_and_unencodable_json() -> None:
    deeply_nested = "[" * 1_500 + "0" + "]" * 1_500
    with pytest.raises(InputError, match=r"invalid interop JSON|complexity limits"):
        load_structural_summary(deeply_nested)
    with pytest.raises(InputError, match="byte input limit"):
        load_structural_summary(" " * 1_048_577)
    with pytest.raises(InputError, match="invalid interop JSON"):
        load_structural_summary("\ud800")


def test_interop_cli_verifies_the_shared_contract(tmp_path: Path) -> None:
    summary = tmp_path / "summary.json"
    summary.write_text(json.dumps(_summary()), encoding="utf-8")
    output = io.StringIO()
    assert (
        main(["interop-check", str(CORPUS / "two_stage_ota.sp"), str(summary)], stdout=output) == 2
    )
    assert output.getvalue() == "structural summary verified; audit decision: review\n"

    permissive = io.StringIO()
    assert (
        main(
            [
                "interop-check",
                str(CORPUS / "two_stage_ota.sp"),
                str(summary),
                "--fail-on",
                "deny",
            ],
            stdout=permissive,
        )
        == 0
    )
    assert permissive.getvalue().endswith("audit decision: review\n")

    policy = tmp_path / "deny-review.toml"
    policy.write_text(
        'schema_version = 1\n[rules.severity_overrides]\nVAL002 = "deny"\n', encoding="utf-8"
    )
    denied = io.StringIO()
    assert (
        main(
            [
                "interop-check",
                str(CORPUS / "two_stage_ota.sp"),
                str(summary),
                "--policy",
                str(policy),
            ],
            stdout=denied,
        )
        == 2
    )
    assert denied.getvalue().endswith("audit decision: deny\n")


def test_interop_cli_reads_summary_through_the_byte_limit(tmp_path: Path) -> None:
    summary = tmp_path / "oversized.json"
    summary.write_bytes(b" " * 1_048_577)
    errors = io.StringIO()
    assert (
        main(
            ["interop-check", str(CORPUS / "two_stage_ota.sp"), str(summary)],
            stderr=errors,
        )
        == EXIT_INPUT
    )
    assert "byte input limit" in errors.getvalue()


def test_console_entrypoint_propagates_the_exit_status(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("sys.argv", ["schematic-airlock", "interop-check"])
    with pytest.raises(SystemExit) as raised:
        entrypoint()
    assert raised.value.code == EXIT_INPUT


def test_fuzz_smoke_and_cli_are_deterministic() -> None:
    path = CORPUS / "rc_sensor_frontend.sp"
    seed = path.read_text(encoding="utf-8")
    assert fuzz_smoke(seed, cases=25, seed=4) == fuzz_smoke(seed, cases=25, seed=4)
    output = io.StringIO()
    assert main(["fuzz-smoke", str(path), "--cases", "4"], stdout=output) == 0
    assert json.loads(output.getvalue())["cases"] == 4
    with pytest.raises(ValueError, match="cases"):
        fuzz_smoke(seed, cases=1.5)  # type: ignore[arg-type]


def test_benchmark_manifest_binds_every_corpus_file() -> None:
    manifest = json.loads((ROOT / "benchmarks" / "manifest.json").read_text(encoding="utf-8"))
    recorded = {ROOT / record["path"] for record in manifest["corpus"]["files"]}
    expected = set(CORPUS.glob("*.sp")) | set(CORPUS.glob("*.lib"))
    assert recorded == expected
    for record in manifest["corpus"]["files"]:
        assert sha256((ROOT / record["path"]).read_bytes()).hexdigest() == record["sha256"]


def test_runtime_benchmark_hashes_decks_and_followed_libraries() -> None:
    benchmark_run = runpy.run_path("benchmarks/benchmark.py")["run"]
    with pytest.raises(ValueError, match="integer"):
        benchmark_run(1.5)
    with pytest.raises(ValueError, match="integer"):
        benchmark_run(True)

    expected = sha256()
    corpus = ROOT / "corpus" / "portable_analog"
    paths = tuple(sorted((*corpus.glob("*.sp"), *corpus.glob("*.lib"))))
    for path in paths:
        relative = path.relative_to(corpus).as_posix().encode()
        content = path.read_bytes()
        expected.update(len(relative).to_bytes(8, "big"))
        expected.update(relative)
        expected.update(len(content).to_bytes(8, "big"))
        expected.update(content)
    result = benchmark_run(1)
    manifest = json.loads((ROOT / "benchmarks" / "manifest.json").read_text(encoding="utf-8"))
    assert result["workload_sha256"] == expected.hexdigest() == manifest["workload_sha256"]
    assert result["distribution_version"] == version("schematic-airlock")
    assert result["package_tree_sha256"] == _imported_tree_sha256()
    assert (
        result["harness_sha256"]
        == sha256((ROOT / "benchmarks" / "benchmark.py").read_bytes()).hexdigest()
    )
    assert manifest["runtime"] == {
        "distribution_version": result["distribution_version"],
        "package_tree_sha256": result["package_tree_sha256"],
        "harness_sha256": result["harness_sha256"],
    }
    for key, value in manifest["expected"].items():
        assert result[key] == value
