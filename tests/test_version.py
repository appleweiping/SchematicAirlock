from __future__ import annotations

from importlib.metadata import version

import pytest

from schematic_airlock import __version__, audit_text
from schematic_airlock.cli import main


def test_runtime_distribution_cli_and_report_versions_agree(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert __version__ == version("schematic-airlock") == "0.4.0"
    with pytest.raises(SystemExit) as raised:
        main(["--version"])
    assert raised.value.code == 0
    assert capsys.readouterr().out == f"schematic-airlock {__version__}\n"
    report = audit_text("R1 out 0 1k\n")
    assert report.tool_version == __version__
    assert report.as_dict()["tool"] == {"name": "SchematicAirlock", "version": __version__}
