"""Atomic no-clobber report output with input-alias protection."""

from __future__ import annotations

import os
import tempfile
import unicodedata
from collections.abc import Iterable
from pathlib import Path


def _identity(path: Path) -> str:
    return unicodedata.normalize("NFC", str(path.resolve(strict=False))).casefold()


def _aliases(first: Path, second: Path) -> bool:
    try:
        return _identity(first) == _identity(second) or (
            first.exists() and second.exists() and first.samefile(second)
        )
    except OSError as exc:
        raise ValueError(f"cannot resolve output path alias: {exc}") from exc


def write_report(
    destination: str | Path,
    text: str,
    *,
    protected: Iterable[str | Path],
    force: bool,
) -> None:
    """Write a complete UTF-8/LF report atomically without risking an input."""

    target = Path(destination)
    if any(_aliases(target, Path(source)) for source in protected):
        raise ValueError(f"output path {target} aliases an input and is never writable")
    if target.exists() and not force:
        raise ValueError(f"refusing to overwrite existing output {target}; pass --force")
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            prefix=f".{target.name}.",
            suffix=".tmp",
            dir=target.parent,
            delete=False,
        ) as stream:
            temporary = Path(stream.name)
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        if force:
            os.replace(temporary, target)
        else:
            try:
                os.link(temporary, target)
            except FileExistsError as exc:
                raise ValueError(
                    f"refusing to overwrite existing output {target}; pass --force"
                ) from exc
        temporary.unlink(missing_ok=True)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
