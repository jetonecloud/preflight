"""Two scans of one account, side by side: what got fixed, and what's new.

The JSON export exists so this can be done. Every finding carries an ID that
is stable across scans - same check, same region, same resource, same
string - so a finding present last time and absent now has either been fixed
or stopped being looked at. Telling those two apart is most of the work here.

Nothing in this module talks to AWS. It reads two files a scan already wrote.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from preflight.core.report import SCHEMA_VERSION


class CompareError(Exception):
    """Two exports that can't be read, or can't be compared honestly."""

    def __init__(self, message: str, hint: str | None = None) -> None:
        super().__init__(message)
        self.hint = hint


@dataclass(frozen=True)
class Snapshot:
    """One JSON export, read back: just the parts a comparison needs."""

    path: Path | None
    account_id: str
    finished_at: datetime
    regions: tuple[str, ...]
    modules: tuple[str, ...]
    #: Check key to its status ("ran", "skipped", "failed"). A check that
    #: wasn't selected - `--only`, `--modules` - isn't in here at all.
    checks: dict[str, str]
    findings: dict[str, dict[str, Any]]
    redacted: bool = False
    demo: bool = False
    version: str = ""

    @property
    def label(self) -> str:
        """`2026-11-25 09:44 UTC`, for headings."""
        return self.finished_at.strftime("%Y-%m-%d %H:%M UTC")

    @classmethod
    def from_dict(cls, data: Any, path: Path | None = None) -> Snapshot:
        name = path.name if path else "the export"
        if not isinstance(data, dict) or "schema_version" not in data:
            raise CompareError(
                f"{name} isn't a Preflight export.",
                "Pass the .json file a scan writes next to its report.",
            )
        version = data["schema_version"]
        if not isinstance(version, int) or version > SCHEMA_VERSION:
            raise CompareError(
                f"{name} was written by a newer Preflight (schema {version}).",
                "Upgrade Preflight to compare it.",
            )
        try:
            scan = data["scan"]
            findings = {item["id"]: item for item in data["findings"]}
            return cls(
                path=path,
                account_id=str(data["account"]["id"]),
                finished_at=datetime.fromisoformat(scan["finished_at"]),
                regions=tuple(scan["regions"]),
                modules=tuple(module["key"] for module in data["modules"]),
                checks={check["key"]: check["status"] for check in data["checks"]},
                findings=findings,
                redacted=bool(scan.get("redacted", False)),
                demo=bool(scan.get("demo", False)),
                version=str(data.get("preflight", {}).get("version", "")),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise CompareError(
                f"{name} is missing part of a Preflight export ({exc}).",
                "It may have been edited by hand, or cut off while being written.",
            ) from exc


def load(path: Path) -> Snapshot:
    """Read a JSON export from disk."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise CompareError(f"Couldn't read {path} ({exc.strerror or exc}).") from exc
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise CompareError(
            f"{path.name} isn't valid JSON (line {exc.lineno}).",
            "Pass the .json file a scan writes next to its report.",
        ) from exc
    return Snapshot.from_dict(data, path)
