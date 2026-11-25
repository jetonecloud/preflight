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


# --- matching two scans ---------------------------------------------------


def monthly(item: dict[str, Any]) -> float | None:
    """A finding's monthly figure as the export wrote it, or `None`."""
    value = item.get("estimated_monthly_savings_usd")
    return float(value) if value is not None else None


def _order(items: list[dict[str, Any]]) -> tuple[dict[str, Any], ...]:
    """Biggest saving first, then by ID - the order the report uses."""
    return tuple(sorted(items, key=lambda item: (-(monthly(item) or 0.0), item["id"])))


def _sum(items: tuple[dict[str, Any], ...]) -> float:
    return sum(monthly(item) or 0.0 for item in items)


@dataclass(frozen=True)
class Change:
    """One finding present in both scans, and what moved between them."""

    before: dict[str, Any]
    after: dict[str, Any]

    @property
    def id(self) -> str:
        return str(self.after["id"])

    @property
    def severity_changed(self) -> bool:
        return self.before.get("severity") != self.after.get("severity")

    @property
    def monthly_delta(self) -> float:
        return (monthly(self.after) or 0.0) - (monthly(self.before) or 0.0)

    @property
    def changed(self) -> bool:
        """Worse or better - a cent of rounding isn't either."""
        return self.severity_changed or abs(self.monthly_delta) >= 0.01


@dataclass(frozen=True)
class Comparison:
    """What happened to an account between two scans of it."""

    before: Snapshot
    after: Snapshot
    #: Present before, absent now, and the later scan looked where it was.
    fixed: tuple[dict[str, Any], ...]
    #: Absent before, present now.
    new: tuple[dict[str, Any], ...]
    #: Present in both.
    still_open: tuple[Change, ...]

    @property
    def changed(self) -> tuple[Change, ...]:
        return tuple(change for change in self.still_open if change.changed)

    @property
    def fixed_monthly(self) -> float:
        return _sum(self.fixed)

    @property
    def new_monthly(self) -> float:
        return _sum(self.new)

    @property
    def monthly_before(self) -> float:
        return sum(monthly(item) or 0.0 for item in self.before.findings.values())

    @property
    def monthly_after(self) -> float:
        return sum(monthly(item) or 0.0 for item in self.after.findings.values())

    @property
    def priced(self) -> bool:
        """Whether either scan put a price on anything."""
        everything = (*self.before.findings.values(), *self.after.findings.values())
        return any(monthly(item) is not None for item in everything)

    @property
    def unchanged(self) -> bool:
        return not self.fixed and not self.new and not self.changed


def compare(before: Snapshot, after: Snapshot) -> Comparison:
    """Match `before` and `after` finding by finding."""
    gone = [item for key, item in before.findings.items() if key not in after.findings]
    arrived = [item for key, item in after.findings.items() if key not in before.findings]
    both = [
        Change(before=before.findings[key], after=item)
        for key, item in after.findings.items()
        if key in before.findings
    ]
    both.sort(key=lambda change: (-(monthly(change.after) or 0.0), change.id))
    return Comparison(
        before=before,
        after=after,
        fixed=_order(gone),
        new=_order(arrived),
        still_open=tuple(both),
    )
