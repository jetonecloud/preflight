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
class Unseen:
    """A finding one scan has and the other couldn't have seen, and why."""

    item: dict[str, Any]
    reason: str

    @property
    def id(self) -> str:
        return str(self.item["id"])


def blind_spot(item: dict[str, Any], scan: Snapshot, other: Snapshot) -> str | None:
    """Why `scan` couldn't have reported `item`, or `None` if it looked.

    `other` is the scan that did report it, which is how a region is told
    apart from a global resource: IAM users live in no region either scan
    listed, so a region missing from both says nothing about coverage.
    """
    module, check, region = item.get("module"), item.get("check"), item.get("resource", {})
    region = region.get("region") if isinstance(region, dict) else None
    if module not in scan.modules:
        return f"the {module} module wasn't run"
    status = scan.checks.get(str(check))
    if status is None:
        return f"{check} wasn't run"
    if status == "failed":
        return f"{check} failed"
    if status != "ran":
        return f"{check} was {status}"
    if region and region in other.regions and region not in scan.regions:
        return f"{region} wasn't scanned"
    return None


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
    #: Present before, absent now - but the later scan didn't look where it
    #: was, so it may well still be there. Never counted as fixed.
    unverified: tuple[Unseen, ...] = ()
    #: Absent before, present now - but the earlier scan didn't look where it
    #: is, so it may have been there all along. Not counted as new.
    first_seen: tuple[Unseen, ...] = ()
    #: The files were given newest first and have been put the right way round.
    swapped: bool = False

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

    @property
    def like_for_like(self) -> bool:
        """Whether both scans looked at the same things."""
        return not self.unverified and not self.first_seen


def check_comparable(first: Snapshot, second: Snapshot) -> None:
    """Refuse the pairs whose comparison would be wrong rather than empty."""
    if first.path and second.path and first.path.resolve() == second.path.resolve():
        raise CompareError(
            f"That's the same export twice ({first.path.name}).",
            "Pass an older scan and a newer one.",
        )
    if first.redacted or second.redacted:
        which = first if first.redacted else second
        name = which.path.name if which.path else "One of the exports"
        raise CompareError(
            f"{name} was redacted, so its findings can't be matched up.",
            "Redaction numbers resources per report - vol-1 in one scan isn't vol-1 "
            "in the next. Compare the exports written without --redact.",
        )
    if first.account_id != second.account_id:
        raise CompareError(
            f"These are scans of two different accounts "
            f"({first.account_id} and {second.account_id}).",
            "A comparison only means something for one account over time.",
        )


def compare(before: Snapshot, after: Snapshot) -> Comparison:
    """Match `before` and `after` finding by finding.

    The pair is checked first, and put in time order if it came newest
    first: "fixed" and "new" only mean something one way round.
    """
    check_comparable(before, after)
    swapped = before.finished_at > after.finished_at
    if swapped:
        before, after = after, before

    gone: list[dict[str, Any]] = []
    unverified: list[Unseen] = []
    for key, item in before.findings.items():
        if key in after.findings:
            continue
        reason = blind_spot(item, after, before)
        if reason:
            unverified.append(Unseen(item, reason))
        else:
            gone.append(item)

    arrived: list[dict[str, Any]] = []
    first_seen: list[Unseen] = []
    for key, item in after.findings.items():
        if key in before.findings:
            continue
        reason = blind_spot(item, before, after)
        if reason:
            first_seen.append(Unseen(item, reason))
        else:
            arrived.append(item)

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
        unverified=tuple(sorted(unverified, key=lambda unseen: unseen.id)),
        first_seen=tuple(sorted(first_seen, key=lambda unseen: unseen.id)),
        swapped=swapped,
    )
