"""The thing you actually keep: one scan, written down.

`ScanResult` is the whole output of a scan — what was read, what was found,
what couldn't be read and why — and it renders to exactly two formats. The
JSON is the stable one, versioned, meant to be diffed between scans or fed
to something else. The HTML is the one you send to someone.

Both are built from the same object, so they can't disagree, and the HTML is
a single self-contained file with no fonts, scripts or images to fetch. You
can email it, open it on a plane, or print it to PDF, and nothing about it
phones home.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass, field, replace
from datetime import datetime
from importlib import resources
from typing import TYPE_CHECKING, Any

from preflight import __version__
from preflight.core.findings import (
    Finding,
    Severity,
    count_by_severity,
    rank,
    total_monthly,
)
from preflight.core.naming import REPORT_STEM
from preflight.core.pricing import PRICES_REVIEWED
from preflight.core.redact import Redactor
from preflight.core.scan import CheckOutcome
from preflight.core.spend import Spend
from preflight.modules.base import Module

if TYPE_CHECKING:  # pragma: no cover - typing only
    from preflight.core.session import Identity

#: Bump this when the JSON changes shape in a way a reader would notice.
#: Added fields don't count; renamed or removed ones do.
SCHEMA_VERSION = 1

TEMPLATE_NAME = "report.html.j2"

#: How many findings the report leads with. Three is the product: the first
#: three things to fix, not a list of ninety things to feel bad about.
HEADLINE_COUNT = 3


@dataclass(frozen=True)
class Account:
    """The account a scan ran against, flattened so it can be redacted."""

    id: str
    arn: str
    kind: str = "unknown"
    is_preflight_role: bool = False

    @classmethod
    def of(cls, identity: Identity) -> Account:
        return cls(
            id=identity.account_id,
            arn=identity.arn,
            kind=identity.kind,
            is_preflight_role=identity.is_preflight_role,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "identity_arn": self.arn,
            "identity_kind": self.kind,
            "is_preflight_role": self.is_preflight_role,
        }


@dataclass(frozen=True)
class ScanResult:
    """Everything one scan produced."""

    account: Account
    regions: tuple[str, ...]
    outcomes: tuple[CheckOutcome, ...]
    modules: tuple[Module, ...]
    started_at: datetime
    finished_at: datetime
    lookback_days: int
    credentials: str = ""
    command: str = ""
    spend: Spend | None = None
    notes: tuple[str, ...] = ()
    version: str = __version__
    demo: bool = False
    redacted: bool = False
    prices_reviewed: str = PRICES_REVIEWED
    _findings: tuple[Finding, ...] | None = field(default=None, repr=False)

    # --- what was found ---------------------------------------------------

    @property
    def findings(self) -> tuple[Finding, ...]:
        """Every finding, worst first."""
        if self._findings is not None:
            return self._findings
        return rank([finding for outcome in self.outcomes for finding in outcome.findings])

    @property
    def headline(self) -> tuple[Finding, ...]:
        """The first few things to fix."""
        return self.findings[:HEADLINE_COUNT]

    @property
    def monthly_usd(self) -> float:
        return total_monthly(self.findings)

    @property
    def annual_usd(self) -> float:
        return self.monthly_usd * 12

    @property
    def by_severity(self) -> dict[str, int]:
        return count_by_severity(self.findings)

    @property
    def share_of_spend(self) -> float | None:
        """Monthly saving as a fraction of last month's bill."""
        return self.spend.share_of(self.monthly_usd) if self.spend else None

    # --- what happened ----------------------------------------------------

    @property
    def ran(self) -> tuple[CheckOutcome, ...]:
        return tuple(outcome for outcome in self.outcomes if outcome.ran)

    @property
    def clean(self) -> tuple[CheckOutcome, ...]:
        """Checks that ran and found nothing — the good news, and worth showing."""
        return tuple(outcome for outcome in self.outcomes if outcome.clean)

    @property
    def skipped(self) -> tuple[CheckOutcome, ...]:
        return tuple(outcome for outcome in self.outcomes if outcome.status == "skipped")

    @property
    def failed(self) -> tuple[CheckOutcome, ...]:
        return tuple(outcome for outcome in self.outcomes if outcome.status == "failed")

    @property
    def missing_actions(self) -> tuple[str, ...]:
        """IAM actions that stopped a check running, deduplicated and sorted."""
        return tuple(
            sorted({outcome.missing_action for outcome in self.skipped if outcome.missing_action})
        )

    @property
    def examined(self) -> int:
        return sum(outcome.examined for outcome in self.outcomes)

    @property
    def seconds(self) -> float:
        return max((self.finished_at - self.started_at).total_seconds(), 0.0)

    @property
    def complete(self) -> bool:
        """Whether every check ran. A report that says so has earned it."""
        return not self.skipped and not self.failed and not self.notes

    # --- grouping for the report -----------------------------------------

    def groups(self) -> list[dict[str, Any]]:
        """Findings grouped under the check that produced them, in module order."""
        grouped: list[dict[str, Any]] = []
        for outcome in self.outcomes:
            if not outcome.findings:
                continue
            findings = rank(outcome.findings)
            grouped.append(
                {
                    "check": outcome.check,
                    "outcome": outcome,
                    "findings": findings,
                    "monthly_usd": total_monthly(findings),
                }
            )
        grouped.sort(key=lambda group: -group["monthly_usd"])
        return grouped

    # --- transforms -------------------------------------------------------

    def redact(self) -> ScanResult:
        """The same report with the account scrubbed out of it."""
        redactor = Redactor(True, account_id=self.account.id)
        # Redact once, through the outcomes, then derive the flat list from
        # them — so a finding can't end up with one pseudonym in the headline
        # and another in its section.
        outcomes = tuple(
            replace(
                outcome,
                findings=tuple(finding.redacted(redactor) for finding in outcome.findings),
            )
            for outcome in self.outcomes
        )
        findings = [finding for outcome in outcomes for finding in outcome.findings]
        return replace(
            self,
            account=Account(
                id=redactor.account(self.account.id),
                arn="<redacted>",
                kind=self.account.kind,
                is_preflight_role=self.account.is_preflight_role,
            ),
            outcomes=outcomes,
            notes=tuple(redactor.text(note) for note in self.notes),
            credentials="<redacted>",
            command=redactor.text(self.command),
            redacted=True,
            _findings=rank(findings),
        )

    def filename_stem(self) -> str:
        """`preflight-report-123456789012-20261022-141500`."""
        when = self.finished_at.strftime("%Y%m%d-%H%M%S")
        account = self.account.id or "unknown"
        return f"{REPORT_STEM}-{account}-{when}"

    # --- output -----------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "preflight": {"version": self.version, "command": self.command},
            "scan": {
                "started_at": _iso(self.started_at),
                "finished_at": _iso(self.finished_at),
                "duration_seconds": round(self.seconds, 1),
                "lookback_days": self.lookback_days,
                "regions": list(self.regions),
                "credentials": self.credentials,
                "redacted": self.redacted,
                "demo": self.demo,
                "prices_reviewed": self.prices_reviewed,
            },
            "account": self.account.to_dict(),
            "modules": [{"key": module.key, "name": module.name} for module in self.modules],
            "spend": self.spend.to_dict() if self.spend else None,
            "summary": {
                "findings": len(self.findings),
                "by_severity": self.by_severity,
                "estimated_monthly_savings_usd": round(self.monthly_usd, 2),
                "estimated_annual_savings_usd": round(self.annual_usd, 2),
                "share_of_last_month_spend": (
                    round(self.share_of_spend, 4) if self.share_of_spend is not None else None
                ),
                "resources_examined": self.examined,
                "checks_run": len(self.ran),
                "checks_skipped": len(self.skipped),
                "checks_failed": len(self.failed),
            },
            "checks": [outcome.to_dict() for outcome in self.outcomes],
            "findings": [finding.to_dict() for finding in self.findings],
            "notes": list(self.notes),
            "missing_actions": list(self.missing_actions),
        }

    def to_json(self, *, indent: int = 2) -> str:
        """Pretty by default: this file gets opened by people, not just tools."""
        return json.dumps(self.to_dict(), indent=indent, sort_keys=False) + "\n"

    def to_html(self) -> str:
        return render_html(self)


def _iso(moment: datetime) -> str:
    return moment.isoformat(timespec="seconds")


# --- presentation helpers (shared by the HTML and the terminal) -----------


def money(amount: float | None, *, precise: bool = False) -> str:
    """`$1,284` for anything substantial, `$3.65` when the cents matter."""
    if amount is None:
        return "—"
    if precise or abs(amount) < 10:
        return f"${amount:,.2f}"
    return f"${amount:,.0f}"


def percent(fraction: float | None) -> str:
    if fraction is None:
        return "—"
    if fraction < 0.01:
        return "under 1%"
    return f"{fraction:.0%}"


def plural(count: int, singular: str, many: str | None = None) -> str:
    return singular if count == 1 else (many or f"{singular}s")


#: Severity to the status palette. Each one is always drawn with its word
#: next to it — the colour is the second signal, never the only one.
SEVERITY_STYLE: dict[str, str] = {
    Severity.HIGH.value: "critical",
    Severity.MEDIUM.value: "serious",
    Severity.LOW.value: "warning",
}


def render_html(result: ScanResult) -> str:
    """Render the standalone HTML report."""
    from jinja2 import Environment, StrictUndefined, select_autoescape

    env = Environment(
        autoescape=select_autoescape(default_for_string=True, default=True),
        trim_blocks=True,
        lstrip_blocks=True,
        undefined=StrictUndefined,
        keep_trailing_newline=True,
    )
    env.filters["money"] = money
    env.filters["percent"] = percent
    env.filters["plural"] = plural
    template = env.from_string(_load_template())
    return template.render(
        result=result,
        groups=result.groups(),
        severity_style=SEVERITY_STYLE,
        generated_at=result.finished_at.strftime("%d %B %Y at %H:%M UTC"),
        version=result.version,
    )


def _load_template() -> str:
    return (
        resources.files("preflight")
        .joinpath("templates", TEMPLATE_NAME)
        .read_text(encoding="utf-8")
    )


def write(
    result: ScanResult,
    directory: Any,
    *,
    formats: Sequence[str] = ("html", "json"),
) -> dict[str, Any]:
    """Write the report into `directory`, returning the paths by format."""
    from pathlib import Path

    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    stem = result.filename_stem()
    written: dict[str, Any] = {}
    if "html" in formats:
        path = directory / f"{stem}.html"
        path.write_text(result.to_html(), encoding="utf-8")
        written["html"] = path
    if "json" in formats:
        path = directory / f"{stem}.json"
        path.write_text(result.to_json(), encoding="utf-8")
        written["json"] = path
    return written
