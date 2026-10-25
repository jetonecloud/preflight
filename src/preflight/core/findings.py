"""What a check found, and what we think it's worth.

A check's only output is `Finding`s. Everything a report shows — the headline
number, the ranking, the derivation under each dollar figure — is computed
from them, so a finding has to carry its own evidence rather than leave the
report to guess.

Two rules worth keeping in mind when writing a check:

- **Say how you got the number.** Every `Estimate` carries a `basis` in plain
  words. If you can't write the sentence, you don't understand the estimate
  well enough to show it to someone.
- **Stay quiet when you're not sure.** A finding with `Confidence.LOW` is
  still a claim about someone's account. If a guard can't rule out the
  innocent explanation, don't emit the finding at all.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Any

#: AWS bills by the month on a 730-hour average. Using it everywhere keeps
#: hourly resources comparable with monthly ones.
HOURS_PER_MONTH = 730


class Severity(Enum):
    """How much attention a finding deserves."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def rank(self) -> int:
        """Sort key: 0 is the most severe."""
        return _SEVERITY_ORDER[self]

    @property
    def label(self) -> str:
        return self.value


_SEVERITY_ORDER: dict[Severity, int] = {
    Severity.HIGH: 0,
    Severity.MEDIUM: 1,
    Severity.LOW: 2,
}


class Confidence(Enum):
    """How sure the check is that this is a real problem.

    `HIGH` means the API said so outright — a volume whose state is
    `available` is unattached, full stop. `MEDIUM` means we inferred it from
    usage metrics, which can be wrong if the thing is seasonal. `LOW` means
    the signal is weak enough that the finding leads with "worth a look"
    rather than "fix this".
    """

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def rank(self) -> int:
        return _CONFIDENCE_ORDER[self]

    @property
    def label(self) -> str:
        return self.value


_CONFIDENCE_ORDER: dict[Confidence, int] = {
    Confidence.HIGH: 0,
    Confidence.MEDIUM: 1,
    Confidence.LOW: 2,
}


#: Monthly-dollar thresholds for the default severity. Deliberately low: $20 a
#: month is a rounding error on a big bill and a real line item on a small one,
#: and the people running Preflight are usually the second kind.
HIGH_SEVERITY_USD = 100.0
MEDIUM_SEVERITY_USD = 20.0


def severity_for(monthly_usd: float | None) -> Severity:
    """Default severity from what a finding costs per month."""
    if monthly_usd is None:
        return Severity.LOW
    if monthly_usd >= HIGH_SEVERITY_USD:
        return Severity.HIGH
    if monthly_usd >= MEDIUM_SEVERITY_USD:
        return Severity.MEDIUM
    return Severity.LOW


def at_least(floor: Severity, monthly_usd: float | None) -> Severity:
    """The severity the cost implies, but never gentler than `floor`.

    For findings where the dollar figure understates the problem: a stopped
    database that restarts itself next week is worth reading about even if
    its storage only costs $12 a month.
    """
    implied = severity_for(monthly_usd)
    return implied if implied.rank <= floor.rank else floor


@dataclass(frozen=True)
class Estimate:
    """A dollar figure and the arithmetic behind it.

    `basis` is shown directly under the number in the report, so write it as a
    sentence someone can check with a calculator and the AWS pricing page:
    `"100 GB x $0.08/GB-month (gp3, us-east-1 list price)."`
    """

    monthly_usd: float
    basis: str

    @property
    def annual_usd(self) -> float:
        return self.monthly_usd * 12

    def to_dict(self) -> dict[str, Any]:
        return {
            "monthly_usd": round(self.monthly_usd, 2),
            "annual_usd": round(self.annual_usd, 2),
            "basis": self.basis,
        }


@dataclass(frozen=True)
class Resource:
    """The thing a finding is about.

    `kind` is Preflight's own label rather than an AWS one (`ec2:volume`,
    `rds:snapshot`), because the report groups by it and the AWS names aren't
    consistent enough to read well in a table.
    """

    id: str
    kind: str
    region: str
    name: str | None = None
    arn: str | None = None
    tags: Mapping[str, str] = field(default_factory=dict)

    @property
    def label(self) -> str:
        """What to call it on screen: the Name tag if it has one, else the ID."""
        return f"{self.name} ({self.id})" if self.name else self.id

    @property
    def owner(self) -> str | None:
        """Whoever a tag says owns this, if anyone does."""
        for key in ("Owner", "owner", "Team", "team", "Contact", "contact"):
            value = self.tags.get(key)
            if value:
                return value
        return None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "region": self.region,
            "name": self.name,
            "arn": self.arn,
            "tags": dict(self.tags),
        }


@dataclass(frozen=True)
class Finding:
    """One thing worth fixing, in one account.

    `id` is stable across scans — same resource, same check, same string — so
    two reports can be diffed to see what was actually fixed between them.
    """

    check: str
    module: str
    title: str
    resource: Resource
    evidence: Sequence[str]
    recommendation: str
    confidence: Confidence = Confidence.HIGH
    estimate: Estimate | None = None
    severity: Severity | None = None

    @property
    def id(self) -> str:
        return f"{self.module}/{self.check}/{self.resource.region}/{self.resource.id}"

    @property
    def level(self) -> Severity:
        """The severity this finding was given, or the one its cost implies."""
        if self.severity is not None:
            return self.severity
        return severity_for(self.monthly_usd)

    @property
    def monthly_usd(self) -> float | None:
        return self.estimate.monthly_usd if self.estimate else None

    @property
    def annual_usd(self) -> float | None:
        return self.estimate.annual_usd if self.estimate else None

    @property
    def sort_key(self) -> tuple[Any, ...]:
        """Biggest saving first, then severity, then confidence, then the ID.

        The trailing ID keeps the order stable between two scans of an
        unchanged account, which is what makes the reports diffable.
        """
        return (
            -(self.monthly_usd or 0.0),
            self.level.rank,
            self.confidence.rank,
            self.id,
        )

    def redacted(self, redactor: Any) -> Finding:
        """A copy with account and resource identifiers run through `redactor`.

        The resource is pseudonymised first, so the alias is registered
        before the evidence that mentions it gets scrubbed.
        """
        resource = Resource(
            id=redactor.identifier(self.resource.id, self.resource.kind),
            kind=self.resource.kind,
            region=self.resource.region,
            name=redactor.name(self.resource.name),
            arn=redactor.arn(self.resource.arn),
            tags={} if redactor.active else dict(self.resource.tags),
        )
        return replace(
            self,
            title=redactor.text(self.title),
            resource=resource,
            evidence=tuple(redactor.text(line) for line in self.evidence),
            recommendation=redactor.text(self.recommendation),
            estimate=(
                Estimate(self.estimate.monthly_usd, redactor.text(self.estimate.basis))
                if self.estimate
                else None
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "check": self.check,
            "module": self.module,
            "title": self.title,
            "severity": self.level.value,
            "confidence": self.confidence.value,
            "resource": self.resource.to_dict(),
            "evidence": list(self.evidence),
            "recommendation": self.recommendation,
            "estimated_monthly_savings_usd": (
                round(self.monthly_usd, 2) if self.monthly_usd is not None else None
            ),
            "estimated_annual_savings_usd": (
                round(self.annual_usd, 2) if self.annual_usd is not None else None
            ),
            "estimate_basis": self.estimate.basis if self.estimate else None,
        }


def rank(findings: Sequence[Finding]) -> tuple[Finding, ...]:
    """Findings in the order a reader should work through them."""
    return tuple(sorted(findings, key=lambda finding: finding.sort_key))


def total_monthly(findings: Sequence[Finding]) -> float:
    """What the whole list is worth per month, counting only priced findings."""
    return sum(finding.monthly_usd or 0.0 for finding in findings)


def count_by_severity(findings: Sequence[Finding]) -> dict[str, int]:
    """Findings per severity, always with all three keys so charts don't gap."""
    counts = {severity.value: 0 for severity in Severity}
    for finding in findings:
        counts[finding.level.value] += 1
    return counts
