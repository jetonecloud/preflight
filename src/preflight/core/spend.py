"""What the account actually costs, for context.

A finding worth $40 a month means one thing on a $300 bill and another on a
$30,000 one. Cost Explorer can tell us which, in a single call, so the report
can say "about 8% of last month's bill" instead of leaving the reader to
work out whether to care.

This is context, not a finding. If `ce:GetCostAndUsage` isn't granted, or
Cost Explorer was never enabled on the account, the report simply doesn't
show the comparison — it's never a reason to stop a scan.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from typing import Any

ACTION = "ce:GetCostAndUsage"

#: Unblended cost is what AWS actually invoiced, which is the number the
#: person reading the report will recognise from their bill.
METRIC = "UnblendedCost"

#: How many service lines to keep. Enough to recognise the shape of a bill,
#: short enough to read.
TOP_SERVICES = 5


@dataclass(frozen=True)
class ServiceSpend:
    name: str
    amount_usd: float


@dataclass(frozen=True)
class Spend:
    """One full calendar month of spend, with the biggest services named."""

    period: str  # "2026-09"
    total_usd: float
    currency: str
    services: tuple[ServiceSpend, ...] = ()

    def share_of(self, monthly_usd: float) -> float | None:
        """`monthly_usd` as a fraction of the bill, or `None` if there's no bill."""
        if self.total_usd <= 0:
            return None
        return monthly_usd / self.total_usd

    def to_dict(self) -> dict[str, Any]:
        return {
            "period": self.period,
            "total_usd": round(self.total_usd, 2),
            "currency": self.currency,
            "top_services": [
                {"name": service.name, "amount_usd": round(service.amount_usd, 2)}
                for service in self.services
            ],
        }


def last_full_month(today: date) -> tuple[date, date]:
    """The first day of last month, and the first day of this one.

    Cost Explorer's `End` is exclusive, so this pair is exactly one calendar
    month and never includes the partial month in progress — a half-finished
    month would make every percentage in the report look twice as good as it
    is.
    """
    this_month = today.replace(day=1)
    previous = (this_month - timedelta(days=1)).replace(day=1)
    return previous, this_month


def read(session: Any, *, today: date | None = None) -> Spend | None:
    """Last full month's spend, or `None` if we can't see it.

    Never raises: this is the one read where "we couldn't" is an acceptable
    answer, because nothing in the report depends on it.
    """
    # Imported here, not at the top: a module a check can reach must not
    # pull botocore in just by being imported. See core/scan.py.
    from preflight.core import aws

    start, end = last_full_month(today or datetime.now(UTC).date())
    try:
        response = aws.call(
            session.client("ce"),
            ACTION,
            TimePeriod={"Start": start.isoformat(), "End": end.isoformat()},
            Granularity="MONTHLY",
            Metrics=[METRIC],
            GroupBy=[{"Type": "DIMENSION", "Key": "SERVICE"}],
        )
    except aws.AwsError:
        return None
    return _parse(response, period=start.strftime("%Y-%m"))


def _parse(response: dict[str, Any], *, period: str) -> Spend | None:
    results: Sequence[dict[str, Any]] = response.get("ResultsByTime", ())
    if not results:
        return None
    groups = results[0].get("Groups", ())
    currency = "USD"
    services: list[ServiceSpend] = []
    total = 0.0
    for group in groups:
        metric = group.get("Metrics", {}).get(METRIC, {})
        try:
            amount = float(metric.get("Amount", 0.0))
        except (TypeError, ValueError):
            continue
        currency = str(metric.get("Unit") or currency)
        keys = group.get("Keys", ())
        name = str(keys[0]) if keys else "Other"
        total += amount
        services.append(ServiceSpend(name, amount))

    if not groups:
        # No GroupBy support on this response shape: fall back to the total.
        metric = results[0].get("Total", {}).get(METRIC, {})
        try:
            total = float(metric.get("Amount", 0.0))
        except (TypeError, ValueError):
            return None
        currency = str(metric.get("Unit") or currency)

    if total <= 0:
        return None

    services.sort(key=lambda service: -service.amount_usd)
    return Spend(
        period=period,
        total_usd=total,
        currency=currency,
        services=tuple(services[:TOP_SERVICES]),
    )
