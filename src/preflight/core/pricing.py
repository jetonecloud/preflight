"""What AWS charges, so a finding can say what it's worth.

Two sources, in this order:

1. **The table below.** Per-unit list prices for the handful of things the
   cost checks care about. Hard-coded on purpose: it needs no permissions, no
   network, and no waiting, and it's auditable in one screen.
2. **`pricing:GetProducts`.** Only for EC2 on-demand instance rates, where a
   table of every instance type in every region isn't something you'd want to
   read or maintain. There's a small fallback table for the common families,
   and a finding that can't be priced says so rather than guessing.

Everything in the table is a **us-east-1** list price. That's deliberate:
us-east-1 is at or near the cheapest for all of these, so pricing a volume in
eu-west-2 at us-east-1 rates understates the saving rather than inflating it.
Estimates are supposed to be the number you'd be comfortable defending on a
call, not the biggest one we can justify.

Prices exclude tax, Savings Plans, Reserved Instances, private pricing and
EDP discounts — which, again, makes the estimates conservative for anyone who
has them. The report says so.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from preflight.core.findings import HOURS_PER_MONTH

#: When the table below was last checked against AWS's public pricing pages.
#: Bump it in the same commit that changes a number, and nowhere else.
PRICES_REVIEWED = "2026-10"

#: Shown under every figure derived from the table.
LIST_PRICE_NOTE = f"us-east-1 list price, reviewed {PRICES_REVIEWED}"


@dataclass(frozen=True)
class Price:
    """A unit price, and enough context to check it by hand."""

    amount: float
    unit: str
    note: str = LIST_PRICE_NOTE

    def monthly(self, quantity: float = 1.0) -> float:
        """What `quantity` of this costs for a month."""
        per_month = self.amount * (HOURS_PER_MONTH if self.unit == "hour" else 1.0)
        return per_month * quantity

    def describe(self, quantity: float, what: str) -> str:
        """The derivation line a finding shows under its dollar figure."""
        if self.unit == "hour":
            rate = f"${self.amount:,.3f}/hour x {HOURS_PER_MONTH} hours"
        else:
            rate = f"${self.amount:,.4f}/{self.unit}".rstrip("0").rstrip(".")
        amount = f"{quantity:,.0f}" if quantity != 1 else ""
        lead = f"{amount} {what}".strip()
        return f"{lead} at {rate} ({self.note})."


# --- EBS ------------------------------------------------------------------
# https://aws.amazon.com/ebs/pricing/

EBS_GB_MONTH: Mapping[str, Price] = {
    "gp3": Price(0.080, "GB-month"),
    "gp2": Price(0.100, "GB-month"),
    "io1": Price(0.125, "GB-month"),
    "io2": Price(0.125, "GB-month"),
    "st1": Price(0.045, "GB-month"),
    "sc1": Price(0.015, "GB-month"),
    "standard": Price(0.050, "GB-month"),
}

#: Volume types we don't know: priced as the cheapest one we do, so an
#: unfamiliar type can never inflate an estimate.
EBS_FALLBACK = Price(0.015, "GB-month", f"{LIST_PRICE_NOTE}, cheapest EBS tier")

#: Standard-tier EBS snapshot storage. Snapshots are incremental, so this is
#: an upper bound applied to the volume size — see `snapshot_monthly`.
SNAPSHOT_GB_MONTH = Price(0.050, "GB-month")

#: How much of a snapshot's nominal volume size we assume is actually billed.
#: Snapshots only store changed blocks, and a 100 GB volume rarely means 100
#: GB of snapshot. A third is a guess, but it's a guess in the user's favour.
SNAPSHOT_FILL_RATIO = 0.33


# --- Network --------------------------------------------------------------
# https://aws.amazon.com/vpc/pricing/ and https://aws.amazon.com/ec2/pricing/

#: Every public IPv4 address is charged by the hour, attached or not.
PUBLIC_IPV4_HOUR = Price(0.005, "hour")

#: NAT gateway, per hour. Data processing is extra and not counted here.
NAT_GATEWAY_HOUR = Price(0.045, "hour")

#: Load balancers, per hour. LCU/capacity-unit charges are extra and not
#: counted here, which is the right call for a balancer we think is idle.
LOAD_BALANCER_HOUR: Mapping[str, Price] = {
    "application": Price(0.0225, "hour"),
    "network": Price(0.0225, "hour"),
    "gateway": Price(0.0125, "hour"),
    "classic": Price(0.025, "hour"),
}


# --- RDS ------------------------------------------------------------------
# https://aws.amazon.com/rds/pricing/

RDS_STORAGE_GB_MONTH: Mapping[str, Price] = {
    "gp2": Price(0.115, "GB-month"),
    "gp3": Price(0.115, "GB-month"),
    "io1": Price(0.125, "GB-month"),
    "io2": Price(0.125, "GB-month"),
    "standard": Price(0.100, "GB-month"),
    "magnetic": Price(0.100, "GB-month"),
}

RDS_STORAGE_FALLBACK = Price(0.100, "GB-month", f"{LIST_PRICE_NOTE}, cheapest RDS storage tier")

#: Manual RDS snapshot storage beyond the free allowance.
RDS_SNAPSHOT_GB_MONTH = Price(0.095, "GB-month")


# --- EC2 on-demand --------------------------------------------------------

#: Linux/shared-tenancy on-demand rates for the types small teams actually
#: run, used when `pricing:GetProducts` isn't available or wasn't granted.
#: Anything outside this table falls through to the pricing API, and a type
#: neither source knows produces a finding with no dollar figure.
EC2_HOURLY_FALLBACK: Mapping[str, float] = {
    "t2.micro": 0.0116,
    "t2.small": 0.023,
    "t2.medium": 0.0464,
    "t2.large": 0.0928,
    "t2.xlarge": 0.1856,
    "t3.micro": 0.0104,
    "t3.small": 0.0208,
    "t3.medium": 0.0416,
    "t3.large": 0.0832,
    "t3.xlarge": 0.1664,
    "t3.2xlarge": 0.3328,
    "t3a.micro": 0.0094,
    "t3a.small": 0.0188,
    "t3a.medium": 0.0376,
    "t3a.large": 0.0752,
    "t3a.xlarge": 0.1504,
    "t4g.micro": 0.0084,
    "t4g.small": 0.0168,
    "t4g.medium": 0.0336,
    "t4g.large": 0.0672,
    "t4g.xlarge": 0.1344,
    "m5.large": 0.096,
    "m5.xlarge": 0.192,
    "m5.2xlarge": 0.384,
    "m5.4xlarge": 0.768,
    "m6i.large": 0.096,
    "m6i.xlarge": 0.192,
    "m6i.2xlarge": 0.384,
    "m6i.4xlarge": 0.768,
    "c5.large": 0.085,
    "c5.xlarge": 0.170,
    "c5.2xlarge": 0.340,
    "c5.4xlarge": 0.680,
    "c6i.large": 0.085,
    "c6i.xlarge": 0.170,
    "c6i.2xlarge": 0.340,
    "r5.large": 0.126,
    "r5.xlarge": 0.252,
    "r5.2xlarge": 0.504,
    "r6i.large": 0.126,
    "r6i.xlarge": 0.252,
    "r6i.2xlarge": 0.504,
}

#: Instance sizes in order, so "one size down" is a list index.
SIZE_LADDER: tuple[str, ...] = (
    "nano",
    "micro",
    "small",
    "medium",
    "large",
    "xlarge",
    "2xlarge",
    "3xlarge",
    "4xlarge",
    "6xlarge",
    "8xlarge",
    "9xlarge",
    "12xlarge",
    "16xlarge",
    "18xlarge",
    "24xlarge",
    "32xlarge",
    "48xlarge",
)


#: How many rungs down to consider before giving up. The ladder is shared by
#: every family, but no family has every rung — `c6i` skips 18xlarge, `c5`
#: skips 16xlarge — so the nearest smaller size is sometimes a type that
#: doesn't exist. Trying a couple more finds the real one; trying many would
#: start comparing an instance against something half its size.
SMALLER_STEPS = 3


def smaller_sizes(instance_type: str, limit: int = SMALLER_STEPS) -> list[str]:
    """Candidate sizes below this one, nearest first.

    Whether each candidate exists is settled by whether it can be priced,
    which is the only question that matters to a saving estimate.
    """
    family, _, size = instance_type.partition(".")
    if not family or size not in SIZE_LADDER:
        return []
    index = SIZE_LADDER.index(size)
    lower = SIZE_LADDER[max(index - limit, 0) : index]
    return [f"{family}.{rung}" for rung in reversed(lower)]


def one_size_down(instance_type: str) -> str | None:
    """`m5.xlarge` -> `m5.large`. `None` if it's already the smallest."""
    candidates = smaller_sizes(instance_type, limit=1)
    return candidates[0] if candidates else None


def ebs_monthly(volume_type: str, size_gb: float) -> tuple[float, str]:
    """What an EBS volume costs a month, and how that was worked out."""
    price = EBS_GB_MONTH.get(volume_type.lower(), EBS_FALLBACK)
    return price.monthly(size_gb), price.describe(size_gb, f"GB of {volume_type}")


def snapshot_monthly(size_gb: float) -> tuple[float, str]:
    """What a snapshot costs a month, discounted for incremental storage."""
    billed = size_gb * SNAPSHOT_FILL_RATIO
    amount = SNAPSHOT_GB_MONTH.monthly(billed)
    basis = (
        f"{size_gb:,.0f} GB volume, charged incrementally: we assume "
        f"{SNAPSHOT_FILL_RATIO:.0%} of it ({billed:,.0f} GB) at "
        f"${SNAPSHOT_GB_MONTH.amount:.3f}/GB-month ({SNAPSHOT_GB_MONTH.note})."
    )
    return amount, basis


def rds_storage_monthly(storage_type: str, size_gb: float) -> tuple[float, str]:
    """What an RDS instance's allocated storage costs a month."""
    price = RDS_STORAGE_GB_MONTH.get(storage_type.lower(), RDS_STORAGE_FALLBACK)
    return price.monthly(size_gb), price.describe(size_gb, f"GB of RDS {storage_type} storage")


class PriceBook:
    """Instance prices, looked up once and remembered.

    Wraps `pricing:GetProducts` so the checks don't have to care whether the
    permission was granted, the call failed, or the answer came from the
    fallback table. `hourly()` returns `None` when nothing can price the type,
    and the caller drops the dollar figure rather than inventing one.
    """

    def __init__(self, client_factory: Any = None) -> None:
        self._client_factory = client_factory
        self._cache: dict[tuple[str, str], float | None] = {}
        self._api_failed = False
        self._api_used = False
        #: Set once if the pricing API was unreachable or not permitted, so
        #: the report can explain why some findings have no dollar figure.
        self.degraded_reason: str | None = None

    @property
    def used_api(self) -> bool:
        """Whether any figure in this scan came from the live pricing API."""
        return self._api_used

    def hourly(self, region: str, instance_type: str) -> float | None:
        """On-demand Linux rate for an instance type, or `None` if unknown."""
        key = (region, instance_type)
        if key not in self._cache:
            self._cache[key] = self._resolve(region, instance_type)
        return self._cache[key]

    def _resolve(self, region: str, instance_type: str) -> float | None:
        price = self._from_api(region, instance_type)
        if price is not None:
            return price
        return EC2_HOURLY_FALLBACK.get(instance_type)

    def _from_api(self, region: str, instance_type: str) -> float | None:
        client = self._pricing_client()
        if client is None:
            return None
        try:
            response = client.get_products(
                ServiceCode="AmazonEC2",
                MaxResults=10,
                Filters=[
                    {"Type": "TERM_MATCH", "Field": field, "Value": value}
                    for field, value in (
                        ("instanceType", instance_type),
                        ("regionCode", region),
                        ("operatingSystem", "Linux"),
                        ("tenancy", "Shared"),
                        ("preInstalledSw", "NA"),
                        ("capacitystatus", "Used"),
                        ("licenseModel", "No License required"),
                    )
                ],
            )
        except Exception as exc:  # noqa: BLE001 - any failure means "use the table"
            self._api_failed = True
            self.degraded_reason = _short_reason(exc)
            return None
        price = _cheapest_on_demand(response.get("PriceList", ()))
        if price is not None:
            self._api_used = True
        return price

    def _pricing_client(self) -> Any:
        """Ask the factory every time.

        The factory is the scan context, which re-checks that the running
        check declared `pricing:GetProducts` — so the price lookup can't be
        the one call that slips past the permission contract. Building the
        client itself is cheap; the session caches it.

        Deliberately not wrapped in a `try`: the factory refusing is a bug
        in the check's declaration, and swallowing it here would turn a
        loud, immediate failure into a silently missing dollar figure.
        """
        if self._api_failed or self._client_factory is None:
            return None
        return self._client_factory()


def _cheapest_on_demand(price_list: Any) -> float | None:
    """Pull the lowest USD on-demand rate out of a `GetProducts` response.

    The payload is a list of JSON *strings*, each a product with its terms
    nested several layers deep under opaque offer codes. Anything unexpected
    in there means no price rather than a wrong one.
    """
    rates: list[float] = []
    for entry in price_list:
        try:
            product = json.loads(entry) if isinstance(entry, str) else entry
            terms = product["terms"]["OnDemand"]
        except (KeyError, TypeError, ValueError):
            continue
        for term in terms.values():
            for dimension in term.get("priceDimensions", {}).values():
                if dimension.get("unit") not in ("Hrs", "Hours"):
                    continue
                raw = dimension.get("pricePerUnit", {}).get("USD")
                try:
                    rate = float(raw)
                except (TypeError, ValueError):
                    continue
                # A $0.00 dimension is a free-tier or placeholder row.
                if rate > 0:
                    rates.append(rate)
    return min(rates) if rates else None


def _short_reason(exc: Exception) -> str:
    """One readable line for the report's notes, never a stack trace."""
    name = type(exc).__name__
    text = str(exc).strip().splitlines()
    return f"{name}: {text[0]}" if text else name
