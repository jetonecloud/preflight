"""Reading CloudWatch, which is how a check tells "unused" from "quiet".

Nothing here decides anything — it fetches series and reports what's in them.
The judgement call ("no bytes through this NAT gateway in two weeks means
nobody is using it") belongs in the check, next to the guard that keeps it
honest.

One thing worth knowing: **an empty series is not a zero.** CloudWatch
returns no datapoints for a metric that was never published, which happens
for a resource created after the window started, for a metric the service
only emits under load, and for a region with nothing in it. Treating that as
"idle" is the easiest way to invent a false positive, so `MetricSeries`
keeps `has_data` separate from `maximum` and every caller has to look at it.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

ACTION = "cloudwatch:GetMetricStatistics"

#: CloudWatch returns at most 1440 datapoints per call, so an hourly period
#: covers 60 days and a daily one covers four years. Neither is close to the
#: windows we ask for.
HOUR = 3600
DAY = 86400

#: Metric reads are independent and latency-bound, so a few at a time turns a
#: minute of waiting into a few seconds. Kept small: the point is to hide the
#: round trips, not to race AWS's throttle limits.
MAX_WORKERS = 8


@dataclass(frozen=True)
class MetricRequest:
    """One series to fetch, tagged with a key the caller can match it back by."""

    key: str
    namespace: str
    metric: str
    dimensions: Mapping[str, str]
    statistics: tuple[str, ...] = ("Maximum",)
    period: int = HOUR
    unit: str | None = None


@dataclass(frozen=True)
class MetricSeries:
    """What CloudWatch had for one metric over the window."""

    key: str
    datapoints: tuple[Mapping[str, Any], ...] = field(default_factory=tuple)

    @property
    def has_data(self) -> bool:
        """Whether CloudWatch published anything at all. Check this first."""
        return bool(self.datapoints)

    @property
    def count(self) -> int:
        return len(self.datapoints)

    def values(self, statistic: str = "Maximum") -> tuple[float, ...]:
        return tuple(
            float(point[statistic]) for point in self.datapoints if point.get(statistic) is not None
        )

    def maximum(self, statistic: str = "Maximum") -> float | None:
        values = self.values(statistic)
        return max(values) if values else None

    def average(self, statistic: str = "Average") -> float | None:
        values = self.values(statistic)
        return sum(values) / len(values) if values else None

    def total(self, statistic: str = "Sum") -> float | None:
        values = self.values(statistic)
        return sum(values) if values else None


def fetch(
    client: Any,
    requests: Sequence[MetricRequest],
    *,
    start: datetime,
    end: datetime,
    region: str | None = None,
    workers: int = MAX_WORKERS,
) -> dict[str, MetricSeries]:
    """Fetch every request against one region, in parallel, in order.

    Raises the first `AwsError` any of them hit — in practice a missing
    `cloudwatch:GetMetricStatistics`, which means the check asking for this
    can't run at all and should be reported as skipped rather than guessed at.
    """
    if not requests:
        return {}

    def one(request: MetricRequest) -> MetricSeries:
        return _series(client, request, start=start, end=end, region=region)

    if len(requests) == 1 or workers <= 1:
        return {series.key: series for series in (one(request) for request in requests)}

    with ThreadPoolExecutor(max_workers=min(workers, len(requests))) as pool:
        results = list(pool.map(one, requests))
    return {series.key: series for series in results}


def _series(
    client: Any,
    request: MetricRequest,
    *,
    start: datetime,
    end: datetime,
    region: str | None,
) -> MetricSeries:
    # Imported here rather than at the top so that declaring a check — which
    # is all `preflight scan` does when it generates a role — never loads
    # botocore. See `tests/test_cli_scan.py::test_scan_does_not_import_an_aws_client`.
    from preflight.core import aws

    params: dict[str, Any] = {
        "Namespace": request.namespace,
        "MetricName": request.metric,
        "Dimensions": [
            {"Name": name, "Value": value} for name, value in request.dimensions.items()
        ],
        "StartTime": start,
        "EndTime": end,
        "Period": request.period,
        "Statistics": list(request.statistics),
    }
    if request.unit:
        params["Unit"] = request.unit
    response = aws.call(client, ACTION, region=region, **params)
    points = tuple(response.get("Datapoints", ()))
    return MetricSeries(request.key, points)


def window_periods(days: int) -> int:
    """A sensible period for a window: hourly up to a month, daily beyond."""
    return HOUR if days <= 30 else DAY
