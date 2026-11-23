"""Logs that are kept forever because nobody said otherwise.

A CloudWatch log group created by Lambda, ECS or an agent starts with
"Never expire", and almost nobody goes back to change it. The data is
compressed and cheap per gigabyte, which is exactly why it gets forgotten:
it grows every day, it's billed every month, and the oldest of it is the
part nobody will ever read.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any

from preflight.core.findings import Confidence, Finding, Resource, Severity
from preflight.core.pricing import log_storage_monthly
from preflight.core.scan import ScanContext, ignored
from preflight.modules.base import Check

MODULE = "observability"

#: A group holding less than this isn't worth a line in the report, whatever
#: its retention. A gigabyte of compressed logs costs three cents a month.
MIN_STORED_GB = 1.0

#: Past this a forgotten log group stops being tidiness and starts being a
#: line item - and usually a sign that something is far chattier than it
#: needs to be.
LARGE_STORED_GB = 50.0

#: A log group made this week may well be about to get its retention set by
#: whatever created it. Give it a week before saying anything.
MIN_GROUP_AGE_DAYS = 7

BYTES_PER_GB = 1024**3


def log_groups_kept_forever(ctx: ScanContext) -> Iterator[Finding]:
    """Log groups with no retention setting and enough data to matter."""
    for region in ctx.regions:
        for group in ctx.collect("logs:DescribeLogGroups", "logGroups", region=region):
            ctx.looked_at()
            if group.get("retentionInDays"):
                continue

            stored_gb = float(group.get("storedBytes") or 0) / BYTES_PER_GB
            if stored_gb < MIN_STORED_GB:
                continue

            created = _from_millis(group.get("creationTime"))
            age = ctx.days_since(created)
            if age is not None and age < MIN_GROUP_AGE_DAYS:
                continue

            name = str(group.get("logGroupName"))
            arn = _group_arn(ctx, region, group)
            tags = dict(ctx.tags_for(region, arn))
            if ignored(tags):
                continue

            monthly, basis = log_storage_monthly(stored_gb)
            evidence = [
                "Retention is 'Never expire', so every event it has ever received is still stored.",
                f"Holding {stored_gb:,.1f} GB in {region}, costing about "
                f"${monthly:,.2f}/month to keep. {basis}",
            ]
            if age is not None:
                evidence.append(
                    f"Created {age:,.0f} days ago; everything older than the "
                    "retention you'd choose would go."
                )
            evidence.append(
                "No estimate is given: how much a retention period saves depends "
                "on how the data is spread over time, which the API doesn't say."
            )

            yield Finding(
                check="log-groups-kept-forever",
                module=MODULE,
                title=f"Log group kept forever ({stored_gb:,.0f} GB)",
                resource=Resource(
                    id=name,
                    kind="logs:log-group",
                    region=region,
                    arn=arn,
                    tags=tags,
                ),
                evidence=tuple(evidence),
                recommendation=(
                    "Set a retention period - 30 days is plenty for most application "
                    "logs, a year for audit trails. If something has to be kept "
                    "longer, export it to S3 and tag this group 'preflight:ignore'."
                ),
                confidence=Confidence.HIGH,
                severity=Severity.MEDIUM if stored_gb >= LARGE_STORED_GB else Severity.LOW,
            )


def _from_millis(value: Any) -> Any:
    """CloudWatch Logs gives times as epoch milliseconds, not datetimes."""
    if isinstance(value, int | float) and not isinstance(value, bool):
        return datetime.fromtimestamp(value / 1000, tz=UTC)
    return value


def _group_arn(ctx: ScanContext, region: str, group: dict[str, Any]) -> str:
    """The log group's ARN in the form the tagging API uses: no trailing `:*`."""
    arn = group.get("logGroupArn") or group.get("arn")
    if arn:
        return str(arn).removesuffix(":*")
    return ctx.arn("logs", region, f"log-group:{group.get('logGroupName')}")


LOG_GROUPS_KEPT_FOREVER = Check(
    key="log-groups-kept-forever",
    title="Log groups kept forever",
    looks_for="CloudWatch log groups with no retention period, growing every day.",
    actions=("logs:DescribeLogGroups",),
    run=log_groups_kept_forever,
)
