"""Whether anything is writing down what happens in the account.

CloudTrail's event history keeps 90 days of management events whether you
ask or not, and it's not enough: it can't be searched across regions, it
can't be kept, and it goes when the account does. A trail is the record
you'd want after an incident - so the check asks whether every scanned
region has one that's actually logging.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from preflight.core.findings import Confidence, Finding, Resource, Severity
from preflight.core.scan import ScanContext, ignored
from preflight.modules.base import Check

MODULE = "security"
GLOBAL = "global"

HISTORY_CAVEAT = (
    "CloudTrail's 90-day event history still exists, but it can't be kept, "
    "exported after the fact, or searched across regions."
)


def trail_coverage(ctx: ScanContext) -> Iterator[Finding]:
    """Regions with no logging trail, and trails that have stopped logging."""
    trails: dict[str, dict[str, Any]] = {}
    covering: dict[str, list[str]] = {}
    for region in ctx.regions:
        ctx.looked_at()
        listed = ctx.collect(
            "cloudtrail:DescribeTrails", "trailList", region=region, includeShadowTrails=True
        )
        for trail in listed:
            arn = str(trail.get("TrailARN") or trail.get("Name"))
            trails.setdefault(arn, trail)
            home = trail.get("HomeRegion") or region
            if trail.get("IsMultiRegionTrail") or home == region:
                covering.setdefault(region, []).append(arn)

    logging = {arn: _is_logging(ctx, trail) for arn, trail in trails.items()}

    stopped: dict[str, list[str]] = {}
    uncovered: list[str] = []
    for region in ctx.regions:
        arns = covering.get(region, [])
        if any(logging[arn] for arn in arns):
            continue
        if arns:
            for arn in arns:
                stopped.setdefault(arn, []).append(region)
        else:
            uncovered.append(region)

    for arn, regions in stopped.items():
        trail = trails[arn]
        home = str(trail.get("HomeRegion") or regions[0])
        tags = dict(ctx.tags_for(home, arn))
        if ignored(tags):
            continue
        name = str(trail.get("Name") or arn)
        yield Finding(
            check="trail-coverage",
            module=MODULE,
            title="Trail that has stopped logging",
            resource=Resource(id=name, kind="cloudtrail:trail", region=home, arn=arn, tags=tags),
            evidence=(
                "The trail exists but isn't logging, so nothing is being recorded for "
                + ", ".join(regions)
                + ".",
                "Logging gets switched off by hand - or by someone who'd rather not be recorded.",
                HISTORY_CAVEAT,
            ),
            recommendation=(
                "Start logging again, find out from the event history who stopped "
                "it and when, and alarm on StopLogging so it can't happen quietly."
            ),
            confidence=Confidence.HIGH,
            severity=Severity.HIGH,
        )

    if not uncovered:
        return
    if not trails and len(uncovered) == len(ctx.regions):
        yield Finding(
            check="trail-coverage",
            module=MODULE,
            title="No CloudTrail trail at all",
            resource=Resource(id=ctx.account_id, kind="cloudtrail:account", region=GLOBAL),
            evidence=(
                "No trail in any scanned region, and no organisation trail reaches "
                "this account: nothing is keeping a record of who did what.",
                HISTORY_CAVEAT,
            ),
            recommendation=(
                "Create one multi-region trail writing to an S3 bucket - management "
                "events only, which costs nothing for the first copy."
            ),
            confidence=Confidence.HIGH,
            severity=Severity.HIGH,
        )
        return
    for region in uncovered:
        yield Finding(
            check="trail-coverage",
            module=MODULE,
            title="Region no trail is recording",
            resource=Resource(id=region, kind="cloudtrail:region", region=region),
            evidence=(
                f"There are trails, but none of them is multi-region or based in {region}.",
                HISTORY_CAVEAT,
            ),
            recommendation=(
                "Make an existing trail multi-region rather than adding one per "
                "region - a region nobody uses is where an attacker would."
            ),
            confidence=Confidence.HIGH,
            severity=Severity.MEDIUM,
        )


def _is_logging(ctx: ScanContext, trail: dict[str, Any]) -> bool:
    arn = str(trail.get("TrailARN") or trail.get("Name"))
    home = trail.get("HomeRegion") or None
    status = ctx.call("cloudtrail:GetTrailStatus", region=home, Name=arn)
    return bool(status.get("IsLogging"))


TRAIL_COVERAGE = Check(
    key="trail-coverage",
    title="CloudTrail coverage",
    looks_for="Regions no CloudTrail trail is recording, and trails that stopped logging.",
    actions=("cloudtrail:DescribeTrails", "cloudtrail:GetTrailStatus"),
    run=trail_coverage,
)
