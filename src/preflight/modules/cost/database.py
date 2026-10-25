"""Databases that cost money while doing nothing.

RDS has a specific trap worth knowing about: stopping an instance doesn't
stop the bill, and it doesn't stay stopped. AWS restarts a stopped RDS
instance after seven days, so "we stopped it to save money" quietly becomes
"we're paying full price again" a week later, and nobody gets an email
about it.
"""

from __future__ import annotations

from collections.abc import Iterator

from preflight.core.findings import (
    Confidence,
    Estimate,
    Finding,
    Resource,
    Severity,
    at_least,
)
from preflight.core.pricing import (
    RDS_SNAPSHOT_GB_MONTH,
    SNAPSHOT_FILL_RATIO,
    rds_storage_monthly,
)
from preflight.core.scan import ScanContext, ignored, name_of, tags_to_dict
from preflight.modules.base import Check

MODULE = "cost"

#: Manual snapshots are kept deliberately, so we leave them alone for a good
#: while. Six months is long enough that "we might need to roll back" has
#: stopped being true.
OLD_MANUAL_SNAPSHOT_DAYS = 180


def stopped_databases(ctx: ScanContext) -> Iterator[Finding]:
    """Stopped RDS instances, which are still billed for storage and restart themselves."""
    for region in ctx.regions:
        for database in ctx.collect("rds:DescribeDBInstances", "DBInstances", region=region):
            ctx.looked_at()
            if database.get("DBInstanceStatus") != "stopped":
                continue

            tags = tags_to_dict(database.get("TagList"))
            if ignored(tags):
                continue

            identifier = str(database.get("DBInstanceIdentifier") or "")
            size = float(database.get("AllocatedStorage") or 0)
            storage_type = str(database.get("StorageType") or "gp2")
            if size <= 0:
                continue

            monthly, basis = rds_storage_monthly(storage_type, size)
            engine = str(database.get("Engine") or "database")

            evidence = [
                "The instance is stopped, but RDS keeps billing for its allocated "
                "storage and any backups.",
                f"{size:,.0f} GB of {storage_type} storage for a "
                f"{database.get('DBInstanceClass')} {engine} instance.",
                "AWS restarts a stopped RDS instance automatically after 7 days, "
                "so the compute charge comes back on its own.",
            ]
            if database.get("MultiAZ"):
                evidence.append("Multi-AZ, so the storage is charged twice over.")

            yield Finding(
                check="stopped-databases",
                module=MODULE,
                title=f"Stopped {engine} instance still billing for storage",
                resource=Resource(
                    id=identifier,
                    kind="rds:instance",
                    region=region,
                    name=name_of(tags),
                    arn=str(database.get("DBInstanceArn") or ""),
                    tags=tags,
                ),
                evidence=tuple(evidence),
                recommendation=(
                    "Decide one way or the other: take a final snapshot and delete "
                    "it, or start it and use it. A stopped RDS instance is the "
                    "worst of both — you pay for it and it isn't available."
                ),
                confidence=Confidence.HIGH,
                estimate=Estimate(monthly, basis),
                # Worth reading about even on a small instance: the automatic
                # restart is the part that surprises people, not the storage.
                severity=at_least(Severity.MEDIUM, monthly),
            )


def old_database_snapshots(ctx: ScanContext) -> Iterator[Finding]:
    """Manual RDS snapshots old enough that nobody is going to restore them.

    Automated snapshots are left alone entirely: they're governed by the
    instance's retention window, so flagging them would be telling someone
    their backup policy is working.
    """
    for region in ctx.regions:
        for snapshot in ctx.collect(
            "rds:DescribeDBSnapshots",
            "DBSnapshots",
            region=region,
            SnapshotType="manual",
        ):
            ctx.looked_at()
            # The request already asks for manual snapshots only. Checked
            # again here because the consequence of the filter not applying
            # is telling someone their automated backups are waste.
            if snapshot.get("SnapshotType") != "manual":
                continue
            if snapshot.get("Status") != "available":
                continue

            tags = tags_to_dict(snapshot.get("TagList"))
            if ignored(tags):
                continue

            age = ctx.days_since(snapshot.get("SnapshotCreateTime"))
            if age is None or age < OLD_MANUAL_SNAPSHOT_DAYS:
                continue

            identifier = str(snapshot.get("DBSnapshotIdentifier") or "")
            size = float(snapshot.get("AllocatedStorage") or 0)
            if size <= 0:
                continue

            billed = size * SNAPSHOT_FILL_RATIO
            monthly = RDS_SNAPSHOT_GB_MONTH.monthly(billed)
            basis = (
                f"{size:,.0f} GB snapshot, charged incrementally: we assume "
                f"{SNAPSHOT_FILL_RATIO:.0%} of it ({billed:,.0f} GB) at "
                f"${RDS_SNAPSHOT_GB_MONTH.amount:.3f}/GB-month "
                f"({RDS_SNAPSHOT_GB_MONTH.note})."
            )

            kept_for = f"{age / 365:.1f} years" if age >= 365 else f"{age:,.0f} days"
            source = str(snapshot.get("DBInstanceIdentifier") or "an instance")
            evidence = [
                f"Taken manually {age:,.0f} days ago, from {source}.",
                "Manual snapshots are never cleaned up automatically — they "
                "outlive the instance they came from and keep billing.",
                f"Engine {snapshot.get('Engine')}, {size:,.0f} GB allocated.",
            ]

            yield Finding(
                check="old-database-snapshots",
                module=MODULE,
                title=f"Manual database snapshot kept for {kept_for}",
                resource=Resource(
                    id=identifier,
                    kind="rds:snapshot",
                    region=region,
                    name=name_of(tags),
                    arn=str(snapshot.get("DBSnapshotArn") or ""),
                    tags=tags,
                ),
                evidence=tuple(evidence),
                recommendation=(
                    "Check whether anyone would ever restore it. If it's kept for "
                    "a compliance reason, tag it 'preflight:ignore' so it stops "
                    "showing up here; otherwise delete it."
                ),
                confidence=Confidence.MEDIUM,
                estimate=Estimate(monthly, basis),
            )


STOPPED_DATABASES = Check(
    key="stopped-databases",
    title="Stopped RDS instances",
    looks_for="Databases that are stopped but still charged for storage — and restart themselves.",
    actions=("rds:DescribeDBInstances",),
    run=stopped_databases,
)

OLD_DATABASE_SNAPSHOTS = Check(
    key="old-database-snapshots",
    title="Old manual database snapshots",
    looks_for="Manual RDS snapshots old enough that nobody is going to restore them.",
    actions=("rds:DescribeDBSnapshots",),
    run=old_database_snapshots,
)
