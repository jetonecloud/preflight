"""Databases, and what happens to them on a bad day.

A database is usually the one thing in an account that can't just be
replaced: an instance behind a load balancer can be relaunched from an image,
but the data has to come from somewhere. These checks ask the two questions
that decide how bad a bad day gets - is there a standby to fail over to, and
is there anything to restore from.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from preflight.core.findings import Finding, Resource, Severity
from preflight.core.scan import ScanContext, ignored, tags_to_dict
from preflight.modules.base import Check
from preflight.modules.reliability.common import (
    MODULE,
    confidence_for,
    environment_caveat,
    non_production,
    too_new,
)

#: Editions that can't run Multi-AZ at all, so suggesting it would be noise.
NO_MULTI_AZ_ENGINES = frozenset({"sqlserver-ex"})

#: A snapshot this recent means backups are happening some other way - a
#: nightly script, or AWS Backup - and the retention setting doesn't matter.
RECENT_SNAPSHOT_DAYS = 2

#: Past this, a restore would lose enough to call it high severity anyway.
STALE_SNAPSHOT_DAYS = 30


def _databases(ctx: ScanContext, region: str) -> list[dict[str, Any]]:
    return ctx.collect("rds:DescribeDBInstances", "DBInstances", region=region)


# --- databases in one zone ------------------------------------------------


def single_az_databases(ctx: ScanContext) -> Iterator[Finding]:
    """Databases with no standby in another zone, and Aurora clusters of one."""
    for region in ctx.regions:
        clusters: dict[str, list[dict[str, Any]]] = {}
        for database in _databases(ctx, region):
            if database.get("DBInstanceStatus") != "available":
                continue
            cluster = database.get("DBClusterIdentifier")
            if cluster:
                clusters.setdefault(str(cluster), []).append(database)
                continue
            ctx.looked_at()
            if database.get("MultiAZ"):
                continue
            if database.get("ReadReplicaSourceDBInstanceIdentifier"):
                # A replica is somebody's spare, not the thing to protect.
                continue
            if str(database.get("Engine") or "") in NO_MULTI_AZ_ENGINES:
                continue
            tags = tags_to_dict(database.get("TagList"))
            if ignored(tags) or non_production(tags):
                continue
            if too_new(ctx, database.get("InstanceCreateTime")):
                continue
            yield _instance_finding(ctx, region, database, tags)

        for cluster, members in sorted(clusters.items()):
            ctx.looked_at()
            if len(members) > 1:
                continue
            (only,) = members
            tags = tags_to_dict(only.get("TagList"))
            if ignored(tags) or non_production(tags):
                continue
            if too_new(ctx, only.get("InstanceCreateTime")):
                continue
            yield _cluster_finding(ctx, region, cluster, only, tags)


def _instance_finding(
    ctx: ScanContext, region: str, database: dict[str, Any], tags: dict[str, str]
) -> Finding:
    identifier = str(database.get("DBInstanceIdentifier"))
    engine = str(database.get("Engine") or "database")
    zone = database.get("AvailabilityZone")
    evidence = [
        f"Multi-AZ is off: it runs in one Availability Zone{f' ({zone})' if zone else ''} "
        "with no standby.",
        "If that zone has trouble or the host fails, the database is down until "
        "RDS brings up a replacement and replays it from storage - minutes at best, "
        "and every write fails in the meantime.",
    ]
    caveat = environment_caveat(tags)
    if caveat:
        evidence.append(caveat)
    return Finding(
        check="single-az-databases",
        module=MODULE,
        title=f"{engine} database with no standby",
        resource=Resource(
            id=identifier,
            kind="rds:db",
            region=region,
            arn=database.get("DBInstanceArn") or ctx.arn("rds", region, f"db:{identifier}"),
            tags=tags,
        ),
        evidence=tuple(evidence),
        recommendation=(
            "Turn on Multi-AZ. RDS keeps a synchronous standby in another zone and "
            "fails over to it in a minute or two, on the same endpoint. It roughly "
            "doubles the instance cost; the change itself causes no downtime, but "
            "schedule it for a quiet hour because I/O slows while the standby is built."
        ),
        confidence=confidence_for(tags),
        severity=Severity.MEDIUM,
    )


def _cluster_finding(
    ctx: ScanContext,
    region: str,
    cluster: str,
    only: dict[str, Any],
    tags: dict[str, str],
) -> Finding:
    engine = str(only.get("Engine") or "aurora")
    evidence = [
        f"The cluster has one instance ({only.get('DBInstanceIdentifier')}) and no "
        "replica to promote.",
        "Aurora keeps the data in three zones whatever you do, but with nothing to "
        "fail over to, losing the writer means waiting for a new one to be created "
        "- typically ten minutes or more.",
    ]
    caveat = environment_caveat(tags)
    if caveat:
        evidence.append(caveat)
    return Finding(
        check="single-az-databases",
        module=MODULE,
        title=f"{engine} cluster with nothing to fail over to",
        resource=Resource(
            id=cluster,
            kind="rds:cluster",
            region=region,
            arn=ctx.arn("rds", region, f"cluster:{cluster}"),
            tags=tags,
        ),
        evidence=tuple(evidence),
        recommendation=(
            "Add a reader in a different Availability Zone. Aurora promotes it "
            "automatically when the writer fails, usually in under a minute, and it "
            "can take read traffic in the meantime."
        ),
        confidence=confidence_for(tags),
        severity=Severity.MEDIUM,
    )


SINGLE_AZ_DATABASES = Check(
    key="single-az-databases",
    title="Databases with no standby",
    looks_for=(
        "Running databases with Multi-AZ off, and Aurora clusters with no replica to fail over to."
    ),
    actions=("rds:DescribeDBInstances",),
    run=single_az_databases,
)


# --- databases with nothing to restore from -------------------------------


def databases_without_backups(ctx: ScanContext) -> Iterator[Finding]:
    """Databases with automated backups off and no recent snapshot either."""
    for region in ctx.regions:
        for database in _databases(ctx, region):
            if database.get("DBInstanceStatus") != "available":
                continue
            if database.get("DBClusterIdentifier"):
                # Aurora backs up the cluster, and won't let retention go to zero.
                continue
            ctx.looked_at()
            if int(database.get("BackupRetentionPeriod") or 0) > 0:
                continue
            if database.get("ReadReplicaSourceDBInstanceIdentifier"):
                # Replicas are rebuilt from their source, not restored.
                continue
            tags = tags_to_dict(database.get("TagList"))
            if ignored(tags) or non_production(tags):
                continue
            if too_new(ctx, database.get("InstanceCreateTime")):
                continue

            identifier = str(database.get("DBInstanceIdentifier"))
            newest = _newest_snapshot_age(ctx, region, identifier)
            if newest is not None and newest <= RECENT_SNAPSHOT_DAYS:
                continue
            yield _backup_finding(ctx, region, database, tags, newest)


def _newest_snapshot_age(ctx: ScanContext, region: str, identifier: str) -> float | None:
    """Days since the newest finished snapshot of this database, of any kind."""
    ages = [
        age
        for snapshot in ctx.collect(
            "rds:DescribeDBSnapshots",
            "DBSnapshots",
            region=region,
            DBInstanceIdentifier=identifier,
        )
        if snapshot.get("Status") == "available"
        and (age := ctx.days_since(snapshot.get("SnapshotCreateTime"))) is not None
    ]
    return min(ages) if ages else None


def _backup_finding(
    ctx: ScanContext,
    region: str,
    database: dict[str, Any],
    tags: dict[str, str],
    newest: float | None,
) -> Finding:
    identifier = str(database.get("DBInstanceIdentifier"))
    engine = str(database.get("Engine") or "database")
    evidence = [
        "Automated backups are off (backup retention is 0 days), so there's no "
        "point-in-time recovery: a bad migration or a dropped table can't be undone.",
    ]
    if newest is None:
        title = f"{engine} database with nothing to restore from"
        evidence.append("There are no snapshots of it either.")
        severity = Severity.HIGH
    else:
        days = int(newest)
        title = f"{engine} database whose last backup is {days} days old"
        evidence.append(
            f"The newest snapshot is {days} days old: restoring it would lose "
            "everything written since."
        )
        severity = Severity.HIGH if newest > STALE_SNAPSHOT_DAYS else Severity.MEDIUM
    caveat = environment_caveat(tags)
    if caveat:
        evidence.append(caveat)
    return Finding(
        check="databases-without-backups",
        module=MODULE,
        title=title,
        resource=Resource(
            id=identifier,
            kind="rds:db",
            region=region,
            arn=database.get("DBInstanceArn") or ctx.arn("rds", region, f"db:{identifier}"),
            tags=tags,
        ),
        evidence=tuple(evidence),
        recommendation=(
            "Set a backup retention period of at least 7 days. Automated backups "
            "cost nothing up to the size of the database, and give you a restore "
            "to any second inside the window. Changing it from 0 restarts the "
            "instance, so do it in a maintenance window."
        ),
        confidence=confidence_for(tags),
        severity=severity,
    )


DATABASES_WITHOUT_BACKUPS = Check(
    key="databases-without-backups",
    title="Databases with nothing to restore from",
    looks_for="Running databases with automated backups off and no recent snapshot.",
    actions=("rds:DescribeDBInstances", "rds:DescribeDBSnapshots"),
    run=databases_without_backups,
)
