"""Stopped RDS instances and old manual snapshots."""

from __future__ import annotations

from conftest import days_ago, denied, findings, run, tags

from preflight.core.findings import Confidence, Severity
from preflight.modules.cost.database import (
    OLD_DATABASE_SNAPSHOTS,
    OLD_MANUAL_SNAPSHOT_DAYS,
    STOPPED_DATABASES,
)


def database(identifier="analytics", status="stopped", storage=100, **extra):
    return {
        "DBInstanceIdentifier": identifier,
        "DBInstanceArn": f"arn:aws:rds:us-east-1:123456789012:db:{identifier}",
        "DBInstanceStatus": status,
        "DBInstanceClass": "db.t3.large",
        "Engine": "postgres",
        "AllocatedStorage": storage,
        "StorageType": "gp2",
        **extra,
    }


def db_snapshot(identifier="before-cutover", age=400, storage=100, kind="manual", **extra):
    return {
        "DBSnapshotIdentifier": identifier,
        "DBSnapshotArn": f"arn:aws:rds:us-east-1:123456789012:snapshot:{identifier}",
        "DBInstanceIdentifier": "app",
        "SnapshotType": kind,
        "Status": "available",
        "Engine": "postgres",
        "AllocatedStorage": storage,
        "SnapshotCreateTime": days_ago(age),
        **extra,
    }


# --- stopped databases ----------------------------------------------------


def test_flags_a_stopped_database_and_prices_its_storage():
    found = findings(STOPPED_DATABASES, {"describe_db_instances": {"DBInstances": [database()]}})
    assert len(found) == 1
    assert found[0].confidence is Confidence.HIGH
    assert round(found[0].monthly_usd, 2) == 11.5  # 100 GB gp2
    assert any("7 days" in line for line in found[0].evidence)


def test_a_small_stopped_database_is_still_worth_mentioning():
    """The automatic restart is the surprise, not the storage bill."""
    found = findings(
        STOPPED_DATABASES, {"describe_db_instances": {"DBInstances": [database(storage=20)]}}
    )
    assert found[0].level is Severity.MEDIUM


def test_a_running_database_is_not_a_finding():
    running = database(status="available")
    assert findings(STOPPED_DATABASES, {"describe_db_instances": {"DBInstances": [running]}}) == ()


def test_multi_az_storage_is_called_out():
    found = findings(
        STOPPED_DATABASES, {"describe_db_instances": {"DBInstances": [database(MultiAZ=True)]}}
    )
    assert any("twice" in line for line in found[0].evidence)


def test_the_ignore_tag_works_on_rds_tag_lists():
    kept = database(TagList=tags(**{"preflight:ignore": "on purpose"}))
    assert findings(STOPPED_DATABASES, {"describe_db_instances": {"DBInstances": [kept]}}) == ()


def test_missing_rds_permission_skips_the_check():
    outcome = run(STOPPED_DATABASES, {"describe_db_instances": denied("DescribeDBInstances")})
    assert outcome.status == "skipped"
    assert outcome.missing_action == "rds:DescribeDBInstances"


# --- old manual snapshots -------------------------------------------------


def test_flags_an_old_manual_snapshot():
    found = findings(
        OLD_DATABASE_SNAPSHOTS, {"describe_db_snapshots": {"DBSnapshots": [db_snapshot()]}}
    )
    assert len(found) == 1
    assert found[0].confidence is Confidence.MEDIUM
    assert round(found[0].monthly_usd, 2) == 3.14  # a third of 100 GB at $0.095
    assert "1.1 years" in found[0].title


def test_a_recent_manual_snapshot_is_left_alone():
    young = db_snapshot(age=OLD_MANUAL_SNAPSHOT_DAYS - 1)
    assert (
        findings(OLD_DATABASE_SNAPSHOTS, {"describe_db_snapshots": {"DBSnapshots": [young]}}) == ()
    )


def test_automated_snapshots_are_never_flagged():
    """Those are the retention policy doing its job."""
    automated = db_snapshot(kind="automated")
    found = findings(
        OLD_DATABASE_SNAPSHOTS, {"describe_db_snapshots": {"DBSnapshots": [automated]}}
    )
    assert found == ()


def test_only_manual_snapshots_are_requested():
    calls: list[dict] = []

    def record(**params):
        calls.append(params)
        return {"DBSnapshots": []}

    findings(OLD_DATABASE_SNAPSHOTS, {"describe_db_snapshots": record})
    assert calls and calls[0].get("SnapshotType") == "manual"


def test_snapshots_still_being_taken_are_skipped():
    creating = db_snapshot(Status="creating")
    assert (
        findings(OLD_DATABASE_SNAPSHOTS, {"describe_db_snapshots": {"DBSnapshots": [creating]}})
        == ()
    )
