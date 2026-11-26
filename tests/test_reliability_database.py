"""Databases with no standby, and databases with nothing to restore from."""

from __future__ import annotations

from conftest import days_ago, denied, findings, run, tags

from preflight.core.findings import Confidence, Severity
from preflight.modules.reliability.database import (
    DATABASES_WITHOUT_BACKUPS,
    SINGLE_AZ_DATABASES,
)

ACCOUNT = "123456789012"


def database(identifier="orders", multi_az=False, status="available", age=200, **extra):
    return {
        "DBInstanceIdentifier": identifier,
        "DBInstanceArn": f"arn:aws:rds:us-east-1:{ACCOUNT}:db:{identifier}",
        "DBInstanceStatus": status,
        "Engine": "postgres",
        "MultiAZ": multi_az,
        "AvailabilityZone": "us-east-1a",
        "BackupRetentionPeriod": 7,
        "InstanceCreateTime": days_ago(age),
        "TagList": [],
        **extra,
    }


def account(*databases, **more):
    return {"describe_db_instances": {"DBInstances": list(databases)}, **more}


# --- databases with no standby --------------------------------------------


def test_a_multi_az_database_is_fine():
    outcome = run(SINGLE_AZ_DATABASES, account(database(multi_az=True)))
    assert outcome.findings == ()
    assert outcome.examined == 1


def test_flags_a_single_az_database():
    (found,) = findings(SINGLE_AZ_DATABASES, account(database()))
    assert found.title == "postgres database with no standby"
    assert found.resource.kind == "rds:db"
    assert found.level is Severity.MEDIUM
    assert found.confidence is Confidence.MEDIUM
    assert any("us-east-1a" in line for line in found.evidence)
    assert any("Environment=dev" in line for line in found.evidence)


def test_a_production_tag_makes_it_certain():
    tagged = database(TagList=tags(Environment="Production"))
    (found,) = findings(SINGLE_AZ_DATABASES, account(tagged))
    assert found.confidence is Confidence.HIGH
    assert not any("Environment=dev" in line for line in found.evidence)


def test_leaves_dev_and_staging_alone():
    dev = database("dev-db", TagList=tags(env="dev"))
    staging = database("staging-db", TagList=tags(Stage="Staging"))
    assert findings(SINGLE_AZ_DATABASES, account(dev, staging)) == ()


def test_read_replicas_are_not_the_thing_to_protect():
    replica = database("orders-replica", ReadReplicaSourceDBInstanceIdentifier="orders")
    assert findings(SINGLE_AZ_DATABASES, account(replica)) == ()


def test_stopped_and_new_databases_are_left_alone():
    stopped = database("old", status="stopped")
    new = database("new", age=2)
    assert findings(SINGLE_AZ_DATABASES, account(stopped, new)) == ()


def test_sql_server_express_cant_do_multi_az():
    assert findings(SINGLE_AZ_DATABASES, account(database(Engine="sqlserver-ex"))) == ()


def test_respects_the_ignore_tag():
    quiet = database(TagList=tags(**{"preflight:ignore": "true"}))
    assert findings(SINGLE_AZ_DATABASES, account(quiet)) == ()


def test_an_aurora_cluster_of_one_is_flagged_once():
    writer = database("app-1", Engine="aurora-postgresql", DBClusterIdentifier="app")
    (found,) = findings(SINGLE_AZ_DATABASES, account(writer))
    assert found.resource.id == "app"
    assert found.resource.kind == "rds:cluster"
    assert found.title == "aurora-postgresql cluster with nothing to fail over to"


def test_an_aurora_cluster_with_a_reader_is_fine():
    writer = database("app-1", Engine="aurora-mysql", DBClusterIdentifier="app")
    reader = database("app-2", Engine="aurora-mysql", DBClusterIdentifier="app")
    outcome = run(SINGLE_AZ_DATABASES, account(writer, reader))
    assert outcome.findings == ()
    assert outcome.examined == 1


def test_skipped_without_permission():
    outcome = run(SINGLE_AZ_DATABASES, {"describe_db_instances": denied("DescribeDBInstances")})
    assert outcome.status == "skipped"
    assert outcome.missing_action == "rds:DescribeDBInstances"


# --- databases with nothing to restore from -------------------------------


def snapshot(identifier="orders", age=1, kind="manual", status="available"):
    return {
        "DBSnapshotIdentifier": f"{identifier}-{age}",
        "DBInstanceIdentifier": identifier,
        "SnapshotType": kind,
        "Status": status,
        "SnapshotCreateTime": days_ago(age),
    }


def no_backups(*snapshots, **extra):
    return account(
        database(BackupRetentionPeriod=0, **extra),
        describe_db_snapshots={"DBSnapshots": list(snapshots)},
    )


def test_a_database_with_backups_is_fine_and_costs_no_snapshot_reads():
    outcome = run(DATABASES_WITHOUT_BACKUPS, account(database()))
    assert outcome.findings == ()
    assert outcome.examined == 1


def test_flags_a_database_with_no_backups_and_no_snapshots():
    (found,) = findings(DATABASES_WITHOUT_BACKUPS, no_backups())
    assert found.title == "postgres database with nothing to restore from"
    assert found.level is Severity.HIGH
    assert any("retention is 0 days" in line for line in found.evidence)


def test_a_recent_snapshot_means_backups_happen_some_other_way():
    """AWS Backup and nightly scripts make snapshots that aren't 'automated'."""
    assert findings(DATABASES_WITHOUT_BACKUPS, no_backups(snapshot(age=1, kind="awsbackup"))) == ()


def test_an_old_snapshot_is_reported_with_its_age():
    (found,) = findings(DATABASES_WITHOUT_BACKUPS, no_backups(snapshot(age=12), snapshot(age=40)))
    assert found.title == "postgres database whose last backup is 12 days old"
    assert found.level is Severity.MEDIUM


def test_a_very_old_snapshot_is_as_bad_as_none():
    (found,) = findings(DATABASES_WITHOUT_BACKUPS, no_backups(snapshot(age=90)))
    assert found.level is Severity.HIGH


def test_an_unfinished_snapshot_doesnt_count():
    (found,) = findings(DATABASES_WITHOUT_BACKUPS, no_backups(snapshot(age=0, status="creating")))
    assert found.title.endswith("nothing to restore from")


def test_replicas_aurora_and_dev_databases_are_left_alone():
    replica = database("r", BackupRetentionPeriod=0, ReadReplicaSourceDBInstanceIdentifier="o")
    aurora = database("a", BackupRetentionPeriod=0, DBClusterIdentifier="app")
    dev = database("d", BackupRetentionPeriod=0, TagList=tags(Environment="test"))
    assert findings(DATABASES_WITHOUT_BACKUPS, account(replica, aurora, dev)) == ()


def test_skipped_when_snapshots_cant_be_read():
    responses = no_backups()
    responses["describe_db_snapshots"] = denied("DescribeDBSnapshots")
    outcome = run(DATABASES_WITHOUT_BACKUPS, responses)
    assert outcome.status == "skipped"
    assert outcome.missing_action == "rds:DescribeDBSnapshots"
