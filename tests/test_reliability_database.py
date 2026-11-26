"""Databases with no standby, and databases with nothing to restore from."""

from __future__ import annotations

from conftest import days_ago, denied, findings, run, tags

from preflight.core.findings import Confidence, Severity
from preflight.modules.reliability.database import SINGLE_AZ_DATABASES

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
