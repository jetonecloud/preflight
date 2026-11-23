"""Alarms that reach nobody, and resources no alarm watches."""

from __future__ import annotations

from conftest import days_ago, denied, findings, run, tags

from preflight.core.findings import Confidence, Severity
from preflight.modules.observability.alarms import (
    ALARMS_THAT_NOTIFY_NOBODY,
    MIN_RESOURCE_AGE_DAYS,
    UNWATCHED_RESOURCES,
)

ACCOUNT = "123456789012"
PAGER = f"arn:aws:sns:us-east-1:{ACCOUNT}:pager"
QUIET = f"arn:aws:sns:us-east-1:{ACCOUNT}:quiet"
GONE = f"arn:aws:sns:us-east-1:{ACCOUNT}:gone"
SCALE_OUT = f"arn:aws:autoscaling:us-east-1:{ACCOUNT}:scalingPolicy:abc:policyName/out"


def alarm(name="api-5xx", actions=(PAGER,), enabled=True, **extra):
    return {
        "AlarmName": name,
        "AlarmArn": f"arn:aws:cloudwatch:us-east-1:{ACCOUNT}:alarm:{name}",
        "AlarmActions": list(actions),
        "ActionsEnabled": enabled,
        "Namespace": "AWS/ApplicationELB",
        "MetricName": "HTTPCode_Target_5XX_Count",
        "StateValue": "OK",
        **extra,
    }


def account(alarms=(), composites=(), topics=(PAGER, QUIET), subscriptions=None, **more):
    if subscriptions is None:
        subscriptions = [{"TopicArn": PAGER, "SubscriptionArn": f"{PAGER}:sub-1"}]
    return {
        "describe_alarms": {"MetricAlarms": list(alarms), "CompositeAlarms": list(composites)},
        "list_topics": {"Topics": [{"TopicArn": topic} for topic in topics]},
        "list_subscriptions": {"Subscriptions": list(subscriptions)},
        **more,
    }


# --- alarms that notify nobody --------------------------------------------


def test_an_alarm_that_pages_someone_is_fine():
    outcome = run(ALARMS_THAT_NOTIFY_NOBODY, account([alarm()]))
    assert outcome.findings == ()
    assert outcome.examined == 1


def test_flags_an_alarm_with_its_actions_switched_off():
    found = findings(ALARMS_THAT_NOTIFY_NOBODY, account([alarm(enabled=False)]))
    assert len(found) == 1
    assert found[0].title == "Alarm with its actions switched off"
    assert found[0].confidence is Confidence.HIGH
    assert found[0].level is Severity.MEDIUM


def test_flags_an_alarm_with_no_actions_but_hedges():
    found = findings(ALARMS_THAT_NOTIFY_NOBODY, account([alarm(actions=())]))
    assert found[0].title == "Alarm with nowhere to send it"
    assert found[0].confidence is Confidence.MEDIUM


def test_a_composites_children_are_allowed_to_be_silent():
    child = alarm("db-cpu", actions=())
    parent = {
        "AlarmName": "db-trouble",
        "AlarmArn": f"arn:aws:cloudwatch:us-east-1:{ACCOUNT}:alarm:db-trouble",
        "AlarmActions": [PAGER],
        "ActionsEnabled": True,
        "AlarmRule": 'ALARM("db-cpu") AND ALARM("db-connections")',
    }
    assert findings(ALARMS_THAT_NOTIFY_NOBODY, account([child], composites=[parent])) == ()


def test_groups_alarms_by_the_topic_nobody_reads():
    alarms = [alarm("a", actions=(QUIET,)), alarm("b", actions=(QUIET,))]
    found = findings(ALARMS_THAT_NOTIFY_NOBODY, account(alarms))
    assert len(found) == 1
    finding = found[0]
    assert finding.title == "Alarms sent to a topic nobody is subscribed to"
    assert finding.resource.id == "quiet"
    assert finding.resource.kind == "sns:topic"
    assert finding.level is Severity.HIGH
    assert any("a, b" in line for line in finding.evidence)


def test_an_unconfirmed_subscription_counts_as_nobody():
    pending = [{"TopicArn": QUIET, "SubscriptionArn": "PendingConfirmation"}]
    found = findings(
        ALARMS_THAT_NOTIFY_NOBODY,
        account([alarm(actions=(QUIET,))], subscriptions=pending),
    )
    assert len(found) == 1
    assert found[0].level is Severity.MEDIUM


def test_flags_a_topic_that_no_longer_exists():
    found = findings(ALARMS_THAT_NOTIFY_NOBODY, account([alarm(actions=(GONE,))]))
    assert found[0].title == "Alarms sent to a topic that doesn't exist"


def test_one_working_topic_is_enough():
    assert findings(ALARMS_THAT_NOTIFY_NOBODY, account([alarm(actions=(QUIET, PAGER))])) == ()


def test_an_alarm_that_scales_something_is_doing_its_job():
    """Autoscaling alarms aren't meant to tell a person anything."""
    scaling = alarm("cpu-high", actions=(SCALE_OUT,))
    mixed = alarm("cpu-higher", actions=(SCALE_OUT, QUIET))
    assert findings(ALARMS_THAT_NOTIFY_NOBODY, account([scaling, mixed])) == ()


def test_a_topic_in_another_region_is_given_the_benefit_of_the_doubt():
    elsewhere = f"arn:aws:sns:eu-west-1:{ACCOUNT}:pager"
    assert findings(ALARMS_THAT_NOTIFY_NOBODY, account([alarm(actions=(elsewhere,))])) == ()


def test_respects_the_ignore_tag():
    arn = f"arn:aws:cloudwatch:us-east-1:{ACCOUNT}:alarm:api-5xx"
    tagged = {
        "get_resources": {
            "ResourceTagMappingList": [
                {"ResourceARN": arn, "Tags": [{"Key": "preflight:ignore", "Value": "yes"}]}
            ]
        }
    }
    assert findings(ALARMS_THAT_NOTIFY_NOBODY, account([alarm(enabled=False)], **tagged)) == ()


def test_no_alarms_means_no_sns_reads():
    outcome = run(ALARMS_THAT_NOTIFY_NOBODY, account(topics=(), subscriptions=[]))
    assert outcome.status == "ran"
    assert outcome.examined == 0


def test_missing_alarm_permission_skips_the_check():
    outcome = run(ALARMS_THAT_NOTIFY_NOBODY, {"describe_alarms": denied("DescribeAlarms")})
    assert outcome.status == "skipped"
    assert outcome.missing_action == "cloudwatch:DescribeAlarms"


def test_missing_sns_permission_skips_rather_than_guesses():
    data = account([alarm(actions=(QUIET,))])
    data["list_subscriptions"] = denied("ListSubscriptions", code="AuthorizationError")
    outcome = run(ALARMS_THAT_NOTIFY_NOBODY, data)
    assert outcome.status == "skipped"
    assert outcome.missing_action == "sns:ListSubscriptions"


# --- resources nothing is watching ----------------------------------------

LB_ARN = f"arn:aws:elasticloadbalancing:us-east-1:{ACCOUNT}:loadbalancer/app/web/50dc6c495c0c9188"


def database(identifier="orders", status="available", age=120, cluster=None, **extra):
    data = {
        "DBInstanceIdentifier": identifier,
        "DBInstanceArn": f"arn:aws:rds:us-east-1:{ACCOUNT}:db:{identifier}",
        "DBInstanceStatus": status,
        "Engine": "postgres",
        "InstanceCreateTime": days_ago(age),
        **extra,
    }
    if cluster:
        data["DBClusterIdentifier"] = cluster
    return data


def balancer(kind="application", age=120, state="active"):
    return {
        "LoadBalancerArn": LB_ARN,
        "LoadBalancerName": "web",
        "Type": kind,
        "State": {"Code": state},
        "CreatedTime": days_ago(age),
    }


def watching(name, value):
    return alarm(f"watch-{value}", Dimensions=[{"Name": name, "Value": value}])


def estate(databases=(), balancers=(), alarms=()):
    return {
        "describe_db_instances": {"DBInstances": list(databases)},
        "describe_load_balancers": {"LoadBalancers": list(balancers)},
        "describe_alarms": {"MetricAlarms": list(alarms)},
    }


def test_flags_a_database_no_alarm_mentions():
    found = findings(UNWATCHED_RESOURCES, estate([database()]))
    assert len(found) == 1
    assert found[0].title == "postgres database with no alarm on it"
    assert found[0].confidence is Confidence.MEDIUM
    assert found[0].resource.kind == "rds:db"


def test_a_watched_database_is_fine():
    watched = estate([database()], alarms=[watching("DBInstanceIdentifier", "orders")])
    outcome = run(UNWATCHED_RESOURCES, watched)
    assert outcome.findings == ()
    assert outcome.examined == 1


def test_an_alarm_on_the_cluster_covers_its_instances():
    data = estate(
        [database("orders-1", cluster="orders")],
        alarms=[watching("DBClusterIdentifier", "orders")],
    )
    assert findings(UNWATCHED_RESOURCES, data) == ()


def test_metric_math_alarms_count():
    math = alarm(
        "error-rate",
        Metrics=[
            {
                "Id": "m1",
                "MetricStat": {
                    "Metric": {
                        "Namespace": "AWS/ApplicationELB",
                        "MetricName": "HTTPCode_ELB_5XX_Count",
                        "Dimensions": [
                            {"Name": "LoadBalancer", "Value": "app/web/50dc6c495c0c9188"}
                        ],
                    }
                },
            }
        ],
    )
    assert findings(UNWATCHED_RESOURCES, estate(balancers=[balancer()], alarms=[math])) == ()


def test_flags_an_unwatched_load_balancer():
    found = findings(UNWATCHED_RESOURCES, estate(balancers=[balancer()]))
    assert found[0].title == "Application load balancer with no alarm on it"
    assert found[0].resource.arn == LB_ARN


def test_stopped_new_and_gateway_resources_are_left_alone():
    data = estate(
        [database(status="stopped"), database("fresh", age=MIN_RESOURCE_AGE_DAYS - 1)],
        [balancer(kind="gateway"), balancer(state="provisioning")],
    )
    assert findings(UNWATCHED_RESOURCES, data) == ()


def test_respects_the_ignore_tag_on_a_database():
    kept = database(TagList=tags(**{"preflight:ignore": "scratch"}))
    assert findings(UNWATCHED_RESOURCES, estate([kept])) == ()


def test_nothing_to_watch_means_no_alarm_reads():
    outcome = run(UNWATCHED_RESOURCES, estate())
    assert outcome.status == "ran"


def test_missing_rds_permission_skips_the_check():
    data = estate()
    data["describe_db_instances"] = denied("DescribeDBInstances")
    outcome = run(UNWATCHED_RESOURCES, data)
    assert outcome.status == "skipped"
    assert outcome.missing_action == "rds:DescribeDBInstances"
