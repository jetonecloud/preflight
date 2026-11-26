"""Auto Scaling groups that can't replace what breaks."""

from __future__ import annotations

from conftest import days_ago, denied, findings, run, tags

from preflight.core.findings import Confidence, Severity
from preflight.modules.reliability.scaling import AUTOSCALING_GROUPS_THAT_CANT_HEAL as CHECK

ACCOUNT = "123456789012"
TARGETS = f"arn:aws:elasticloadbalancing:us-east-1:{ACCOUNT}:targetgroup/web/abc"


def group(name="web", desired=2, zones=("us-east-1a", "us-east-1b"), **extra):
    return {
        "AutoScalingGroupName": name,
        "AutoScalingGroupARN": f"arn:aws:autoscaling:us-east-1:{ACCOUNT}:autoScalingGroup:x:"
        f"autoScalingGroupName/{name}",
        "MinSize": 1,
        "MaxSize": 4,
        "DesiredCapacity": desired,
        "AvailabilityZones": list(zones),
        "HealthCheckType": "ELB",
        "TargetGroupARNs": [TARGETS],
        "SuspendedProcesses": [],
        "CreatedTime": days_ago(100),
        "Tags": [],
        **extra,
    }


def account(*groups):
    return {"describe_auto_scaling_groups": {"AutoScalingGroups": list(groups)}}


def test_a_healthy_group_is_fine():
    outcome = run(CHECK, account(group()))
    assert outcome.findings == ()
    assert outcome.examined == 1


def test_flags_suspended_healing_as_high():
    suspended = group(
        SuspendedProcesses=[{"ProcessName": "ReplaceUnhealthy"}, {"ProcessName": "Launch"}]
    )
    (found,) = findings(CHECK, account(suspended))
    assert found.title == "Auto Scaling group with healing switched off"
    assert found.level is Severity.HIGH
    assert any("Launch, ReplaceUnhealthy are suspended" in line for line in found.evidence)
    assert found.recommendation.startswith("Resume the suspended processes")


def test_suspending_scaling_alone_is_not_a_healing_problem():
    """Pausing scheduled actions or alarms is a legitimate thing to do."""
    paused = group(SuspendedProcesses=[{"ProcessName": "ScheduledActions"}])
    assert findings(CHECK, account(paused)) == ()


def test_flags_ec2_health_checks_behind_a_load_balancer():
    (found,) = findings(CHECK, account(group(HealthCheckType="EC2")))
    assert found.title == "Auto Scaling group that ignores its load balancer"
    assert found.level is Severity.MEDIUM


def test_ec2_health_checks_are_fine_with_no_load_balancer():
    alone = group(HealthCheckType="EC2", TargetGroupARNs=[])
    assert findings(CHECK, account(alone)) == ()


def test_flags_a_group_in_one_zone():
    (found,) = findings(CHECK, account(group(zones=("us-east-1a",))))
    assert found.title == "Auto Scaling group confined to one zone"
    assert any("us-east-1a" in line for line in found.evidence)


def test_several_problems_make_one_finding_led_by_the_worst():
    broken = group(
        zones=("us-east-1a",),
        HealthCheckType="EC2",
        SuspendedProcesses=[{"ProcessName": "HealthCheck"}],
    )
    (found,) = findings(CHECK, account(broken))
    assert found.level is Severity.HIGH
    assert found.title.endswith("healing switched off")
    assert "health check type to ELB" in found.recommendation
    assert "one more Availability Zone" in found.recommendation


def test_parked_new_dev_and_ignored_groups_are_left_alone():
    parked = group("parked", desired=0, zones=("us-east-1a",))
    new = group("new", zones=("us-east-1a",), CreatedTime=days_ago(1))
    dev = group("dev", zones=("us-east-1a",), Tags=tags(Environment="dev"))
    quiet = group("quiet", zones=("us-east-1a",), Tags=tags(**{"preflight:ignore": "yes"}))
    assert findings(CHECK, account(parked, new, dev, quiet)) == ()


def test_a_production_tag_makes_it_certain():
    (found,) = findings(CHECK, account(group(zones=("a",), Tags=tags(env="prod"))))
    assert found.confidence is Confidence.HIGH


def test_skipped_without_permission():
    outcome = run(CHECK, {"describe_auto_scaling_groups": denied("DescribeAutoScalingGroups")})
    assert outcome.status == "skipped"
    assert outcome.missing_action == "autoscaling:DescribeAutoScalingGroups"
