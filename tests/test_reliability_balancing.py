"""Load-balanced services one failure from down."""

from __future__ import annotations

from conftest import days_ago, denied, findings, run

from preflight.core.findings import Confidence, Severity
from preflight.modules.reliability.balancing import FRAGILE_LOAD_BALANCED_SERVICES as CHECK

ACCOUNT = "123456789012"
LB = f"arn:aws:elasticloadbalancing:us-east-1:{ACCOUNT}:loadbalancer/app/web/1"
TG = f"arn:aws:elasticloadbalancing:us-east-1:{ACCOUNT}:targetgroup/web/2"


def balancer(arn=LB, age=100, state="active", kind="application"):
    return {
        "LoadBalancerArn": arn,
        "LoadBalancerName": arn.split("/")[-2],
        "Type": kind,
        "State": {"Code": state},
        "CreatedTime": days_ago(age),
    }


def target(instance, state="healthy", zone=None):
    described = {"Id": instance, "Port": 80}
    if zone:
        described["AvailabilityZone"] = zone
    return {"Target": described, "TargetHealth": {"State": state}}


def instance(identifier, zone):
    return {"InstanceId": identifier, "Placement": {"AvailabilityZone": zone}}


def account(
    targets,
    *,
    balancers=None,
    instances=(),
    scaled=(),
    target_type="instance",
    **more,
):
    return {
        "describe_load_balancers": {"LoadBalancers": balancers or [balancer()]},
        "describe_target_groups": {
            "TargetGroups": [
                {
                    "TargetGroupArn": TG,
                    "TargetGroupName": "web",
                    "TargetType": target_type,
                    "LoadBalancerArns": [LB],
                }
            ]
        },
        "describe_target_health": {"TargetHealthDescriptions": list(targets)},
        "describe_auto_scaling_groups": {
            "AutoScalingGroups": [{"TargetGroupARNs": list(scaled)}] if scaled else []
        },
        "describe_instances": {"Reservations": [{"Instances": list(instances)}]},
        **more,
    }


SPREAD = [instance("i-1", "us-east-1a"), instance("i-2", "us-east-1b")]


def test_two_healthy_targets_in_two_zones_are_fine():
    outcome = run(CHECK, account([target("i-1"), target("i-2")], instances=SPREAD))
    assert outcome.findings == ()
    assert outcome.examined == 1


def test_flags_a_target_group_with_nothing_healthy():
    (found,) = findings(CHECK, account([target("i-1", "unhealthy"), target("i-2", "unhealthy")]))
    assert found.title == "Load balancer with nothing healthy behind it"
    assert found.level is Severity.HIGH
    assert found.confidence is Confidence.HIGH
    assert found.resource.kind == "elb:target-group"
    assert any("behind web" in line for line in found.evidence)


def test_targets_still_starting_up_are_not_an_outage():
    assert (
        findings(
            CHECK,
            account([target("i-1", "initial"), target("i-2", "unhealthy")]),
        )
        == ()
    )


def test_an_outage_is_reported_even_when_a_scaling_group_manages_it():
    broken = account([target("i-1", "unhealthy")], scaled=[TG])
    (found,) = findings(CHECK, broken)
    assert found.level is Severity.HIGH


def test_flags_a_lone_target_nothing_replaces():
    (found,) = findings(CHECK, account([target("i-1")]))
    assert found.title == "Load balancer with one target behind it"
    assert found.level is Severity.MEDIUM
    assert any("i-1 is the only registered target" in line for line in found.evidence)


def test_a_lone_target_from_a_scaling_group_is_left_to_the_group():
    assert findings(CHECK, account([target("i-1")], scaled=[TG])) == ()


def test_flags_targets_that_all_share_a_zone():
    same = [instance("i-1", "us-east-1a"), instance("i-2", "us-east-1a")]
    (found,) = findings(CHECK, account([target("i-1"), target("i-2")], instances=same))
    assert found.title == "Load balancer whose targets share one zone"
    assert any("us-east-1a" in line for line in found.evidence)


def test_ip_targets_carry_their_own_zone():
    targets = [target("10.0.0.1", zone="us-east-1a"), target("10.0.0.2", zone="us-east-1a")]
    (found,) = findings(CHECK, account(targets, target_type="ip"))
    assert found.title.endswith("share one zone")


def test_an_unknown_zone_gives_the_benefit_of_the_doubt():
    targets = [target("10.0.0.1", zone="us-east-1a"), target("10.0.0.2")]
    assert findings(CHECK, account(targets, target_type="ip")) == ()


def test_draining_targets_dont_count():
    targets = [target("i-1"), target("i-2", "draining")]
    (found,) = findings(CHECK, account(targets))
    assert found.title.endswith("one target behind it")


def test_empty_target_groups_are_the_cost_checks_business():
    assert findings(CHECK, account([])) == ()


def test_new_and_inactive_balancers_are_left_alone():
    assert findings(CHECK, account([target("i-1")], balancers=[balancer(age=2)])) == ()
    assert findings(CHECK, account([target("i-1")], balancers=[balancer(state="failed")])) == ()


def test_respects_tags_on_the_load_balancer():
    tagged = {
        "get_resources": {
            "ResourceTagMappingList": [
                {"ResourceARN": LB, "Tags": [{"Key": "Environment", "Value": "staging"}]}
            ]
        }
    }
    assert findings(CHECK, account([target("i-1")], **tagged)) == ()


def test_no_load_balancers_means_no_further_reads():
    outcome = run(CHECK, {"describe_load_balancers": {"LoadBalancers": []}})
    assert outcome.status == "ran"
    assert outcome.examined == 0


def test_skipped_without_permission():
    responses = account([target("i-1")])
    responses["describe_target_health"] = denied("DescribeTargetHealth")
    outcome = run(CHECK, responses)
    assert outcome.status == "skipped"
    assert outcome.missing_action == "elasticloadbalancing:DescribeTargetHealth"


def test_says_why_the_targets_are_failing():
    failing = {
        "Target": {"Id": "i-1"},
        "TargetHealth": {
            "State": "unhealthy",
            "Reason": "Target.ResponseCodeMismatch",
            "Description": "Health checks failed with these codes: [404]",
        },
    }
    (found,) = findings(CHECK, account([failing, dict(failing)]))
    assert any(
        "AWS says: Health checks failed with these codes: [404]." in line for line in found.evidence
    )
