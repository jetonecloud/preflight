"""Elastic IPs, NAT gateways and load balancers.

These are the checks that read CloudWatch, so most of what's being tested
here is the difference between "zero" and "we don't know" — the mistake
that turns a cost report into noise.
"""

from __future__ import annotations

from conftest import datapoints, days_ago, denied, findings, run, tags

from preflight.core.findings import Confidence
from preflight.modules.cost.network import (
    IDLE_LOAD_BALANCERS,
    IDLE_NAT_GATEWAYS,
    UNASSOCIATED_IPS,
)

# --- Elastic IPs ----------------------------------------------------------


def address(allocation="eipalloc-0aaa1111bbbb2222a", ip="203.0.113.10", **extra):
    return {"AllocationId": allocation, "PublicIp": ip, "PublicIpv4Pool": "amazon", **extra}


def test_flags_an_unassociated_address():
    found = findings(UNASSOCIATED_IPS, {"describe_addresses": {"Addresses": [address()]}})
    assert len(found) == 1
    assert round(found[0].monthly_usd, 2) == 3.65
    assert found[0].confidence is Confidence.HIGH


def test_an_attached_address_is_not_a_finding():
    attached = address(AssociationId="eipassoc-1", InstanceId="i-1")
    assert findings(UNASSOCIATED_IPS, {"describe_addresses": {"Addresses": [attached]}}) == ()


def test_an_address_on_a_spare_network_interface_is_not_a_finding():
    attached = address(NetworkInterfaceId="eni-1")
    assert findings(UNASSOCIATED_IPS, {"describe_addresses": {"Addresses": [attached]}}) == ()


def test_byoip_addresses_are_left_alone():
    """They aren't billed at the Amazon rate, so we'd be quoting a number
    that doesn't appear on anyone's invoice."""
    byoip = address(PublicIpv4Pool="ipv4pool-ec2-0abc")
    assert findings(UNASSOCIATED_IPS, {"describe_addresses": {"Addresses": [byoip]}}) == ()


def test_ignore_tag_applies_here_too():
    kept = address(Tags=tags(**{"preflight:ignore": "yes"}))
    assert findings(UNASSOCIATED_IPS, {"describe_addresses": {"Addresses": [kept]}}) == ()


# --- NAT gateways ---------------------------------------------------------


def gateway(gateway_id="nat-0aaa1111bbbb2222a", age=200, **extra):
    return {
        "NatGatewayId": gateway_id,
        "State": "available",
        "SubnetId": "subnet-1",
        "CreateTime": days_ago(age),
        **extra,
    }


def quiet_metrics(**_):
    return datapoints([0.0] * 14)


def test_flags_a_gateway_with_no_bytes_and_no_connections():
    found = findings(
        IDLE_NAT_GATEWAYS,
        {
            "describe_nat_gateways": {"NatGateways": [gateway()]},
            "get_metric_statistics": quiet_metrics,
        },
    )
    assert len(found) == 1
    assert round(found[0].monthly_usd, 2) == 32.85
    assert found[0].confidence is Confidence.MEDIUM


def test_a_gateway_moving_traffic_is_left_alone():
    def busy(**params):
        if params["MetricName"] == "BytesOutToDestination":
            return datapoints([5_000_000.0] * 14)
        return datapoints([12.0] * 14, "Maximum")

    assert (
        findings(
            IDLE_NAT_GATEWAYS,
            {
                "describe_nat_gateways": {"NatGateways": [gateway()]},
                "get_metric_statistics": busy,
            },
        )
        == ()
    )


def test_connections_alone_are_enough_to_spare_a_gateway():
    """Zero bytes out but live connections means something is using it."""

    def connected(**params):
        if params["MetricName"] == "BytesOutToDestination":
            return datapoints([0.0] * 14)
        return datapoints([3.0] * 14, "Maximum")

    assert (
        findings(
            IDLE_NAT_GATEWAYS,
            {
                "describe_nat_gateways": {"NatGateways": [gateway()]},
                "get_metric_statistics": connected,
            },
        )
        == ()
    )


def test_a_gateway_younger_than_the_window_is_not_judged():
    """Two days of quiet is not evidence of anything."""
    new = gateway(age=1)
    assert (
        findings(
            IDLE_NAT_GATEWAYS,
            {
                "describe_nat_gateways": {"NatGateways": [new]},
                "get_metric_statistics": quiet_metrics,
            },
        )
        == ()
    )


def test_deleted_gateways_are_not_counted():
    gone = gateway(State="deleted")
    outcome = run(
        IDLE_NAT_GATEWAYS,
        {"describe_nat_gateways": {"NatGateways": [gone]}, "get_metric_statistics": quiet_metrics},
    )
    assert outcome.findings == ()
    assert outcome.examined == 0


def test_losing_cloudwatch_skips_the_check():
    outcome = run(
        IDLE_NAT_GATEWAYS,
        {
            "describe_nat_gateways": {"NatGateways": [gateway()]},
            "get_metric_statistics": denied("GetMetricStatistics"),
        },
    )
    assert outcome.status == "skipped"
    assert outcome.missing_action == "cloudwatch:GetMetricStatistics"


# --- load balancers -------------------------------------------------------

ALB_ARN = (
    "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/web/50dc6c495c0c9188"
)
GROUP_ARN = "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/web/1"


def balancer(arn=ALB_ARN, kind="application", age=200, **extra):
    return {
        "LoadBalancerArn": arn,
        "LoadBalancerName": "web",
        "Type": kind,
        "State": {"Code": "active"},
        "CreatedTime": days_ago(age),
        **extra,
    }


def elb_data(balancers=(), groups=(), health=(), classic=(), metrics=None):
    """Responses for both load balancer APIs.

    The Classic API is a different boto3 client under the same IAM action,
    so the two `DescribeLoadBalancers` live on different services and the
    stub keys them the same way the real thing does.
    """
    return {
        "responses": {
            "describe_load_balancers": {"LoadBalancers": list(balancers)},
            "describe_target_groups": {"TargetGroups": list(groups)},
            "describe_target_health": {"TargetHealthDescriptions": list(health)},
            "get_metric_statistics": metrics or (lambda **_: {"Datapoints": []}),
            "get_resources": {"ResourceTagMappingList": []},
        },
        "per_service": {
            "elb": {"describe_load_balancers": {"LoadBalancerDescriptions": list(classic)}}
        },
    }


def test_flags_a_balancer_with_no_target_groups():
    found = findings(IDLE_LOAD_BALANCERS, **elb_data(balancers=[balancer()]))
    assert len(found) == 1
    assert found[0].confidence is Confidence.HIGH
    assert round(found[0].monthly_usd, 2) == 16.43


def test_flags_a_balancer_whose_groups_have_no_targets():
    group = {"TargetGroupArn": GROUP_ARN, "LoadBalancerArns": [ALB_ARN]}
    found = findings(IDLE_LOAD_BALANCERS, **elb_data(balancers=[balancer()], groups=[group]))
    assert len(found) == 1
    assert "no registered targets" in found[0].evidence[0]


def test_a_balancer_with_healthy_targets_and_traffic_is_left_alone():
    group = {"TargetGroupArn": GROUP_ARN, "LoadBalancerArns": [ALB_ARN]}
    health = [{"Target": {"Id": "i-1"}, "TargetHealth": {"State": "healthy"}}]
    data = elb_data(
        balancers=[balancer()],
        groups=[group],
        health=health,
        metrics=lambda **_: datapoints([1000.0] * 14),
    )
    assert findings(IDLE_LOAD_BALANCERS, **data) == ()


def test_a_balancer_with_targets_but_no_requests_is_a_softer_finding():
    group = {"TargetGroupArn": GROUP_ARN, "LoadBalancerArns": [ALB_ARN]}
    health = [{"Target": {"Id": "i-1"}, "TargetHealth": {"State": "healthy"}}]
    data = elb_data(
        balancers=[balancer()],
        groups=[group],
        health=health,
        metrics=lambda **_: datapoints([0.0] * 14),
    )
    found = findings(IDLE_LOAD_BALANCERS, **data)
    assert len(found) == 1
    assert found[0].confidence is Confidence.MEDIUM


def test_no_request_metrics_at_all_is_not_treated_as_zero():
    """An empty series means CloudWatch had nothing, not that nobody called."""
    group = {"TargetGroupArn": GROUP_ARN, "LoadBalancerArns": [ALB_ARN]}
    health = [{"Target": {"Id": "i-1"}, "TargetHealth": {"State": "healthy"}}]
    data = elb_data(balancers=[balancer()], groups=[group], health=health)
    assert findings(IDLE_LOAD_BALANCERS, **data) == ()


def test_provisioning_balancers_are_ignored():
    new = balancer(State={"Code": "provisioning"})
    assert findings(IDLE_LOAD_BALANCERS, **elb_data(balancers=[new])) == ()


def test_flags_a_classic_balancer_with_no_instances():
    classic = [{"LoadBalancerName": "legacy", "Instances": [], "CreatedTime": days_ago(900)}]
    found = findings(IDLE_LOAD_BALANCERS, **elb_data(classic=classic))
    assert len(found) == 1
    assert found[0].resource.kind == "elb:classic"
    assert round(found[0].monthly_usd, 2) == 18.25


def test_a_classic_balancer_with_instances_is_left_alone():
    classic = [
        {
            "LoadBalancerName": "legacy",
            "Instances": [{"InstanceId": "i-1"}],
            "CreatedTime": days_ago(900),
        }
    ]
    assert findings(IDLE_LOAD_BALANCERS, **elb_data(classic=classic)) == ()
