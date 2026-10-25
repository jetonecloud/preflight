"""Stopped instances and oversized ones.

The oversized check is the one with the most ways to be wrong, so most of
this file is about the cases where it has to keep quiet: short histories,
busy networks, spot capacity, and instance types nothing can price.
"""

from __future__ import annotations

from conftest import datapoints, days_ago, denied, findings, run, tags

from preflight.core.findings import Confidence
from preflight.modules.cost.compute import (
    BUSY_CPU_PERCENT,
    LONG_STOPPED_INSTANCES,
    OVERSIZED_INSTANCES,
    STOPPED_DAYS,
)

STOPPED_90_DAYS = f"User initiated ({days_ago(90).strftime('%Y-%m-%d %H:%M:%S')} GMT)"


def instance(instance_id="i-0aaa1111bbbb2222a", kind="m5.large", state="running", age=200, **extra):
    return {
        "InstanceId": instance_id,
        "InstanceType": kind,
        "State": {"Name": state},
        "LaunchTime": days_ago(age),
        "Placement": {"Tenancy": "default"},
        **extra,
    }


def attached(instance_id="i-0aaa1111bbbb2222a", size=100, kind="gp3"):
    return {
        "VolumeId": f"vol-{instance_id[2:]}",
        "Size": size,
        "VolumeType": kind,
        "Attachments": [{"InstanceId": instance_id}],
    }


def ec2_data(instances=(), volumes=(), groups=(), metrics=None):
    return {
        "describe_instances": {"Reservations": [{"Instances": list(instances)}]},
        "describe_volumes": {"Volumes": list(volumes)},
        "describe_auto_scaling_groups": {"AutoScalingGroups": list(groups)},
        "get_metric_statistics": metrics or (lambda **_: {"Datapoints": []}),
        "get_products": {"PriceList": []},
    }


# --- stopped instances ----------------------------------------------------


def test_flags_a_long_stopped_instance_and_prices_its_disks():
    machine = instance(state="stopped", StateTransitionReason=STOPPED_90_DAYS)
    found = findings(
        LONG_STOPPED_INSTANCES,
        ec2_data(instances=[machine], volumes=[attached(size=200)]),
    )
    assert len(found) == 1
    assert found[0].confidence is Confidence.HIGH
    assert found[0].monthly_usd == 16.0  # 200 GB gp3
    assert "90 days" in found[0].title


def test_a_recently_stopped_instance_is_left_alone():
    recent = days_ago(STOPPED_DAYS - 1).strftime("%Y-%m-%d %H:%M:%S")
    machine = instance(state="stopped", StateTransitionReason=f"User initiated ({recent} GMT)")
    assert findings(LONG_STOPPED_INSTANCES, ec2_data([machine], [attached()])) == ()


def test_an_instance_with_no_stop_time_is_not_guessed_at():
    """No parseable timestamp means no claim about how long it's been down."""
    machine = instance(state="stopped", StateTransitionReason="")
    assert findings(LONG_STOPPED_INSTANCES, ec2_data([machine], [attached()])) == ()


def test_an_instance_with_no_volumes_costs_nothing_to_leave():
    machine = instance(state="stopped", StateTransitionReason=STOPPED_90_DAYS)
    assert findings(LONG_STOPPED_INSTANCES, ec2_data([machine], [])) == ()


def test_an_autoscaling_instance_is_left_to_its_group():
    machine = instance(state="stopped", StateTransitionReason=STOPPED_90_DAYS)
    group = {"AutoScalingGroupName": "web", "Instances": [{"InstanceId": machine["InstanceId"]}]}
    data = ec2_data([machine], [attached()], groups=[group])
    assert findings(LONG_STOPPED_INSTANCES, data) == ()


def test_the_volume_sum_covers_every_attached_disk():
    machine = instance(state="stopped", StateTransitionReason=STOPPED_90_DAYS)
    disks = [
        attached(size=100, kind="gp3"),  # $8
        {
            "VolumeId": "vol-second",
            "Size": 200,
            "VolumeType": "gp2",  # $20
            "Attachments": [{"InstanceId": machine["InstanceId"]}],
        },
    ]
    found = findings(LONG_STOPPED_INSTANCES, ec2_data([machine], disks))
    assert found[0].monthly_usd == 28.0
    assert "2 attached volumes" in found[0].estimate.basis


# --- oversized instances --------------------------------------------------


def quiet_cpu(**params):
    if params["MetricName"] == "CPUUtilization":
        return datapoints([2.0] * 336, "Maximum")
    return datapoints([1_000_000.0] * 14)


def test_flags_an_instance_that_never_uses_its_cpu():
    found = findings(
        OVERSIZED_INSTANCES,
        ec2_data(instances=[instance(kind="m5.xlarge")], metrics=quiet_cpu),
    )
    assert len(found) == 1
    assert found[0].confidence is Confidence.MEDIUM
    # m5.xlarge $0.192 -> m5.large $0.096, over 730 hours.
    assert round(found[0].monthly_usd, 2) == 70.08
    assert "m5.large" in found[0].recommendation


def test_a_busy_instance_is_left_alone():
    def busy(**params):
        if params["MetricName"] == "CPUUtilization":
            return datapoints([3.0] * 335 + [BUSY_CPU_PERCENT + 50], "Maximum")
        return datapoints([1.0] * 14)

    assert (
        findings(OVERSIZED_INSTANCES, ec2_data([instance("i-1", "m5.xlarge")], metrics=busy)) == ()
    )


def test_one_busy_hour_is_enough_to_spare_an_instance():
    """Peak, not average: a box sized for a daily spike is sized correctly."""

    def spiky(**params):
        if params["MetricName"] == "CPUUtilization":
            return datapoints([1.0] * 300 + [95.0] + [1.0] * 35, "Maximum")
        return datapoints([1.0] * 14)

    assert (
        findings(OVERSIZED_INSTANCES, ec2_data([instance("i-1", "m5.xlarge")], metrics=spiky)) == ()
    )


def test_a_thin_metric_history_is_not_enough_to_judge():
    def sparse(**params):
        if params["MetricName"] == "CPUUtilization":
            return datapoints([1.0] * 10, "Maximum")
        return datapoints([1.0] * 14)

    assert (
        findings(OVERSIZED_INSTANCES, ec2_data([instance("i-1", "m5.xlarge")], metrics=sparse))
        == ()
    )


def test_a_network_heavy_instance_is_left_alone():
    """Low CPU and 200 GB a day is a proxy, and bandwidth scales with size."""

    def network_heavy(**params):
        if params["MetricName"] == "CPUUtilization":
            return datapoints([2.0] * 336, "Maximum")
        return datapoints([200 * 1024**3] * 14)

    data = ec2_data([instance("i-1", "m5.xlarge")], metrics=network_heavy)
    assert findings(OVERSIZED_INSTANCES, data) == ()


def test_an_instance_younger_than_the_window_is_not_judged():
    young = instance(kind="m5.xlarge", age=3)
    assert findings(OVERSIZED_INSTANCES, ec2_data([young], metrics=quiet_cpu)) == ()


def test_spot_instances_are_left_alone():
    spot = instance(kind="m5.xlarge", InstanceLifecycle="spot")
    assert findings(OVERSIZED_INSTANCES, ec2_data([spot], metrics=quiet_cpu)) == ()


def test_dedicated_tenancy_is_left_alone():
    dedicated = instance(kind="m5.xlarge", Placement={"Tenancy": "dedicated"})
    assert findings(OVERSIZED_INSTANCES, ec2_data([dedicated], metrics=quiet_cpu)) == ()


def test_the_smallest_size_in_a_family_has_nowhere_to_go():
    smallest = instance(kind="t3.nano")
    assert findings(OVERSIZED_INSTANCES, ec2_data([smallest], metrics=quiet_cpu)) == ()


def test_an_unpriceable_type_produces_no_finding_rather_than_a_guess():
    exotic = instance(kind="x9z.4xlarge")
    assert findings(OVERSIZED_INSTANCES, ec2_data([exotic], metrics=quiet_cpu)) == ()


def test_an_autoscaling_instance_is_flagged_but_told_where_to_change_it():
    machine = instance(kind="m5.xlarge")
    group = {"AutoScalingGroupName": "web", "Instances": [{"InstanceId": machine["InstanceId"]}]}
    found = findings(OVERSIZED_INSTANCES, ec2_data([machine], groups=[group], metrics=quiet_cpu))
    assert len(found) == 1
    assert "launch template" in found[0].recommendation


def test_ignore_tag_applies_to_both_compute_checks():
    kept = instance(kind="m5.xlarge", Tags=tags(**{"preflight:ignore": ""}))
    assert findings(OVERSIZED_INSTANCES, ec2_data([kept], metrics=quiet_cpu)) == ()


def test_losing_the_autoscaling_permission_skips_the_check():
    data = ec2_data([instance(kind="m5.xlarge")], metrics=quiet_cpu)
    data["describe_auto_scaling_groups"] = denied("DescribeAutoScalingGroups")
    outcome = run(OVERSIZED_INSTANCES, data)
    assert outcome.status == "skipped"
    assert outcome.missing_action == "autoscaling:DescribeAutoScalingGroups"


def test_a_long_window_asks_for_daily_points_not_hourly():
    """CloudWatch caps a response at 1440 datapoints.

    At an hourly period that runs out just past two months, and the call
    fails rather than returning less — so a long `--days` has to step down
    to a daily period instead of asking for something impossible.
    """
    periods: list[int] = []

    def record(**params):
        if params["MetricName"] == "CPUUtilization":
            periods.append(params["Period"])
            return datapoints([2.0] * 90, "Maximum")
        return datapoints([1.0] * 90)

    data = ec2_data([instance(kind="m5.xlarge", age=200)], metrics=record)

    findings(OVERSIZED_INSTANCES, data, lookback_days=14)
    assert periods == [3600]

    periods.clear()
    found = findings(OVERSIZED_INSTANCES, data, lookback_days=90)
    assert periods == [86400]
    assert len(found) == 1, "90 daily points is plenty of history to judge by"
