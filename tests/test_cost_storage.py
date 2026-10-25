"""Unattached volumes and old snapshots.

Every check gets three tests: it finds the thing, it stays quiet when it
should, and its guard holds. The guard cases are the valuable ones — a
check that over-reports is worse than one that doesn't exist, because
people stop reading the report rather than stop using the check.
"""

from __future__ import annotations

from conftest import days_ago, denied, findings, run, tags

from preflight.core.findings import Confidence
from preflight.modules.cost.storage import (
    MIN_VOLUME_AGE_DAYS,
    OLD_SNAPSHOTS,
    ORPHAN_SNAPSHOT_DAYS,
    STALE_SNAPSHOT_DAYS,
    UNATTACHED_VOLUMES,
)


def volume(volume_id="vol-0aaa1111bbbb2222a", size=100, kind="gp3", age=90, **extra):
    return {
        "VolumeId": volume_id,
        "Size": size,
        "VolumeType": kind,
        "State": "available",
        "CreateTime": days_ago(age),
        **extra,
    }


# --- unattached volumes ---------------------------------------------------


def test_flags_an_available_volume_and_prices_it():
    found = findings(UNATTACHED_VOLUMES, {"describe_volumes": {"Volumes": [volume(size=500)]}})
    assert len(found) == 1
    finding = found[0]
    assert finding.resource.id == "vol-0aaa1111bbbb2222a"
    assert finding.confidence is Confidence.HIGH
    # 500 GB of gp3 at $0.08.
    assert finding.monthly_usd == 40.0
    assert "$0.08" in finding.estimate.basis
    assert finding.resource.arn.endswith("volume/vol-0aaa1111bbbb2222a")


def test_says_nothing_when_every_volume_is_attached():
    assert findings(UNATTACHED_VOLUMES, {"describe_volumes": {"Volumes": []}}) == ()


def test_leaves_a_freshly_detached_volume_alone():
    """A volume detached this week is a migration, not waste."""
    young = volume(age=MIN_VOLUME_AGE_DAYS - 1)
    assert findings(UNATTACHED_VOLUMES, {"describe_volumes": {"Volumes": [young]}}) == ()


def test_respects_the_ignore_tag():
    kept = volume(Tags=tags(**{"preflight:ignore": "retention"}))
    assert findings(UNATTACHED_VOLUMES, {"describe_volumes": {"Volumes": [kept]}}) == ()


def test_ignore_tag_can_be_switched_off_without_removing_it():
    kept = volume(Tags=tags(**{"preflight:ignore": "false"}))
    assert len(findings(UNATTACHED_VOLUMES, {"describe_volumes": {"Volumes": [kept]}})) == 1


def test_unknown_volume_type_is_priced_at_the_cheapest_tier():
    """An unfamiliar type can lower an estimate, never inflate one."""
    found = findings(
        UNATTACHED_VOLUMES, {"describe_volumes": {"Volumes": [volume(kind="gp9", size=100)]}}
    )
    assert found[0].monthly_usd == 1.5


def test_only_available_volumes_are_asked_for():
    """The filter is part of the check: it must not pull every volume back."""
    outcome = run(UNATTACHED_VOLUMES, {"describe_volumes": {"Volumes": []}})
    assert outcome.status == "ran"


def test_missing_permission_skips_the_check_and_names_the_action():
    outcome = run(UNATTACHED_VOLUMES, {"describe_volumes": denied("DescribeVolumes")})
    assert outcome.status == "skipped"
    assert outcome.missing_action == "ec2:DescribeVolumes"
    assert outcome.findings == ()


def test_counts_what_it_looked_at_even_when_nothing_is_wrong():
    outcome = run(
        UNATTACHED_VOLUMES,
        {"describe_volumes": {"Volumes": [volume(age=1), volume("vol-0b", age=2)]}},
    )
    assert outcome.examined == 2
    assert outcome.findings == ()
    assert outcome.clean


# --- old snapshots --------------------------------------------------------


def snapshot(snapshot_id="snap-0aaa1111bbbb2222a", size=200, age=400, volume_id="vol-0gone", **ex):
    return {
        "SnapshotId": snapshot_id,
        "VolumeId": volume_id,
        "VolumeSize": size,
        "State": "completed",
        "StartTime": days_ago(age),
        **ex,
    }


def snapshot_data(snapshots, images=(), volumes=()):
    return {
        "describe_snapshots": {"Snapshots": list(snapshots)},
        "describe_images": {"Images": list(images)},
        "describe_volumes": {"Volumes": list(volumes)},
    }


def test_flags_a_snapshot_whose_volume_is_gone():
    found = findings(OLD_SNAPSHOTS, snapshot_data([snapshot(size=300)]))
    assert len(found) == 1
    assert found[0].confidence is Confidence.HIGH
    # Incremental: a third of 300 GB at $0.05.
    assert round(found[0].monthly_usd, 2) == 4.95
    assert "no longer exists" in found[0].title


def test_never_flags_a_snapshot_an_ami_depends_on():
    """Deleting one of these breaks the image. Age is irrelevant."""
    backing = snapshot(age=STALE_SNAPSHOT_DAYS * 2)
    image = {
        "ImageId": "ami-1",
        "BlockDeviceMappings": [{"Ebs": {"SnapshotId": backing["SnapshotId"]}}],
    }
    assert findings(OLD_SNAPSHOTS, snapshot_data([backing], images=[image])) == ()


def test_leaves_a_recent_orphan_alone():
    recent = snapshot(age=ORPHAN_SNAPSHOT_DAYS - 1)
    assert findings(OLD_SNAPSHOTS, snapshot_data([recent])) == ()


def test_a_live_volumes_snapshot_is_only_mentioned_after_a_year():
    live = [{"VolumeId": "vol-0live"}]
    young = snapshot(age=STALE_SNAPSHOT_DAYS - 1, volume_id="vol-0live")
    assert findings(OLD_SNAPSHOTS, snapshot_data([young], volumes=live)) == ()

    old = snapshot(age=STALE_SNAPSHOT_DAYS + 1, volume_id="vol-0live")
    found = findings(OLD_SNAPSHOTS, snapshot_data([old], volumes=live))
    assert len(found) == 1
    assert found[0].confidence is Confidence.MEDIUM


def test_incomplete_snapshots_are_skipped():
    pending = snapshot(State="pending")
    assert findings(OLD_SNAPSHOTS, snapshot_data([pending])) == ()


def test_losing_the_ami_permission_skips_rather_than_guesses():
    """Without the guard data the check would invent false positives."""
    data = snapshot_data([snapshot()])
    data["describe_images"] = denied("DescribeImages")
    outcome = run(OLD_SNAPSHOTS, data)
    assert outcome.status == "skipped"
    assert outcome.missing_action == "ec2:DescribeImages"
