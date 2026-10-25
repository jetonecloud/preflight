"""Storage you're paying to keep and nobody is reading.

EBS is where money hides quietly. A volume outlives the instance it was
attached to, a snapshot outlives the volume, and neither of them shows up
anywhere you'd normally look — they just sit on the bill as "EBS" forever.
"""

from __future__ import annotations

from collections.abc import Iterator

from preflight.core.findings import Confidence, Estimate, Finding, Resource
from preflight.core.pricing import ebs_monthly, snapshot_monthly
from preflight.core.scan import ScanContext, ignored, name_of, tags_to_dict
from preflight.modules.base import Check

MODULE = "cost"

#: Don't flag a volume that was detached this week — that's a migration in
#: progress, not waste, and saying so would be the kind of false positive
#: that teaches people to ignore the report.
MIN_VOLUME_AGE_DAYS = 7

#: A snapshot whose volume is gone and which no AMI references is a leftover
#: after three months. Before that it's plausibly someone's safety net.
ORPHAN_SNAPSHOT_DAYS = 90

#: A snapshot of a volume that still exists is probably a backup. We only
#: mention it once it's a year old and almost certainly superseded.
STALE_SNAPSHOT_DAYS = 365


def unattached_volumes(ctx: ScanContext) -> Iterator[Finding]:
    """EBS volumes in the `available` state — attached to nothing, billed anyway."""
    for region in ctx.regions:
        volumes = ctx.collect(
            "ec2:DescribeVolumes",
            "Volumes",
            region=region,
            Filters=[{"Name": "status", "Values": ["available"]}],
        )
        for volume in volumes:
            ctx.looked_at()
            tags = tags_to_dict(volume.get("Tags"))
            if ignored(tags):
                continue

            age = ctx.days_since(volume.get("CreateTime"))
            if age is not None and age < MIN_VOLUME_AGE_DAYS:
                continue

            size = float(volume.get("Size") or 0)
            volume_type = str(volume.get("VolumeType") or "standard")
            volume_id = str(volume.get("VolumeId"))
            monthly, basis = ebs_monthly(volume_type, size)

            evidence = [
                "State is 'available', so it isn't attached to any instance.",
                f"{size:,.0f} GB {volume_type} volume in {region}.",
            ]
            if age is not None:
                evidence.append(f"Created {age:,.0f} days ago.")
            if volume.get("Encrypted"):
                evidence.append("Encrypted, so a snapshot of it will be too.")
            evidence.append(
                "EBS charges for provisioned capacity, not used capacity: an "
                "empty detached volume costs the same as a full one."
            )

            yield Finding(
                check="unattached-ebs-volumes",
                module=MODULE,
                title=f"Unattached {size:,.0f} GB {volume_type} volume",
                resource=Resource(
                    id=volume_id,
                    kind="ec2:volume",
                    region=region,
                    name=name_of(tags),
                    arn=ctx.arn("ec2", region, f"volume/{volume_id}"),
                    tags=tags,
                ),
                evidence=tuple(evidence),
                recommendation=(
                    "Take a snapshot if the data might matter, then delete the "
                    "volume. A snapshot costs a fraction of what the volume does."
                ),
                confidence=Confidence.HIGH,
                estimate=Estimate(monthly, basis),
            )


def old_snapshots(ctx: ScanContext) -> Iterator[Finding]:
    """Snapshots nothing is using: no AMI, and often no volume either.

    The AMI check is the important one. Deleting a snapshot that backs a
    registered image breaks the image, and a report that suggests it would be
    worse than no report — so a snapshot referenced by any AMI we can see is
    never flagged, whatever its age.
    """
    for region in ctx.regions:
        snapshots = ctx.collect(
            "ec2:DescribeSnapshots",
            "Snapshots",
            region=region,
            OwnerIds=["self"],
        )
        if not snapshots:
            continue

        in_use_by_ami = _snapshots_behind_images(ctx, region)
        live_volumes = _volume_ids(ctx, region)

        for snapshot in snapshots:
            ctx.looked_at()
            snapshot_id = str(snapshot.get("SnapshotId"))
            tags = tags_to_dict(snapshot.get("Tags"))
            if ignored(tags) or snapshot.get("State") != "completed":
                continue
            if snapshot_id in in_use_by_ami:
                continue

            age = ctx.days_since(snapshot.get("StartTime"))
            if age is None:
                continue

            source_volume = str(snapshot.get("VolumeId") or "")
            volume_gone = bool(source_volume) and source_volume not in live_volumes

            if volume_gone and age >= ORPHAN_SNAPSHOT_DAYS:
                confidence = Confidence.HIGH
                title = "Snapshot of a volume that no longer exists"
                why = (
                    f"Its source volume ({source_volume}) isn't in this account "
                    "any more, so nothing is being backed up by it."
                )
            elif not volume_gone and age >= STALE_SNAPSHOT_DAYS:
                confidence = Confidence.MEDIUM
                title = "Snapshot over a year old"
                why = (
                    f"Its source volume ({source_volume}) still exists, so this "
                    "is probably an old backup that newer ones have superseded."
                )
            else:
                continue

            size = float(snapshot.get("VolumeSize") or 0)
            monthly, basis = snapshot_monthly(size)

            evidence = [why, f"Taken {age:,.0f} days ago, from a {size:,.0f} GB volume."]
            if not in_use_by_ami:
                evidence.append("No AMI in this account references it.")
            else:
                evidence.append(
                    f"Checked against the {len(in_use_by_ami)} snapshot(s) that back "
                    "AMIs in this region — this isn't one of them."
                )
            if snapshot.get("Description"):
                evidence.append(f"Description: {str(snapshot['Description'])[:160]}")

            yield Finding(
                check="old-snapshots",
                module=MODULE,
                title=title,
                resource=Resource(
                    id=snapshot_id,
                    kind="ec2:snapshot",
                    region=region,
                    name=name_of(tags),
                    arn=ctx.arn("ec2", region, f"snapshot/{snapshot_id}"),
                    tags=tags,
                ),
                evidence=tuple(evidence),
                recommendation=(
                    "Confirm nobody is restoring from it, then delete it. If it's "
                    "a deliberate long-term archive, tag it 'preflight:ignore' and "
                    "it won't come up again."
                ),
                confidence=confidence,
                estimate=Estimate(monthly, basis),
            )


def _snapshots_behind_images(ctx: ScanContext, region: str) -> set[str]:
    """Every snapshot ID referenced by an AMI we own in this region."""
    snapshots: set[str] = set()
    for image in ctx.collect("ec2:DescribeImages", "Images", region=region, Owners=["self"]):
        for mapping in image.get("BlockDeviceMappings", ()):
            snapshot_id = mapping.get("Ebs", {}).get("SnapshotId")
            if snapshot_id:
                snapshots.add(str(snapshot_id))
    return snapshots


def _volume_ids(ctx: ScanContext, region: str) -> set[str]:
    """Every volume that currently exists in this region."""
    return {
        str(volume["VolumeId"])
        for volume in ctx.collect("ec2:DescribeVolumes", "Volumes", region=region)
        if volume.get("VolumeId")
    }


UNATTACHED_VOLUMES = Check(
    key="unattached-ebs-volumes",
    title="Unattached EBS volumes",
    looks_for="Disks that aren't attached to anything but are still billed every hour.",
    actions=("ec2:DescribeVolumes",),
    run=unattached_volumes,
)

OLD_SNAPSHOTS = Check(
    key="old-snapshots",
    title="Snapshots nothing is using",
    looks_for=("Old EBS snapshots whose volume is gone and which no AMI depends on."),
    actions=("ec2:DescribeSnapshots", "ec2:DescribeImages", "ec2:DescribeVolumes"),
    run=old_snapshots,
)
