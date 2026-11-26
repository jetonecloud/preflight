"""Instances nobody could launch again the same way.

An instance is only as replaceable as the image it was launched from. If
that AMI has been deregistered, losing the instance means rebuilding it
from memory. If the AMI is more than a year old, whatever has been
patched, installed or configured since lives only on the running box -
the image and the instance stopped describing each other a long time ago.

One finding per image, naming the instances launched from it: the fix is
a new image, not a change to each instance.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from preflight.core.findings import Confidence, Finding, Resource, Severity
from preflight.core.scan import ScanContext, ignored, name_of, tags_to_dict
from preflight.modules.base import Check
from preflight.modules.delivery.common import MIN_RESOURCE_AGE_DAYS, MODULE
from preflight.modules.environment import non_production

#: An image older than this has almost certainly been patched around.
STALE_IMAGE_DAYS = 365

#: DescribeImages takes this many IDs comfortably per call.
DESCRIBE_BATCH = 100

#: How many instances to name before summarising the rest.
NAMED_INSTANCES = 3


def instances_you_couldnt_rebuild(ctx: ScanContext) -> Iterator[Finding]:
    """Running instances launched from an AMI that's gone, or over a year old."""
    for region in ctx.regions:
        by_image: dict[str, list[dict[str, Any]]] = {}
        for reservation in ctx.collect("ec2:DescribeInstances", "Reservations", region=region):
            for instance in reservation.get("Instances") or ():
                if (instance.get("State") or {}).get("Name") != "running":
                    continue
                ctx.looked_at()
                tags = tags_to_dict(instance.get("Tags"))
                if ignored(tags):
                    continue
                age = ctx.days_since(instance.get("LaunchTime"))
                if age is not None and age < MIN_RESOURCE_AGE_DAYS:
                    continue
                image = instance.get("ImageId")
                if image:
                    by_image.setdefault(str(image), []).append(instance)
        if not by_image:
            continue
        images = _describe(ctx, region, sorted(by_image))
        for image_id, instances in by_image.items():
            finding = _judge(ctx, region, image_id, images.get(image_id), instances)
            if finding is not None:
                yield finding


def _describe(ctx: ScanContext, region: str, ids: list[str]) -> dict[str, dict[str, Any]]:
    """The images that still exist, by ID. A missing key means it's gone.

    A deregistered image is usually just left out of the answer, but an ID
    AWS has never heard of fails the whole request - so a batch that fails
    that way is asked about one image at a time.
    """
    from preflight.core import aws  # not at the top: generating a role loads no AWS SDK

    found: dict[str, dict[str, Any]] = {}
    for start in range(0, len(ids), DESCRIBE_BATCH):
        batch = ids[start : start + DESCRIBE_BATCH]
        try:
            found.update(_read(ctx, region, batch))
        except aws.NotFound:
            for image_id in batch:
                try:
                    found.update(_read(ctx, region, [image_id]))
                except aws.NotFound:
                    continue
    return found


def _read(ctx: ScanContext, region: str, ids: list[str]) -> dict[str, dict[str, Any]]:
    answer = ctx.call(
        "ec2:DescribeImages",
        region=region,
        ImageIds=ids,
        IncludeDeprecated=True,
        IncludeDisabled=True,
    )
    return {str(image.get("ImageId")): image for image in answer.get("Images") or ()}


def _judge(
    ctx: ScanContext,
    region: str,
    image_id: str,
    image: dict[str, Any] | None,
    instances: list[dict[str, Any]],
) -> Finding | None:
    if image is not None and str(image.get("State", "available")) == "available":
        # Older than a year matters on production; on a sandbox it's just old.
        instances = [i for i in instances if not non_production(tags_to_dict(i.get("Tags")))]
        if not instances:
            return None
        age = ctx.days_since(image.get("CreationDate"))
        if age is None or age < STALE_IMAGE_DAYS:
            return None
        return _finding(
            ctx,
            region,
            image_id,
            image,
            instances,
            title="Instances launched from an image over a year old",
            severity=Severity.LOW,
            confidence=Confidence.MEDIUM,
            reason=(
                f"{_label(image_id, image)} was built {int(age)} days ago. Everything "
                "patched, installed or configured on these instances since then exists "
                "only on them, so a replacement launched from it would come up a year "
                "behind."
            ),
            step=(
                "Build a fresh image from your current setup (EC2 Image Builder, Packer, "
                "or the latest base image plus your provisioning) and roll the instances "
                "onto it."
            ),
        )
    gone = "has been deregistered" if image is None else f"is {image.get('State')}"
    return _finding(
        ctx,
        region,
        image_id,
        image,
        instances,
        title="Instances launched from an image that's gone",
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        reason=(
            f"{_label(image_id, image)} {gone}. If one of these instances fails, "
            "nothing can launch another like it."
        ),
        step=(
            "Capture an image of one of these instances now (CreateImage, or a fresh "
            "build from your provisioning code) and use that for replacements."
        ),
    )


def _label(image_id: str, image: dict[str, Any] | None) -> str:
    name = (image or {}).get("Name")
    return f"Image {image_id} ({name})" if name else f"Image {image_id}"


def _finding(
    ctx: ScanContext,
    region: str,
    image_id: str,
    image: dict[str, Any] | None,
    instances: list[dict[str, Any]],
    *,
    title: str,
    severity: Severity,
    confidence: Confidence,
    reason: str,
    step: str,
) -> Finding:
    labels = []
    for instance in instances[:NAMED_INSTANCES]:
        instance_id = str(instance.get("InstanceId"))
        name = name_of(tags_to_dict(instance.get("Tags")))
        labels.append(f"{instance_id} ({name})" if name else instance_id)
    more = len(instances) - len(labels)
    running = ", ".join(labels) + (f" and {more} more" if more > 0 else "")
    count = "1 running instance" if len(instances) == 1 else f"{len(instances)} running instances"
    return Finding(
        check="instances-you-couldnt-rebuild",
        module=MODULE,
        title=title,
        resource=Resource(
            id=image_id,
            kind="ec2:image",
            region=region,
            name=(image or {}).get("Name"),
            arn=f"arn:{ctx.identity.partition}:ec2:{region}::image/{image_id}",
            tags=tags_to_dict((image or {}).get("Tags")),
        ),
        evidence=(f"{count} launched from it: {running}.", reason),
        recommendation=step,
        confidence=confidence,
        severity=severity,
    )


INSTANCES_YOU_COULDNT_REBUILD = Check(
    key="instances-you-couldnt-rebuild",
    title="Instances you couldn't launch again",
    looks_for=(
        "Running instances whose AMI has been deregistered, or was built more than a year ago."
    ),
    actions=("ec2:DescribeInstances", "ec2:DescribeImages"),
    run=instances_you_couldnt_rebuild,
)
