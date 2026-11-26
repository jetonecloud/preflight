"""ECS services that run whatever an image tag points at today.

`:latest` - or no tag, which means the same thing - is a pointer anyone
with push access can move. The service doesn't change when it moves, but
the next task ECS starts does: a crash, a scale-out or a host retirement
quietly deploys whatever was pushed last, with no record of it in the
service. And rolling back means finding and re-pushing the old image,
because there's no old task definition that names it.

An ECR repository with immutable tags is the exception: there, `latest`
can't be moved once it's pushed, so it's as good as a version.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

from preflight.core.findings import Finding, Resource, Severity
from preflight.core.scan import ScanContext, ignored
from preflight.modules.base import Check
from preflight.modules.delivery.common import MIN_RESOURCE_AGE_DAYS, MODULE
from preflight.modules.environment import confidence_for, non_production

#: DescribeServices takes at most this many services per call.
DESCRIBE_BATCH = 10

#: Tags that are moved on purpose, by every push.
MOVING_TAGS = frozenset({"latest"})

#: `<account>.dkr.ecr.<region>.amazonaws.com[.cn]/<repository>`
ECR_HOST = re.compile(r"^(\d{12})\.dkr\.ecr(?:-fips)?\.([a-z0-9-]+)\.amazonaws\.com(?:\.cn)?$")


@dataclass(frozen=True)
class ImageRef:
    """An image reference, taken apart."""

    host: str | None
    repository: str
    tag: str | None
    digest: str | None

    @property
    def pinned(self) -> bool:
        return self.digest is not None

    @property
    def moving(self) -> bool:
        return not self.pinned and (self.tag is None or self.tag in MOVING_TAGS)

    @property
    def ecr(self) -> tuple[str, str] | None:
        """(account, region) when the image lives in ECR."""
        if self.host is None:
            return None
        match = ECR_HOST.match(self.host)
        return (match.group(1), match.group(2)) if match else None


def parse_image(image: str) -> ImageRef:
    """`host:5000/team/app:v1@sha256:...` into its parts.

    The registry host is the first path segment only when it looks like
    one (has a dot or a port, or is `localhost`); otherwise `team/app` is
    a Docker Hub repository.
    """
    rest, _, digest = image.partition("@")
    host: str | None = None
    first, sep, remainder = rest.partition("/")
    if sep and ("." in first or ":" in first or first == "localhost"):
        host, rest = first, remainder
    name, colon, tag = rest.rpartition(":")
    if not colon or "/" in tag:
        name, tag = rest, ""
    return ImageRef(host=host, repository=name, tag=tag or None, digest=digest or None)


def services_on_moving_tags(ctx: ScanContext) -> Iterator[Finding]:
    """Services whose task definition names an image by `:latest` or no tag."""
    definitions: dict[str, dict[str, Any]] = {}
    for region in ctx.regions:
        for cluster in ctx.collect("ecs:ListClusters", "clusterArns", region=region):
            arns = [
                str(arn)
                for arn in ctx.collect(
                    "ecs:ListServices", "serviceArns", region=region, cluster=str(cluster)
                )
            ]
            for start in range(0, len(arns), DESCRIBE_BATCH):
                described = ctx.call(
                    "ecs:DescribeServices",
                    region=region,
                    cluster=str(cluster),
                    services=arns[start : start + DESCRIBE_BATCH],
                    include=["TAGS"],
                )
                for service in described.get("services") or ():
                    finding = _judge(ctx, region, str(cluster), service, definitions)
                    if finding is not None:
                        yield finding


def _judge(
    ctx: ScanContext,
    region: str,
    cluster: str,
    service: dict[str, Any],
    definitions: dict[str, dict[str, Any]],
) -> Finding | None:
    if service.get("status") != "ACTIVE" or int(service.get("desiredCount") or 0) == 0:
        return None
    ctx.looked_at()
    tags = _tags(service.get("tags"))
    if ignored(tags) or non_production(tags):
        return None
    age = ctx.days_since(service.get("createdAt"))
    if age is not None and age < MIN_RESOURCE_AGE_DAYS:
        return None
    arn = str(service.get("taskDefinition") or "")
    if not arn:
        return None
    if arn not in definitions:
        described = ctx.call("ecs:DescribeTaskDefinition", region=region, taskDefinition=arn)
        definitions[arn] = described.get("taskDefinition") or {}
    moving = [
        (str(container.get("name")), str(container.get("image")))
        for container in definitions[arn].get("containerDefinitions") or ()
        if container.get("image") and _moves(ctx, parse_image(str(container["image"])))
    ]
    if not moving:
        return None
    return _finding(ctx, region, cluster, service, tags, arn, moving)


def _moves(ctx: ScanContext, ref: ImageRef) -> bool:
    if not ref.moving:
        return False
    ecr = ref.ecr
    if ecr is None or ecr[0] != ctx.account_id:
        return True
    # Our own ECR: an immutable repository can't have its tags moved.
    repositories = ctx.collect("ecr:DescribeRepositories", "repositories", region=ecr[1])
    for repository in repositories:
        if repository.get("repositoryName") == ref.repository:
            return not str(repository.get("imageTagMutability", "")).startswith("IMMUTABLE")
    return True


def _tags(raw: Any) -> dict[str, str]:
    """ECS spells tag keys in lower case, unlike nearly everything else."""
    return {
        str(tag.get("key")): str(tag.get("value", ""))
        for tag in raw or ()
        if tag.get("key") is not None
    }


def _finding(
    ctx: ScanContext,
    region: str,
    cluster: str,
    service: dict[str, Any],
    tags: dict[str, str],
    definition: str,
    moving: list[tuple[str, str]],
) -> Finding:
    name = str(service.get("serviceName"))
    cluster_name = cluster.rsplit("/", 1)[-1]
    revision = definition.rsplit("/", 1)[-1]
    images = ", ".join(f"{container} runs {image}" for container, image in moving)
    evidence = [
        f"Service {name} in cluster {cluster_name}, on task definition {revision}.",
        f"{images}.",
        "Every task ECS starts - after a crash, a scale-out, a host retirement - pulls "
        "whatever that tag points at then, which may not be what was deployed. Rolling "
        "back means re-pushing the old image, since no task definition names it.",
    ]
    return Finding(
        check="services-on-moving-tags",
        module=MODULE,
        title="ECS service deploys a moving image tag",
        resource=Resource(
            id=f"{cluster_name}/{name}",
            kind="ecs:service",
            region=region,
            arn=service.get("serviceArn")
            or ctx.arn("ecs", region, f"service/{cluster_name}/{name}"),
            tags=tags,
        ),
        evidence=tuple(evidence),
        recommendation=(
            "Tag each build with something that never moves (the commit hash, a version) "
            "and deploy that tag, or pin the image by digest; turning on tag immutability "
            "in ECR stops it happening again."
        ),
        confidence=confidence_for(tags),
        severity=Severity.MEDIUM,
    )


SERVICES_ON_MOVING_TAGS = Check(
    key="services-on-moving-tags",
    title="Services that deploy a moving image tag",
    looks_for=(
        "ECS services whose containers run :latest or an untagged image, outside an "
        "ECR repository with immutable tags."
    ),
    actions=(
        "ecs:ListClusters",
        "ecs:ListServices",
        "ecs:DescribeServices",
        "ecs:DescribeTaskDefinition",
        "ecr:DescribeRepositories",
    ),
    run=services_on_moving_tags,
)
