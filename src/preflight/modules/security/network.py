"""Security groups that let the whole internet in where it shouldn't be.

A web server open on 443 is doing its job. A database open on 5432, or a
box answering SSH to every address on earth, is a door somebody propped
open during a debugging session and never shut. The check only cares about
groups that are attached to something: an open rule on a group nothing uses
is untidy, not exposed.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from preflight.core.findings import Confidence, Finding, Resource, Severity
from preflight.core.scan import ScanContext, ignored, name_of, tags_to_dict
from preflight.modules.base import Check

MODULE = "security"

ANYWHERE_V4 = "0.0.0.0/0"
ANYWHERE_V6 = "::/0"

#: Ports nobody should reach from the open internet, and what usually listens
#: on them. SSH is here but treated more gently below: key-only SSH open to
#: the world is common and survivable, if noisy.
SENSITIVE_PORTS: dict[int, str] = {
    22: "SSH",
    23: "Telnet",
    445: "SMB",
    1433: "SQL Server",
    1521: "Oracle",
    2375: "the Docker API",
    2376: "the Docker API",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5601: "Kibana",
    5984: "CouchDB",
    6379: "Redis",
    9200: "Elasticsearch",
    11211: "Memcached",
    27017: "MongoDB",
}

#: A rule spanning this many ports is "everything" in all but name.
WIDE_RANGE = 1000


def open_security_groups(ctx: ScanContext) -> Iterator[Finding]:
    """Groups in use that admit 0.0.0.0/0 or ::/0 to admin or database ports."""
    for region in ctx.regions:
        groups = ctx.collect("ec2:DescribeSecurityGroups", "SecurityGroups", region=region)
        if not groups:
            continue
        in_use = _interfaces_by_group(ctx, region)

        for group in groups:
            ctx.looked_at()
            group_id = str(group.get("GroupId"))
            exposed = _exposure(group.get("IpPermissions") or ())
            if not exposed:
                continue
            attached = in_use.get(group_id, 0)
            if not attached:
                continue
            tags = tags_to_dict(group.get("Tags"))
            if ignored(tags):
                continue

            everything = any(item.startswith("all traffic") for item in exposed)
            only_ssh = all(item.startswith("port 22 ") for item in exposed)
            severity = Severity.MEDIUM if only_ssh else Severity.HIGH

            what = "is" if attached == 1 else "are"
            noun = "network interface" if attached == 1 else "network interfaces"
            evidence = [
                "Open to the whole internet: " + "; ".join(exposed) + ".",
                f"{attached} {noun} {what} using it, so this is reachable, not theoretical.",
            ]
            if group.get("GroupName") == "default":
                evidence.append(
                    "This is the VPC's default group, which anything launched "
                    "without a group of its own ends up in."
                )
            evidence.append(
                "Whether anything answers depends on what's listening and on "
                "public addressing, which this check doesn't look at."
            )

            yield Finding(
                check="open-security-groups",
                module=MODULE,
                title=(
                    "Security group open to the internet on every port"
                    if everything
                    else "SSH open to the internet"
                    if only_ssh
                    else "Security group open to the internet on admin or database ports"
                ),
                resource=Resource(
                    id=group_id,
                    kind="ec2:security-group",
                    region=region,
                    name=name_of(tags) or str(group.get("GroupName") or "") or None,
                    arn=ctx.arn("ec2", region, f"security-group/{group_id}"),
                    tags=tags,
                ),
                evidence=tuple(evidence),
                recommendation=(
                    "Narrow the source to the addresses that need it - an office "
                    "range, a VPN, another security group. For shell access, "
                    "Session Manager needs no inbound port at all."
                ),
                # The rule is plainly there and something is using it; what
                # we can't see is whether that something has a public address.
                confidence=Confidence.HIGH,
                severity=severity,
            )


def _exposure(permissions: Any) -> list[str]:
    """What each world-open rule exposes, in words. Empty if nothing sensitive."""
    found: list[str] = []
    for rule in permissions:
        sources = [r.get("CidrIp") for r in rule.get("IpRanges") or ()]
        sources += [r.get("CidrIpv6") for r in rule.get("Ipv6Ranges") or ()]
        if ANYWHERE_V4 not in sources and ANYWHERE_V6 not in sources:
            continue
        protocol = str(rule.get("IpProtocol", ""))
        if protocol == "-1":
            found.append("all traffic, every protocol and port")
            continue
        if protocol not in ("tcp", "6", "udp", "17"):
            continue
        low = int(rule.get("FromPort", 0))
        high = int(rule.get("ToPort", low))
        if high - low + 1 >= WIDE_RANGE:
            found.append(f"ports {low}-{high} ({protocol})")
            continue
        for port, service in SENSITIVE_PORTS.items():
            if low <= port <= high:
                found.append(f"port {port} ({service})")
    return list(dict.fromkeys(found))


def _interfaces_by_group(ctx: ScanContext, region: str) -> dict[str, int]:
    """How many network interfaces use each security group in a region."""
    counts: dict[str, int] = {}
    for interface in ctx.collect(
        "ec2:DescribeNetworkInterfaces", "NetworkInterfaces", region=region
    ):
        for group in interface.get("Groups") or ():
            group_id = str(group.get("GroupId"))
            counts[group_id] = counts.get(group_id, 0) + 1
    return counts


OPEN_SECURITY_GROUPS = Check(
    key="open-security-groups",
    title="Security groups open to the internet",
    looks_for="Security groups in use that let anyone reach admin or database ports.",
    actions=("ec2:DescribeSecurityGroups", "ec2:DescribeNetworkInterfaces"),
    run=open_security_groups,
)
