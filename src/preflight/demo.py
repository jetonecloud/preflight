"""A sample account, so you can read a report before trusting us with yours.

`preflight demo` runs the **real** checks — the same functions, the same
guards, the same arithmetic — against canned API responses instead of a live
account. That's deliberate. A hand-written sample report drifts from the
code the moment a check changes its mind about something, and the first
thing it would mislead you about is what the tool actually does.

The dates are relative to today, so the demo never looks stale, and the
account is shaped like a real small one: a couple of regions, a handful of
genuine findings, and several near-misses that the guards correctly leave
alone.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from preflight.core.report import Account, ScanResult
from preflight.core.scan import ScanContext, run_module
from preflight.core.session import AwsSession, Identity
from preflight.core.spend import ServiceSpend, Spend
from preflight.modules.cost import COST

ACCOUNT_ID = "123456789012"
REGIONS = ("us-east-1", "eu-west-1")
LOOKBACK_DAYS = 14

IDENTITY = Identity(
    account_id=ACCOUNT_ID,
    arn=f"arn:aws:sts::{ACCOUNT_ID}:assumed-role/PreflightReadOnlyRole/preflight-scan",
    user_id="AROAEXAMPLEDEMO:preflight-scan",
)

SPEND = Spend(
    period="",  # filled in at build time, relative to today
    total_usd=4812.44,
    currency="USD",
    services=(
        ServiceSpend("Amazon Elastic Compute Cloud - Compute", 1894.12),
        ServiceSpend("Amazon Relational Database Service", 1120.80),
        ServiceSpend("EC2 - Other", 742.19),
        ServiceSpend("Amazon Simple Storage Service", 410.55),
        ServiceSpend("AWS Lambda", 188.03),
    ),
)


def build(now: datetime | None = None) -> ScanResult:
    """Run the cost module against the sample account and return the report."""
    started = datetime.now(UTC)
    now = now or started
    session = DemoSession(now)
    ctx = ScanContext(session, regions=REGIONS, lookback_days=LOOKBACK_DAYS, now=now)
    outcomes = run_module(ctx, COST)
    last_month = (now.replace(day=1) - timedelta(days=1)).strftime("%Y-%m")

    return ScanResult(
        account=Account.of(IDENTITY),
        regions=REGIONS,
        outcomes=tuple(outcomes),
        modules=(COST,),
        started_at=started,
        finished_at=datetime.now(UTC),
        lookback_days=LOOKBACK_DAYS,
        credentials="sample data — no AWS calls were made",
        command="preflight demo",
        spend=Spend(
            period=last_month,
            total_usd=SPEND.total_usd,
            currency=SPEND.currency,
            services=SPEND.services,
        ),
        notes=tuple(ctx.notes),
        demo=True,
    )


# --- the fake account -----------------------------------------------------


class DemoSession(AwsSession):
    """A real session with the client factory replaced.

    Subclassing rather than reimplementing means region discovery, identity
    and error handling are the shipping code — so the demo exercises the
    same path a real scan does, which is the whole point of it.
    """

    def __init__(self, now: datetime) -> None:
        super().__init__(None, home_region=REGIONS[0], source="sample data")
        self.now = now
        self._identity = IDENTITY
        self._demo_clients: dict[tuple[str, str], DemoClient] = {}

    def client(self, service: str, region: str | None = None) -> DemoClient:
        where = region or self.home_region
        key = (service, where)
        if key not in self._demo_clients:
            self._demo_clients[key] = DemoClient(service, where, self.now)
        return self._demo_clients[key]


class DemoClient:
    """A boto3-shaped object over canned data.

    Only implements what `core.aws` actually uses: `can_paginate`, and a
    method per operation. Filters are honoured where a check relies on them,
    because a check that passes `Filters=[{"status": "available"}]` and gets
    everything back would be being tested against the wrong thing.
    """

    def __init__(self, service: str, region: str, now: datetime) -> None:
        self.service = service
        self.region = region
        self.now = now

    def can_paginate(self, _method: str) -> bool:
        return False

    def __getattr__(self, method: str) -> Any:
        def call(**params: Any) -> dict[str, Any]:
            handler = getattr(self, f"_{method}", None)
            if handler is None:
                return {}
            return handler(**params)

        return call

    def _days_ago(self, days: float) -> datetime:
        return self.now - timedelta(days=days)

    # --- EC2 ---------------------------------------------------------------

    def _describe_regions(self, **_: Any) -> dict[str, Any]:
        return {"Regions": [{"RegionName": region} for region in REGIONS]}

    def _describe_volumes(self, **params: Any) -> dict[str, Any]:
        volumes = _VOLUMES.get(self.region, [])
        built = [self._volume(volume) for volume in volumes]
        wanted = _filter_values(params, "status")
        if wanted:
            built = [volume for volume in built if volume["State"] in wanted]
        return {"Volumes": built}

    def _volume(self, spec: dict[str, Any]) -> dict[str, Any]:
        volume = dict(spec)
        volume["CreateTime"] = self._days_ago(volume.pop("age_days"))
        volume.setdefault("State", "available")
        volume.setdefault("Attachments", [])
        return volume

    def _describe_addresses(self, **_: Any) -> dict[str, Any]:
        return {"Addresses": list(_ADDRESSES.get(self.region, []))}

    def _describe_nat_gateways(self, **_: Any) -> dict[str, Any]:
        gateways = []
        for spec in _NAT_GATEWAYS.get(self.region, []):
            gateway = dict(spec)
            gateway["CreateTime"] = self._days_ago(gateway.pop("age_days"))
            gateways.append(gateway)
        return {"NatGateways": gateways}

    def _describe_snapshots(self, **_: Any) -> dict[str, Any]:
        snapshots = []
        for spec in _SNAPSHOTS.get(self.region, []):
            snapshot = dict(spec)
            snapshot["StartTime"] = self._days_ago(snapshot.pop("age_days"))
            snapshots.append(snapshot)
        return {"Snapshots": snapshots}

    def _describe_images(self, **_: Any) -> dict[str, Any]:
        return {"Images": list(_IMAGES.get(self.region, []))}

    def _describe_instances(self, **params: Any) -> dict[str, Any]:
        wanted = _filter_values(params, "instance-state-name")
        instances = []
        for spec in _INSTANCES.get(self.region, []):
            instance = dict(spec)
            instance["LaunchTime"] = self._days_ago(instance.pop("age_days"))
            stopped = instance.pop("stopped_days_ago", None)
            if stopped is not None:
                when = self._days_ago(stopped).strftime("%Y-%m-%d %H:%M:%S")
                instance["StateTransitionReason"] = f"User initiated ({when} GMT)"
            state = instance["State"]["Name"]
            if not wanted or state in wanted:
                instances.append(instance)
        return {"Reservations": [{"Instances": instances}] if instances else []}

    # --- Auto Scaling ------------------------------------------------------

    def _describe_auto_scaling_groups(self, **_: Any) -> dict[str, Any]:
        return {"AutoScalingGroups": list(_ASGS.get(self.region, []))}

    # --- Load balancers ----------------------------------------------------

    def _describe_load_balancers(self, **_: Any) -> dict[str, Any]:
        if self.service == "elb":
            return {"LoadBalancerDescriptions": self._classic()}
        balancers = []
        for spec in _BALANCERS.get(self.region, []):
            balancer = dict(spec)
            balancer["CreatedTime"] = self._days_ago(balancer.pop("age_days"))
            balancers.append(balancer)
        return {"LoadBalancers": balancers}

    def _classic(self) -> list[dict[str, Any]]:
        balancers = []
        for spec in _CLASSIC_BALANCERS.get(self.region, []):
            balancer = dict(spec)
            balancer["CreatedTime"] = self._days_ago(balancer.pop("age_days"))
            balancers.append(balancer)
        return balancers

    def _describe_target_groups(self, **_: Any) -> dict[str, Any]:
        return {"TargetGroups": list(_TARGET_GROUPS.get(self.region, []))}

    def _describe_target_health(self, **params: Any) -> dict[str, Any]:
        targets = _TARGET_HEALTH.get(str(params.get("TargetGroupArn")), [])
        return {"TargetHealthDescriptions": list(targets)}

    # --- RDS ---------------------------------------------------------------

    def _describe_db_instances(self, **_: Any) -> dict[str, Any]:
        return {"DBInstances": list(_DATABASES.get(self.region, []))}

    def _describe_db_snapshots(self, **params: Any) -> dict[str, Any]:
        wanted = params.get("SnapshotType")
        snapshots = []
        for spec in _DB_SNAPSHOTS.get(self.region, []):
            snapshot = dict(spec)
            snapshot["SnapshotCreateTime"] = self._days_ago(snapshot.pop("age_days"))
            if wanted and snapshot.get("SnapshotType") != wanted:
                continue
            snapshots.append(snapshot)
        return {"DBSnapshots": snapshots}

    # --- CloudWatch --------------------------------------------------------

    def _get_metric_statistics(self, **params: Any) -> dict[str, Any]:
        metric = str(params.get("MetricName"))
        dimensions = {d["Name"]: d["Value"] for d in params.get("Dimensions", ())}
        target = next(iter(dimensions.values()), "")
        series = _METRICS.get((metric, target))
        if series is None:
            return {"Datapoints": []}
        points = []
        for index, value in enumerate(series["values"]):
            points.append(
                {
                    "Timestamp": self._days_ago(index / 24 if series["hourly"] else index),
                    series["statistic"]: value,
                    "Average": value,
                }
            )
        return {"Datapoints": points}

    # --- Cost Explorer -----------------------------------------------------

    def _get_cost_and_usage(self, **_: Any) -> dict[str, Any]:
        return {
            "ResultsByTime": [
                {
                    "Groups": [
                        {
                            "Keys": [service.name],
                            "Metrics": {
                                "UnblendedCost": {
                                    "Amount": str(service.amount_usd),
                                    "Unit": "USD",
                                }
                            },
                        }
                        for service in SPEND.services
                    ]
                }
            ]
        }

    # --- Tags --------------------------------------------------------------

    def _get_resources(self, **_: Any) -> dict[str, Any]:
        return {"ResourceTagMappingList": list(_TAGGED.get(self.region, []))}


def _filter_values(params: dict[str, Any], name: str) -> set[str]:
    """Pull one filter's values out of an EC2-style `Filters` argument."""
    for entry in params.get("Filters", ()):
        if entry.get("Name") == name:
            return {str(value) for value in entry.get("Values", ())}
    return set()


def _tags(**pairs: str) -> list[dict[str, str]]:
    return [{"Key": key, "Value": value} for key, value in pairs.items()]


def _hours(value: float, count: int = 336) -> dict[str, Any]:
    return {"values": [value] * count, "statistic": "Maximum", "hourly": True}


def _days(value: float, statistic: str = "Sum", count: int = 14) -> dict[str, Any]:
    return {"values": [value] * count, "statistic": statistic, "hourly": False}


# --- the data -------------------------------------------------------------
#
# Shaped like a two-year-old startup account: a staging environment somebody
# half-deleted, a migration that left its disks behind, and one box that was
# sized for a launch that didn't happen.

_VOLUMES: dict[str, list[dict[str, Any]]] = {
    "us-east-1": [
        {
            "VolumeId": "vol-0a1b2c3d4e5f60001",
            "Size": 500,
            "VolumeType": "gp3",
            "age_days": 212,
            "Encrypted": True,
            "Tags": _tags(Name="postgres-migration-old", Owner="platform"),
        },
        {
            "VolumeId": "vol-0a1b2c3d4e5f60002",
            "Size": 120,
            "VolumeType": "gp2",
            "age_days": 95,
            "Tags": _tags(Name="jenkins-data"),
        },
        {
            # Detached three days ago: a migration in progress, not waste.
            "VolumeId": "vol-0a1b2c3d4e5f60003",
            "Size": 30,
            "VolumeType": "gp3",
            "age_days": 3,
            "Tags": _tags(Name="restore-test"),
        },
        {
            "VolumeId": "vol-0a1b2c3d4e5f60010",
            "Size": 200,
            "VolumeType": "gp3",
            "age_days": 400,
            "State": "in-use",
            "Attachments": [{"InstanceId": "i-0dd1ce4455667701"}],
            "Tags": _tags(Name="staging-api-root"),
        },
        {
            "VolumeId": "vol-0a1b2c3d4e5f60011",
            "Size": 300,
            "VolumeType": "gp2",
            "age_days": 400,
            "State": "in-use",
            "Attachments": [{"InstanceId": "i-0dd1ce4455667701"}],
            "Tags": _tags(Name="staging-api-data"),
        },
        {
            "VolumeId": "vol-0a1b2c3d4e5f60012",
            "Size": 100,
            "VolumeType": "gp3",
            "age_days": 300,
            "State": "in-use",
            "Attachments": [{"InstanceId": "i-0b5a9c1d2e3f40001"}],
        },
    ],
    "eu-west-1": [
        {
            "VolumeId": "vol-0f9e8d7c6b5a40001",
            "Size": 1000,
            "VolumeType": "st1",
            "age_days": 540,
            "Tags": _tags(Name="analytics-scratch", Owner="data"),
        },
        {
            # Deliberately kept, and tagged to say so.
            "VolumeId": "vol-0f9e8d7c6b5a40002",
            "Size": 250,
            "VolumeType": "gp3",
            "age_days": 300,
            "Tags": _tags(Name="legal-hold-2024", **{"preflight:ignore": "retention"}),
        },
    ],
}

_ADDRESSES: dict[str, list[dict[str, Any]]] = {
    "us-east-1": [
        {
            "AllocationId": "eipalloc-0123456789abcdef0",
            "PublicIp": "203.0.113.17",
            "PublicIpv4Pool": "amazon",
            "Tags": _tags(Name="old-bastion"),
        },
        {
            "AllocationId": "eipalloc-0123456789abcdef1",
            "PublicIp": "203.0.113.42",
            "PublicIpv4Pool": "amazon",
        },
        {
            # In use — not a finding.
            "AllocationId": "eipalloc-0123456789abcdef2",
            "PublicIp": "203.0.113.88",
            "PublicIpv4Pool": "amazon",
            "AssociationId": "eipassoc-0123456789abcdef0",
            "InstanceId": "i-0b5a9c1d2e3f40001",
        },
    ],
    "eu-west-1": [],
}

_NAT_GATEWAYS: dict[str, list[dict[str, Any]]] = {
    "us-east-1": [
        {
            "NatGatewayId": "nat-0123456789abcdef0",
            "State": "available",
            "SubnetId": "subnet-0aaaa1111bbbb2222",
            "age_days": 380,
            "Tags": _tags(Name="staging-nat", Environment="staging"),
        },
        {
            # Busy: skipped.
            "NatGatewayId": "nat-0123456789abcdef1",
            "State": "available",
            "SubnetId": "subnet-0cccc3333dddd4444",
            "age_days": 380,
            "Tags": _tags(Name="prod-nat"),
        },
    ],
    "eu-west-1": [
        {
            "NatGatewayId": "nat-0fedcba9876543210",
            "State": "available",
            "SubnetId": "subnet-0eeee5555ffff6666",
            "age_days": 200,
            "Tags": _tags(Name="eu-staging-nat"),
        }
    ],
}

_SNAPSHOTS: dict[str, list[dict[str, Any]]] = {
    "us-east-1": [
        {
            "SnapshotId": "snap-0123456789abcdef0",
            "VolumeId": "vol-0deadbeef00000001",
            "VolumeSize": 500,
            "State": "completed",
            "age_days": 430,
            "Description": "pre-migration backup of the old primary",
            "Tags": _tags(Name="pg-pre-migration"),
        },
        {
            # Backs a registered AMI — never flagged, whatever its age.
            "SnapshotId": "snap-0123456789abcdef1",
            "VolumeId": "vol-0deadbeef00000002",
            "VolumeSize": 80,
            "State": "completed",
            "age_days": 500,
            "Description": "golden image base",
        },
        {
            "SnapshotId": "snap-0123456789abcdef2",
            "VolumeId": "vol-0a1b2c3d4e5f60010",
            "VolumeSize": 200,
            "State": "completed",
            "age_days": 20,
            "Description": "nightly",
        },
    ],
    "eu-west-1": [],
}

_IMAGES: dict[str, list[dict[str, Any]]] = {
    "us-east-1": [
        {
            "ImageId": "ami-0123456789abcdef0",
            "Name": "app-base-2025-04",
            "BlockDeviceMappings": [{"Ebs": {"SnapshotId": "snap-0123456789abcdef1"}}],
        }
    ],
    "eu-west-1": [],
}

_INSTANCES: dict[str, list[dict[str, Any]]] = {
    "us-east-1": [
        {
            "InstanceId": "i-0dd1ce4455667701",
            "InstanceType": "m5.large",
            "State": {"Name": "stopped"},
            "age_days": 400,
            "stopped_days_ago": 118,
            "Tags": _tags(Name="staging-api", Environment="staging", Owner="platform"),
        },
        {
            # Stopped last week: somebody is working on it.
            "InstanceId": "i-0dd1ce4455667702",
            "InstanceType": "t3.medium",
            "State": {"Name": "stopped"},
            "age_days": 90,
            "stopped_days_ago": 6,
            "Tags": _tags(Name="perf-test-runner"),
        },
        {
            "InstanceId": "i-0b5a9c1d2e3f40001",
            "InstanceType": "m5.2xlarge",
            "State": {"Name": "running"},
            "age_days": 260,
            "Placement": {"Tenancy": "default"},
            "Tags": _tags(Name="reporting-worker", Owner="data"),
        },
        {
            # Genuinely busy: skipped.
            "InstanceId": "i-0b5a9c1d2e3f40002",
            "InstanceType": "c5.large",
            "State": {"Name": "running"},
            "age_days": 300,
            "Placement": {"Tenancy": "default"},
            "Tags": _tags(Name="api-1"),
        },
    ],
    "eu-west-1": [],
}

_ASGS: dict[str, list[dict[str, Any]]] = {
    "us-east-1": [
        {
            "AutoScalingGroupName": "api-asg",
            "Instances": [{"InstanceId": "i-0b5a9c1d2e3f40002"}],
        }
    ],
    "eu-west-1": [],
}

_BALANCERS: dict[str, list[dict[str, Any]]] = {
    "us-east-1": [
        {
            "LoadBalancerArn": (
                "arn:aws:elasticloadbalancing:us-east-1:123456789012:"
                "loadbalancer/app/staging-alb/50dc6c495c0c9188"
            ),
            "LoadBalancerName": "staging-alb",
            "Type": "application",
            "State": {"Code": "active"},
            "age_days": 300,
        },
        {
            "LoadBalancerArn": (
                "arn:aws:elasticloadbalancing:us-east-1:123456789012:"
                "loadbalancer/app/prod-alb/9f1c2b3a4d5e6f70"
            ),
            "LoadBalancerName": "prod-alb",
            "Type": "application",
            "State": {"Code": "active"},
            "age_days": 420,
        },
    ],
    "eu-west-1": [],
}

_CLASSIC_BALANCERS: dict[str, list[dict[str, Any]]] = {
    "us-east-1": [
        {"LoadBalancerName": "legacy-site-elb", "Instances": [], "age_days": 1800},
    ],
    "eu-west-1": [],
}

_TARGET_GROUPS: dict[str, list[dict[str, Any]]] = {
    "us-east-1": [
        {
            "TargetGroupArn": (
                "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/staging/1"
            ),
            "LoadBalancerArns": [
                "arn:aws:elasticloadbalancing:us-east-1:123456789012:"
                "loadbalancer/app/staging-alb/50dc6c495c0c9188"
            ],
        },
        {
            "TargetGroupArn": (
                "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/prod/1"
            ),
            "LoadBalancerArns": [
                "arn:aws:elasticloadbalancing:us-east-1:123456789012:"
                "loadbalancer/app/prod-alb/9f1c2b3a4d5e6f70"
            ],
        },
    ],
    "eu-west-1": [],
}

_TARGET_HEALTH: dict[str, list[dict[str, Any]]] = {
    "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/staging/1": [],
    "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/prod/1": [
        {"Target": {"Id": "i-0b5a9c1d2e3f40002"}, "TargetHealth": {"State": "healthy"}},
    ],
}

_DATABASES: dict[str, list[dict[str, Any]]] = {
    "us-east-1": [
        {
            "DBInstanceIdentifier": "analytics-staging",
            "DBInstanceArn": "arn:aws:rds:us-east-1:123456789012:db:analytics-staging",
            "DBInstanceStatus": "stopped",
            "DBInstanceClass": "db.t3.large",
            "Engine": "postgres",
            "AllocatedStorage": 1000,
            "StorageType": "gp2",
            "TagList": _tags(Name="analytics-staging", Owner="data"),
        },
        {
            "DBInstanceIdentifier": "app-prod",
            "DBInstanceArn": "arn:aws:rds:us-east-1:123456789012:db:app-prod",
            "DBInstanceStatus": "available",
            "DBInstanceClass": "db.m6g.large",
            "Engine": "postgres",
            "AllocatedStorage": 500,
            "StorageType": "gp3",
            "TagList": _tags(Name="app-prod"),
        },
    ],
    "eu-west-1": [],
}

_DB_SNAPSHOTS: dict[str, list[dict[str, Any]]] = {
    "us-east-1": [
        {
            "DBSnapshotIdentifier": "app-prod-before-v2-cutover",
            "DBSnapshotArn": (
                "arn:aws:rds:us-east-1:123456789012:snapshot:app-prod-before-v2-cutover"
            ),
            "DBInstanceIdentifier": "app-prod",
            "SnapshotType": "manual",
            "Status": "available",
            "Engine": "postgres",
            "AllocatedStorage": 500,
            "age_days": 410,
            "TagList": [],
        },
        {
            "DBSnapshotIdentifier": "app-prod-recent",
            "DBSnapshotArn": "arn:aws:rds:us-east-1:123456789012:snapshot:app-prod-recent",
            "DBInstanceIdentifier": "app-prod",
            "SnapshotType": "manual",
            "Status": "available",
            "Engine": "postgres",
            "AllocatedStorage": 500,
            "age_days": 30,
            "TagList": [],
        },
    ],
    "eu-west-1": [],
}

_TAGGED: dict[str, list[dict[str, Any]]] = {
    "us-east-1": [
        {
            "ResourceARN": (
                "arn:aws:elasticloadbalancing:us-east-1:123456789012:"
                "loadbalancer/app/staging-alb/50dc6c495c0c9188"
            ),
            "Tags": _tags(Name="staging-alb", Environment="staging", Owner="platform"),
        }
    ],
    "eu-west-1": [],
}

#: `(metric, dimension value)` -> a flat series. Anything not listed here has
#: no datapoints at all, which is what a genuinely unused resource looks like.
_METRICS: dict[tuple[str, str], dict[str, Any]] = {
    ("BytesOutToDestination", "nat-0123456789abcdef0"): _days(0.0),
    ("ActiveConnectionCount", "nat-0123456789abcdef0"): _days(0.0, "Maximum"),
    ("BytesOutToDestination", "nat-0123456789abcdef1"): _days(84_000_000_000.0),
    ("ActiveConnectionCount", "nat-0123456789abcdef1"): _days(312.0, "Maximum"),
    ("BytesOutToDestination", "nat-0fedcba9876543210"): _days(0.0),
    ("ActiveConnectionCount", "nat-0fedcba9876543210"): _days(0.0, "Maximum"),
    ("CPUUtilization", "i-0b5a9c1d2e3f40001"): _hours(3.4),
    ("NetworkIn", "i-0b5a9c1d2e3f40001"): _days(1_200_000_000.0),
    ("CPUUtilization", "i-0b5a9c1d2e3f40002"): _hours(64.2),
    ("NetworkIn", "i-0b5a9c1d2e3f40002"): _days(40_000_000_000.0),
    ("RequestCount", "app/prod-alb/9f1c2b3a4d5e6f70"): _days(2_400_000.0),
}
