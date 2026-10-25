"""Getting hold of AWS credentials, and knowing whose they are.

Preflight never asks for an access key. It uses the standard AWS credential
chain — environment variables, a named profile, SSO, an instance or task
role — which means the credentials it runs with are ones you already had, and
logging in is something you do with your usual tools before you start.

The one thing this module adds on top is `--role-arn`: assume the dedicated
read-only role, with refreshing credentials so a long multi-region scan
doesn't die an hour in.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from preflight import __version__
from preflight.core import aws
from preflight.core.naming import ROLE_NAME

#: boto3's client name for each IAM service prefix, where they differ. The
#: checks name IAM actions (`elasticloadbalancing:DescribeLoadBalancers`),
#: because that's what goes in the policy; boto3 wants its own spelling.
CLIENT_NAMES: dict[str, str] = {
    "elasticloadbalancing": "elbv2",
    "tag": "resourcegroupstaggingapi",
    "ce": "ce",
    "pricing": "pricing",
}

#: Services with one global endpoint. Pinned to us-east-1 (in the standard
#: partition) rather than scanned per region.
GLOBAL_SERVICES: dict[str, str] = {"ce": "us-east-1", "pricing": "us-east-1"}

#: Where to fall back when nothing — not the profile, not the environment —
#: says which region to talk to first.
DEFAULT_HOME_REGION = "us-east-1"

#: Named in CloudTrail for anyone wondering what read all their volumes.
SESSION_NAME = "preflight-scan"


@dataclass(frozen=True)
class Identity:
    """Who we're scanning as, as `sts:GetCallerIdentity` describes it."""

    account_id: str
    arn: str
    user_id: str

    @property
    def partition(self) -> str:
        parts = self.arn.split(":")
        return parts[1] if len(parts) > 1 and parts[1] else "aws"

    @property
    def kind(self) -> str:
        """`root`, `assumed-role`, `user`, `federated-user`, or `unknown`."""
        tail = self.arn.split(":")[-1] if ":" in self.arn else ""
        if tail == "root":
            return "root"
        head = tail.split("/", 1)[0]
        return head if head in ("assumed-role", "user", "federated-user") else "unknown"

    @property
    def name(self) -> str | None:
        """The role or user name, without the session suffix."""
        tail = self.arn.split(":")[-1] if ":" in self.arn else ""
        parts = tail.split("/")
        return parts[1] if len(parts) > 1 else None

    @property
    def is_preflight_role(self) -> bool:
        """Whether this is the dedicated read-only role Preflight generates."""
        return self.kind == "assumed-role" and self.name == ROLE_NAME

    @property
    def is_root(self) -> bool:
        return self.kind == "root"

    def to_dict(self) -> dict[str, Any]:
        return {
            "account_id": self.account_id,
            "arn": self.arn,
            "kind": self.kind,
            "name": self.name,
            "partition": self.partition,
            "is_preflight_role": self.is_preflight_role,
        }


class AwsSession:
    """One set of credentials, and the clients built from them.

    Clients are cached per service and region: a scan of twelve regions
    shouldn't build twelve-times-six connection pools, and botocore clients
    are safe to share between the threads that read CloudWatch.
    """

    def __init__(self, session: Any, *, home_region: str, source: str) -> None:
        self._session = session
        self._clients: dict[tuple[str, str], Any] = {}
        self.home_region = home_region
        #: How we got these credentials, for the report's header.
        self.source = source
        self._identity: Identity | None = None

    # --- identity ---------------------------------------------------------

    @property
    def identity(self) -> Identity:
        """Who we are. Cached, and the first call AWS sees from a scan."""
        if self._identity is None:
            response = aws.call(self.client("sts"), "sts:GetCallerIdentity")
            self._identity = Identity(
                account_id=str(response.get("Account", "")),
                arn=str(response.get("Arn", "")),
                user_id=str(response.get("UserId", "")),
            )
        return self._identity

    # --- clients ----------------------------------------------------------

    def client(self, service: str, region: str | None = None) -> Any:
        """A boto3 client for an IAM service prefix (`ec2`, not `elbv2`)."""
        where = GLOBAL_SERVICES.get(service) or region or self.home_region
        key = (service, where)
        if key not in self._clients:
            self._clients[key] = self._session.client(
                CLIENT_NAMES.get(service, service),
                region_name=where,
                config=_client_config(),
            )
        return self._clients[key]

    # --- regions ----------------------------------------------------------

    def enabled_regions(self) -> tuple[str, ...]:
        """Regions this account has switched on, sorted.

        Raises `MissingPermission` if `ec2:DescribeRegions` wasn't granted —
        the caller decides whether to fall back to one region or stop.
        """
        regions = aws.collect(
            self.client("ec2"),
            "ec2:DescribeRegions",
            "Regions",
            AllRegions=False,
        )
        names = sorted(str(region["RegionName"]) for region in regions if region.get("RegionName"))
        return tuple(names)


def _client_config() -> Any:
    """Patient retries, a bounded wait, and a user agent we can recognise."""
    from botocore.config import Config

    return Config(
        retries={"max_attempts": 6, "mode": "adaptive"},
        connect_timeout=10,
        read_timeout=30,
        user_agent_extra=f"preflight/{__version__}",
    )


def open_session(
    *,
    profile: str | None = None,
    role_arn: str | None = None,
    external_id: str | None = None,
    region: str | None = None,
) -> AwsSession:
    """Resolve credentials the way the user asked for them.

    With `role_arn`, the profile (or ambient credentials) is used only to
    assume that role — which is the recommended path, because the role is the
    one whose permissions you read before deploying.
    """
    import boto3
    from botocore.exceptions import ProfileNotFound

    try:
        base = boto3.Session(profile_name=profile) if profile else boto3.Session()
    except ProfileNotFound as exc:
        raise aws.profile_error(exc, profile or "") from exc

    home = region or base.region_name or DEFAULT_HOME_REGION

    if role_arn is None:
        source = f"profile '{profile}'" if profile else "the ambient AWS credential chain"
        return AwsSession(base, home_region=home, source=source)

    assumed = _assume(base, role_arn=role_arn, external_id=external_id, region=home)
    return AwsSession(assumed, home_region=home, source=f"assumed role {role_arn}")


def _assume(base: Any, *, role_arn: str, external_id: str | None, region: str) -> Any:
    """A session for `role_arn` whose credentials refresh themselves.

    A scan of every enabled region can outlive the one-hour session the
    generated role allows, and having it fail two thirds of the way through
    would be a miserable way to find that out.
    """
    import boto3
    from botocore.credentials import RefreshableCredentials
    from botocore.session import get_session

    sts = base.client("sts", region_name=region, config=_client_config())
    params: dict[str, Any] = {"RoleArn": role_arn, "RoleSessionName": SESSION_NAME}
    if external_id:
        params["ExternalId"] = external_id

    def fetch() -> dict[str, Any]:
        response = aws.call(sts, "sts:AssumeRole", **params)
        credentials = response["Credentials"]
        return {
            "access_key": credentials["AccessKeyId"],
            "secret_key": credentials["SecretAccessKey"],
            "token": credentials["SessionToken"],
            "expiry_time": credentials["Expiration"].isoformat(),
        }

    try:
        metadata = fetch()
    except aws.MissingPermission as exc:
        raise aws.CredentialsError(
            f"Not allowed to assume {role_arn}.",
            "Check the role's trust policy names the identity you're running as "
            "(the TrustedPrincipalArn parameter on the stack).",
        ) from exc

    credentials = RefreshableCredentials.create_from_metadata(
        metadata=metadata,
        refresh_using=fetch,
        method="sts-assume-role",
    )
    botocore_session = get_session()
    botocore_session._credentials = credentials  # noqa: SLF001 - the documented way in
    botocore_session.set_config_variable("region", region)
    return boto3.Session(botocore_session=botocore_session)


@dataclass(frozen=True)
class RegionPlan:
    """Which regions a scan will read, and how that was decided."""

    regions: tuple[str, ...]
    note: str | None = None


def resolve_regions(session: AwsSession, requested: Sequence[str] | None) -> RegionPlan:
    """Work out the regions to scan.

    Named regions are taken at face value — if you asked for it, we'll try
    it. With none named we read every region the account has enabled, because
    forgotten resources are rarely in the region you remember using. Without
    `ec2:DescribeRegions` we can only scan the one region we were pointed at,
    and the report says so.
    """
    if requested:
        return RegionPlan(tuple(dict.fromkeys(requested)))
    try:
        regions = session.enabled_regions()
    except aws.MissingPermission:
        return RegionPlan(
            (session.home_region,),
            "ec2:DescribeRegions wasn't granted, so only "
            f"{session.home_region} was scanned. Other regions may hold "
            "resources this report doesn't mention.",
        )
    if not regions:
        return RegionPlan((session.home_region,), None)
    return RegionPlan(regions)


def identity_caution(identity: Identity) -> tuple[str, str] | None:
    """`(warning, hint)` if the identity looks broader than it needs to be.

    Preflight can't enumerate its own permissions: that needs
    `iam:SimulatePrincipalPolicy`, which is a permission we'd rather not ask
    for just to say something reassuring. So this is only what the ARN alone
    can tell us, and it's worded to claim exactly that much.
    """
    if identity.is_preflight_role:
        return None
    if identity.is_root:
        return (
            "You're scanning as the account root user.",
            "Root can do anything, and Preflight only needs read access. "
            "Use the generated role instead: preflight scan --modules cost --save",
        )
    return (
        f"Scanning as {identity.arn}.",
        "Preflight only reads, but it can't tell what else this identity is "
        f"allowed to do. The dedicated {ROLE_NAME} is one stack away: "
        "preflight scan --modules cost --save",
    )
