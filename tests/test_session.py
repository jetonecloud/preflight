"""Credentials, identity, regions, and turning AWS errors into English."""

from __future__ import annotations

from datetime import UTC, date, datetime

import pytest
from botocore.exceptions import ClientError, EndpointConnectionError, NoCredentialsError
from conftest import StubSession, denied

from preflight.core import aws, spend
from preflight.core.session import (
    CLIENT_NAMES,
    GLOBAL_SERVICES,
    Identity,
    identity_caution,
    open_session,
    resolve_regions,
)

ROOT = Identity("123456789012", "arn:aws:iam::123456789012:root", "123456789012")
USER = Identity("123456789012", "arn:aws:iam::123456789012:user/sam", "AIDA1")
ROLE = Identity(
    "123456789012",
    "arn:aws:sts::123456789012:assumed-role/PreflightReadOnlyRole/preflight-scan",
    "AROA1:preflight-scan",
)
OTHER_ROLE = Identity(
    "123456789012",
    "arn:aws:sts::123456789012:assumed-role/AdminRole/sam",
    "AROA2:sam",
)
GOVCLOUD = Identity("123456789012", "arn:aws-us-gov:iam::123456789012:user/sam", "AIDA2")


# --- identity -------------------------------------------------------------


@pytest.mark.parametrize(
    "identity, kind, name",
    [
        (ROOT, "root", None),
        (USER, "user", "sam"),
        (ROLE, "assumed-role", "PreflightReadOnlyRole"),
        (Identity("1", "garbage", "x"), "unknown", None),
    ],
)
def test_identity_reads_its_own_arn(identity, kind, name):
    assert identity.kind == kind
    assert identity.name == name


def test_the_partition_comes_from_the_arn():
    assert USER.partition == "aws"
    assert GOVCLOUD.partition == "aws-us-gov"


def test_the_dedicated_role_is_recognised():
    assert ROLE.is_preflight_role
    assert not OTHER_ROLE.is_preflight_role
    assert not USER.is_preflight_role


def test_no_caution_when_scanning_as_the_role_we_asked_you_to_make():
    assert identity_caution(ROLE) is None


def test_root_gets_a_specific_warning():
    warning, hint = identity_caution(ROOT)
    assert "root" in warning
    assert "preflight scan" in hint


def test_any_other_identity_gets_an_honest_one():
    """We can't enumerate our own permissions, and we don't pretend to."""
    warning, hint = identity_caution(OTHER_ROLE)
    assert OTHER_ROLE.arn in warning
    assert "can't tell what else" in hint


def test_identity_serialises_for_the_report():
    assert ROLE.to_dict()["is_preflight_role"] is True
    assert ROLE.to_dict()["account_id"] == "123456789012"


# --- regions --------------------------------------------------------------


def test_named_regions_are_taken_at_face_value():
    plan = resolve_regions(StubSession(), ["eu-west-1", "us-east-1", "eu-west-1"])
    assert plan.regions == ("eu-west-1", "us-east-1")
    assert plan.note is None


def test_with_no_regions_named_every_enabled_one_is_scanned():
    session = StubSession(
        {
            "describe_regions": {
                "Regions": [{"RegionName": "eu-west-1"}, {"RegionName": "us-east-1"}]
            }
        }
    )
    plan = resolve_regions(session, ())
    assert plan.regions == ("eu-west-1", "us-east-1")


def test_without_describe_regions_we_scan_one_and_say_so():
    session = StubSession({"describe_regions": denied("DescribeRegions")})
    plan = resolve_regions(session, ())
    assert plan.regions == ("us-east-1",)
    assert "ec2:DescribeRegions" in plan.note
    assert "may hold resources" in plan.note


def test_an_empty_region_list_falls_back_to_home():
    plan = resolve_regions(StubSession({"describe_regions": {"Regions": []}}), ())
    assert plan.regions == ("us-east-1",)


# --- clients --------------------------------------------------------------


def test_iam_prefixes_map_to_boto3_names_where_they_differ():
    assert CLIENT_NAMES["elasticloadbalancing"] == "elbv2"
    assert CLIENT_NAMES["tag"] == "resourcegroupstaggingapi"


def test_global_services_are_pinned_to_one_region():
    assert GLOBAL_SERVICES["ce"] == "us-east-1"
    assert GLOBAL_SERVICES["pricing"] == "us-east-1"


# --- error translation ----------------------------------------------------


def client_error(code: str, message: str = "nope") -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": message}}, "DescribeVolumes")


@pytest.mark.parametrize(
    "code",
    [
        "AccessDenied",
        "AccessDeniedException",
        "UnauthorizedOperation",
        "Client.UnauthorizedOperation",
    ],
)
def test_denials_become_a_named_missing_permission(code):
    error = aws.translate(client_error(code), action="ec2:DescribeVolumes")
    assert isinstance(error, aws.MissingPermission)
    assert error.action == "ec2:DescribeVolumes"
    assert "Add ec2:DescribeVolumes" in error.hint


@pytest.mark.parametrize("code", ["ExpiredToken", "InvalidClientTokenId", "RequestExpired"])
def test_credential_problems_say_how_to_fix_them(code):
    error = aws.translate(client_error(code), action="sts:GetCallerIdentity")
    assert isinstance(error, aws.CredentialsError)
    assert "aws sso login" in error.hint


def test_an_unenabled_region_is_a_region_problem():
    error = aws.translate(
        client_error("OptInRequired"), action="ec2:DescribeVolumes", region="ap-south-1"
    )
    assert isinstance(error, aws.RegionUnavailable)
    assert error.region == "ap-south-1"


def test_cost_explorer_not_being_enabled_is_its_own_case():
    error = aws.translate(
        client_error("SubscriptionRequiredException"), action="ce:GetCostAndUsage"
    )
    assert isinstance(error, aws.NotSubscribed)


def test_anything_else_keeps_the_code_and_message():
    error = aws.translate(client_error("Throttling", "slow down"), action="ec2:DescribeVolumes")
    assert type(error) is aws.AwsError
    assert "Throttling" in error.message and "slow down" in error.message


def test_missing_credentials_are_explained_not_raised_raw():
    error = aws.translate(NoCredentialsError(), action="sts:GetCallerIdentity")
    assert isinstance(error, aws.CredentialsError)
    assert "aws sso login" in error.hint


def test_an_unreachable_endpoint_is_a_region_problem():
    error = aws.translate(
        EndpointConnectionError(endpoint_url="https://ec2.ap-south-1.amazonaws.com"),
        action="ec2:DescribeVolumes",
        region="ap-south-1",
    )
    assert isinstance(error, aws.RegionUnavailable)


# --- action names ---------------------------------------------------------


@pytest.mark.parametrize(
    "action, method",
    [
        ("ec2:DescribeVolumes", "describe_volumes"),
        ("rds:DescribeDBInstances", "describe_db_instances"),
        ("tag:GetResources", "get_resources"),
        ("cloudwatch:GetMetricStatistics", "get_metric_statistics"),
        ("elasticloadbalancing:DescribeTargetHealth", "describe_target_health"),
    ],
)
def test_iam_actions_map_onto_boto3_methods(action, method):
    assert aws.method_name(action) == method


def test_the_service_prefix_is_the_first_half():
    assert aws.service_of("elasticloadbalancing:DescribeLoadBalancers") == "elasticloadbalancing"


# --- paginating -----------------------------------------------------------


class Paged:
    """A client that paginates, the way botocore's paginators do."""

    def can_paginate(self, _method):
        return True

    def get_paginator(self, _method):
        return self

    def paginate(self, **_):
        yield {"Volumes": [{"VolumeId": "vol-1"}]}
        yield {"Volumes": [{"VolumeId": "vol-2"}]}


def test_every_page_is_collected():
    assert len(aws.collect(Paged(), "ec2:DescribeVolumes", "Volumes")) == 2


# --- spend ----------------------------------------------------------------


@pytest.mark.parametrize(
    "today, expected",
    [
        (date(2026, 6, 15), (date(2026, 5, 1), date(2026, 6, 1))),
        (date(2026, 1, 3), (date(2025, 12, 1), date(2026, 1, 1))),
        (date(2026, 3, 1), (date(2026, 2, 1), date(2026, 3, 1))),
    ],
)
def test_the_spend_window_is_always_a_whole_month(today, expected):
    assert spend.last_full_month(today) == expected


def test_spend_adds_up_the_service_lines():
    session = StubSession(
        {
            "get_cost_and_usage": {
                "ResultsByTime": [
                    {
                        "Groups": [
                            {
                                "Keys": ["Amazon EC2"],
                                "Metrics": {"UnblendedCost": {"Amount": "100.5", "Unit": "USD"}},
                            },
                            {
                                "Keys": ["Amazon RDS"],
                                "Metrics": {"UnblendedCost": {"Amount": "50.25", "Unit": "USD"}},
                            },
                        ]
                    }
                ]
            }
        }
    )
    result = spend.read(session, today=date(2026, 6, 15))
    assert result.total_usd == pytest.approx(150.75)
    assert result.services[0].name == "Amazon EC2"
    assert result.period == "2026-05"
    assert result.share_of(15.075) == pytest.approx(0.1)


def test_a_denied_spend_lookup_is_not_an_error():
    session = StubSession({"get_cost_and_usage": denied("GetCostAndUsage")})
    assert spend.read(session, today=date(2026, 6, 15)) is None


def test_an_empty_bill_produces_no_comparison():
    session = StubSession({"get_cost_and_usage": {"ResultsByTime": []}})
    assert spend.read(session, today=date(2026, 6, 15)) is None


# --- opening a session ----------------------------------------------------


class FakeSts:
    """Just enough STS to assume a role."""

    def __init__(self, answer=None):
        self.answer = answer
        self.calls: list[dict] = []

    def assume_role(self, **params):
        self.calls.append(params)
        if isinstance(self.answer, BaseException):
            raise self.answer
        return {
            "Credentials": {
                "AccessKeyId": "ASIAEXAMPLE",
                "SecretAccessKey": "secret",
                "SessionToken": "token",
                "Expiration": datetime(2099, 1, 1, tzinfo=UTC),
            }
        }


class FakeBoto3Session:
    """The caller's own session, which is only used to assume the role."""

    def __init__(self, sts, region_name=None):
        self.sts = sts
        self.region_name = region_name

    def client(self, name, **_):
        assert name == "sts"
        return self.sts


@pytest.fixture
def boto3_with(monkeypatch):
    """Patch `boto3.Session`, leaving the botocore-backed construction real."""
    import boto3

    def install(sts=None, *, region_name=None, raises=None):
        real = boto3.Session

        def factory(*args, **kwargs):
            if "botocore_session" in kwargs:
                return real(*args, **kwargs)
            if raises is not None:
                raise raises
            return FakeBoto3Session(sts, region_name=region_name)

        monkeypatch.setattr(boto3, "Session", factory)

    return install


def test_a_session_without_a_role_uses_the_credentials_it_finds(boto3_with):
    boto3_with(FakeSts(), region_name="eu-west-1")
    session = open_session()
    assert session.home_region == "eu-west-1"
    assert "ambient" in session.source


def test_an_explicit_region_beats_the_profiles_default(boto3_with):
    boto3_with(FakeSts(), region_name="eu-west-1")
    assert open_session(region="ap-southeast-2").home_region == "ap-southeast-2"


def test_with_no_region_anywhere_it_falls_back(boto3_with):
    boto3_with(FakeSts())
    assert open_session().home_region == "us-east-1"


def test_the_profile_is_named_in_the_report(boto3_with):
    boto3_with(FakeSts(), region_name="us-east-1")
    assert "'work'" in open_session(profile="work").source


def test_a_profile_that_does_not_exist_says_how_to_list_them(boto3_with):
    from botocore.exceptions import ProfileNotFound

    boto3_with(raises=ProfileNotFound(profile="typo"))
    with pytest.raises(aws.CredentialsError) as caught:
        open_session(profile="typo")
    assert "no AWS profile called 'typo'" in caught.value.message
    assert "configure list-profiles" in caught.value.hint


def test_assuming_a_role_names_the_session_and_passes_the_external_id(boto3_with):
    sts = FakeSts()
    boto3_with(sts, region_name="us-east-1")
    session = open_session(role_arn="arn:aws:iam::123456789012:role/R", external_id="xyz")
    assert sts.calls[0]["RoleArn"] == "arn:aws:iam::123456789012:role/R"
    assert sts.calls[0]["RoleSessionName"] == "preflight-scan"
    assert sts.calls[0]["ExternalId"] == "xyz"
    assert "assumed role" in session.source


def test_no_external_id_is_sent_when_there_is_none(boto3_with):
    sts = FakeSts()
    boto3_with(sts, region_name="us-east-1")
    open_session(role_arn="arn:aws:iam::123456789012:role/R")
    assert "ExternalId" not in sts.calls[0]


def test_assumed_credentials_refresh_themselves(boto3_with):
    """A scan of every region can outlive a one-hour role session."""
    sts = FakeSts()
    boto3_with(sts, region_name="us-east-1")
    session = open_session(role_arn="arn:aws:iam::123456789012:role/R")
    credentials = session._session.get_credentials()
    assert credentials.method == "sts-assume-role"
    assert credentials.access_key == "ASIAEXAMPLE"


def test_being_refused_the_role_points_at_the_trust_policy(boto3_with):
    boto3_with(FakeSts(denied("AssumeRole")))
    with pytest.raises(aws.CredentialsError) as caught:
        open_session(role_arn="arn:aws:iam::123456789012:role/R")
    assert "Not allowed to assume" in caught.value.message
    assert "trust policy" in caught.value.hint
