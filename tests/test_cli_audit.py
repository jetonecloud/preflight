"""`preflight scan --role-arn ...` and `preflight demo`, end to end.

The scan half of the CLI is the half that reads somebody's account, so the
things worth protecting are: it says what it will read before reading it,
it stops when told to, and it never silently swallows a credential problem.

AWS is replaced at the session boundary — `open_session` — which is the one
seam everything else goes through.
"""

from __future__ import annotations

import json

import pytest
from conftest import NOW, StubSession
from typer.testing import CliRunner

from preflight import demo
from preflight.cli import app
from preflight.core import aws
from preflight.core import session as session_module

ENV = {"COLUMNS": "200", "TERM": "dumb", "NO_COLOR": "1"}
ROLE = "arn:aws:iam::123456789012:role/PreflightReadOnlyRole"

runner = CliRunner()


def invoke(*args, **kwargs):
    return runner.invoke(app, list(args), env=ENV, **kwargs)


@pytest.fixture
def workdir(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    return tmp_path


@pytest.fixture
def sample_account(monkeypatch):
    """Every scan in this file reads the demo account instead of AWS."""
    captured = {}

    def fake_open_session(**kwargs):
        captured.update(kwargs)
        return demo.DemoSession(NOW)

    monkeypatch.setattr(session_module, "open_session", fake_open_session)
    return captured


def reports(directory):
    return sorted(path.name for path in directory.glob("preflight-report-*"))


# --- the happy path -------------------------------------------------------


def test_a_scan_writes_both_reports_and_summarises_them(workdir, sample_account):
    result = invoke("scan", "--role-arn", ROLE, "--yes")
    assert result.exit_code == 0, result.stderr

    assert "Estimated saving" in result.stderr
    assert "Start here" in result.stderr
    assert "Report saved" in result.stderr
    written = reports(workdir)
    assert len(written) == 2
    assert any(name.endswith(".html") for name in written)
    assert any(name.endswith(".json") for name in written)


def test_the_plan_is_shown_before_anything_is_read(workdir, sample_account):
    result = invoke("scan", "--role-arn", ROLE, "--yes")
    stderr = result.stderr
    assert "Account 123456789012" in stderr
    assert "Unattached EBS volumes" in stderr
    assert "Get, List and Describe only" in stderr
    # Every permission, including the ones no single check owns.
    assert "ce:GetCostAndUsage" in stderr
    assert "tag:GetResources" in stderr
    assert stderr.index("Get, List and Describe only") < stderr.index("Estimated saving")


def test_the_role_arn_is_passed_to_the_session(workdir, sample_account):
    invoke("scan", "--role-arn", ROLE, "--external-id", "abc123", "--yes")
    assert sample_account["role_arn"] == ROLE
    assert sample_account["external_id"] == "abc123"


def test_a_profile_scan_passes_the_profile(workdir, sample_account):
    invoke("scan", "--profile", "work", "--yes")
    assert sample_account["profile"] == "work"
    assert sample_account["role_arn"] is None


def test_current_credentials_need_no_profile_or_role(workdir, sample_account):
    result = invoke("scan", "--current", "--yes")
    assert result.exit_code == 0
    assert sample_account["profile"] is None
    assert sample_account["role_arn"] is None


def test_regions_are_passed_through(workdir, sample_account):
    result = invoke("scan", "--role-arn", ROLE, "--region", "eu-west-1", "--yes")
    assert result.exit_code == 0
    assert "1 region: eu-west-1" in result.stderr


def test_the_json_report_carries_the_command_that_made_it(workdir, sample_account):
    invoke("scan", "--role-arn", ROLE, "--region", "us-east-1", "--yes")
    path = next(workdir.glob("*.json"))
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["preflight"]["command"] == (
        f"preflight scan --modules cost --role-arn {ROLE} --region us-east-1"
    )
    assert data["scan"]["regions"] == ["us-east-1"]


# --- asking first ---------------------------------------------------------


def test_saying_no_reads_nothing(workdir, sample_account, monkeypatch):
    monkeypatch.setattr("preflight.cli._interactive", lambda: True)
    result = invoke("scan", "--role-arn", ROLE, input="n\n")
    assert result.exit_code == 1
    assert "Nothing was read" in result.stderr
    assert reports(workdir) == []


def test_saying_yes_goes_ahead(workdir, sample_account, monkeypatch):
    monkeypatch.setattr("preflight.cli._interactive", lambda: True)
    result = invoke("scan", "--role-arn", ROLE, input="y\n")
    assert result.exit_code == 0
    assert len(reports(workdir)) == 2


def test_without_a_terminal_it_says_it_is_going_ahead(workdir, sample_account):
    result = invoke("scan", "--role-arn", ROLE)
    assert result.exit_code == 0
    assert "going ahead" in result.stderr


# --- options --------------------------------------------------------------


def test_only_runs_the_checks_asked_for(workdir, sample_account):
    result = invoke("scan", "--role-arn", ROLE, "--only", "unattached-ebs-volumes", "--yes")
    assert result.exit_code == 0
    data = json.loads(next(workdir.glob("*.json")).read_text(encoding="utf-8"))
    assert [check["key"] for check in data["checks"]] == ["unattached-ebs-volumes"]


def test_an_unknown_check_is_rejected_before_anything_is_read(workdir, sample_account):
    result = invoke("scan", "--role-arn", ROLE, "--only", "nonsense", "--yes")
    assert result.exit_code == 2
    assert "Don't know the check 'nonsense'" in result.stderr
    assert reports(workdir) == []


def test_redaction_reaches_the_files(workdir, sample_account):
    invoke("scan", "--role-arn", ROLE, "--redact", "--yes")
    for path in workdir.glob("preflight-report-*"):
        assert "123456789012" not in path.read_text(encoding="utf-8")
    assert any("<account>" in name for name in reports(workdir))


def test_a_single_format_writes_a_single_file(workdir, sample_account):
    invoke("scan", "--role-arn", ROLE, "--format", "json", "--yes")
    assert all(name.endswith(".json") for name in reports(workdir))


def test_an_unknown_format_is_rejected(workdir, sample_account):
    result = invoke("scan", "--role-arn", ROLE, "--format", "pdf", "--yes")
    assert result.exit_code == 2
    assert "Don't know the format 'pdf'" in result.stderr


def test_reports_can_be_written_somewhere_else(workdir, sample_account):
    target = workdir / "audits" / "june"
    invoke("scan", "--role-arn", ROLE, "--out", str(target), "--yes")
    assert len(reports(target)) == 2
    assert reports(workdir) == []


def test_days_must_be_positive(workdir, sample_account):
    result = invoke("scan", "--role-arn", ROLE, "--days", "0", "--yes")
    assert result.exit_code == 2
    assert "at least 1" in result.stderr


def test_the_lookback_window_reaches_the_report(workdir, sample_account):
    invoke("scan", "--role-arn", ROLE, "--days", "30", "--yes")
    data = json.loads(next(workdir.glob("*.json")).read_text(encoding="utf-8"))
    assert data["scan"]["lookback_days"] == 30


def test_an_unavailable_module_is_rejected(workdir, sample_account):
    result = invoke("scan", "--role-arn", ROLE, "--modules", "security", "--yes")
    assert result.exit_code == 2
    assert "isn't available yet" in result.stderr


# --- credentials ----------------------------------------------------------


def test_missing_credentials_are_explained_not_dumped(workdir, monkeypatch):
    def refuse(**_):
        raise aws.CredentialsError("No AWS credentials found.", "Try aws sso login.")

    monkeypatch.setattr(session_module, "open_session", refuse)
    result = invoke("scan", "--role-arn", ROLE, "--yes")
    assert result.exit_code == 1
    assert "No AWS credentials found." in result.stderr
    assert "aws sso login" in result.stderr
    assert "Traceback" not in result.stderr


def test_an_untrusted_role_says_what_to_check(workdir, monkeypatch):
    def refuse(**_):
        raise aws.CredentialsError(f"Not allowed to assume {ROLE}.", "Check the trust policy.")

    monkeypatch.setattr(session_module, "open_session", refuse)
    result = invoke("scan", "--role-arn", ROLE, "--yes")
    assert result.exit_code == 1
    assert "trust policy" in result.stderr


def test_an_over_privileged_identity_is_called_out(workdir, monkeypatch):
    from preflight.core.session import Identity

    admin = Identity(
        "123456789012", "arn:aws:sts::123456789012:assumed-role/AdminRole/sam", "AROA:sam"
    )

    def as_admin(**_):
        session = demo.DemoSession(NOW)
        session._identity = admin
        return session

    monkeypatch.setattr(session_module, "open_session", as_admin)
    result = invoke("scan", "--role-arn", ROLE, "--yes")
    assert result.exit_code == 0
    assert "can't tell what else this identity is allowed to do" in result.stderr


def test_scanning_as_the_dedicated_role_says_nothing_about_it(workdir, sample_account):
    result = invoke("scan", "--role-arn", ROLE, "--yes")
    assert "can't tell what else" not in result.stderr


# --- gaps -----------------------------------------------------------------


def test_a_missing_permission_is_reported_with_the_fix(workdir, monkeypatch):
    from conftest import denied

    responses = {"describe_volumes": denied("DescribeVolumes")}

    def partly_denied(**_):
        session = demo.DemoSession(NOW)
        real_client = session.client

        def client(service, region=None):
            if service == "ec2":
                return StubSession(responses).client(service, region)
            return real_client(service, region)

        session.client = client
        return session

    monkeypatch.setattr(session_module, "open_session", partly_denied)
    result = invoke("scan", "--role-arn", ROLE, "--yes")
    assert result.exit_code == 0
    assert "skipped" in result.stderr
    assert "ec2:DescribeVolumes" in result.stderr
    assert "preflight scan --modules cost --save" in result.stderr

    data = json.loads(next(workdir.glob("*.json")).read_text(encoding="utf-8"))
    assert "ec2:DescribeVolumes" in data["missing_actions"]


# --- demo -----------------------------------------------------------------


def test_demo_writes_a_sample_report(workdir):
    result = invoke("demo")
    assert result.exit_code == 0
    assert "Sample data" in result.stderr
    assert len(reports(workdir)) == 2


def test_demo_needs_no_credentials(workdir, monkeypatch):
    def explode(**_):
        raise AssertionError("demo must not open an AWS session")

    monkeypatch.setattr(session_module, "open_session", explode)
    assert invoke("demo").exit_code == 0


def test_demo_honours_the_output_options(workdir):
    target = workdir / "samples"
    result = invoke("demo", "--out", str(target), "--format", "html")
    assert result.exit_code == 0
    assert all(name.endswith(".html") for name in reports(target))


# --- a clean account ------------------------------------------------------


def test_an_account_with_nothing_wrong_says_so(workdir, monkeypatch):
    """The quiet case is the one people will doubt, so it gets its own words."""
    from conftest import StubSession

    empty = {
        "describe_regions": {"Regions": [{"RegionName": "us-east-1"}]},
        "describe_volumes": {"Volumes": []},
        "describe_addresses": {"Addresses": []},
        "describe_nat_gateways": {"NatGateways": []},
        "describe_snapshots": {"Snapshots": []},
        "describe_images": {"Images": []},
        "describe_instances": {"Reservations": []},
        "describe_auto_scaling_groups": {"AutoScalingGroups": []},
        "describe_load_balancers": {"LoadBalancers": [], "LoadBalancerDescriptions": []},
        "describe_target_groups": {"TargetGroups": []},
        "describe_db_instances": {"DBInstances": []},
        "describe_db_snapshots": {"DBSnapshots": []},
        "get_cost_and_usage": {"ResultsByTime": []},
        "get_resources": {"ResourceTagMappingList": []},
    }
    monkeypatch.setattr(session_module, "open_session", lambda **_: StubSession(empty))

    result = invoke("scan", "--role-arn", ROLE, "--yes")
    assert result.exit_code == 0
    assert "Nothing worth flagging" in result.stderr
    assert "Start here" not in result.stderr

    data = json.loads(next(workdir.glob("*.json")).read_text(encoding="utf-8"))
    assert data["summary"]["findings"] == 0
    assert data["summary"]["checks_run"] == 9
    assert data["spend"] is None
