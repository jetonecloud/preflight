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


def test_a_scan_prints_the_report_and_writes_the_json(workdir, sample_account):
    result = invoke("scan", "--role-arn", ROLE, "--yes")
    assert result.exit_code == 0, result.stderr

    assert "findings, about $" in result.stderr
    assert "JSON saved to" in result.stderr
    assert "Estimated saving" in result.stderr
    assert "Start here" in result.stderr
    assert "Everything we found" in result.stderr
    assert "What was checked" in result.stderr
    assert "How these numbers were worked out" in result.stderr
    written = reports(workdir)
    assert len(written) == 1
    assert written[0].endswith(".json")


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


#: An interactive scan asks three things in order: where the report goes,
#: whether to keep the JSON, and then whether to read the account at all.
ANSWERS = "terminal\ny\n"


def test_saying_no_reads_nothing(workdir, sample_account, monkeypatch):
    monkeypatch.setattr("preflight.cli._interactive", lambda: True)
    result = invoke("scan", "--role-arn", ROLE, input=f"{ANSWERS}n\n")
    assert result.exit_code == 1
    assert "Nothing was read" in result.stderr
    assert reports(workdir) == []


def test_saying_yes_goes_ahead(workdir, sample_account, monkeypatch):
    monkeypatch.setattr("preflight.cli._interactive", lambda: True)
    result = invoke("scan", "--role-arn", ROLE, input=f"{ANSWERS}y\n")
    assert result.exit_code == 0
    assert len(reports(workdir)) == 1


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


def test_the_json_export_can_be_turned_off(workdir, sample_account):
    result = invoke("scan", "--role-arn", ROLE, "--no-json", "--yes")
    assert result.exit_code == 0
    assert "Estimated saving" in result.stderr
    assert reports(workdir) == []


def test_the_json_export_can_be_written_somewhere_else(workdir, sample_account):
    target = workdir / "audits" / "june"
    invoke("scan", "--role-arn", ROLE, "--out", str(target), "--yes")
    assert len(reports(target)) == 1
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


def test_demo_prints_a_sample_report(workdir):
    result = invoke("demo")
    assert result.exit_code == 0
    assert "Sample data" in result.stderr
    assert "Everything we found" in result.stderr
    assert len(reports(workdir)) == 1


def test_demo_needs_no_credentials(workdir, monkeypatch):
    def explode(**_):
        raise AssertionError("demo must not open an AWS session")

    monkeypatch.setattr(session_module, "open_session", explode)
    assert invoke("demo").exit_code == 0


def test_demo_reports_each_check_as_it_finishes(workdir):
    """The sample arrives a line at a time, like the scan it imitates."""
    result = invoke("demo")
    lines = [line for line in result.stderr.splitlines() if line.startswith("  ! ")]
    assert len(lines) == 9


def test_the_sample_does_not_sit_there_pausing_down_a_pipe(workdir, monkeypatch):
    """The pacing is for a reader. A pipe has none, so it waits for nothing."""
    import time as clock

    def explode(_seconds):
        raise AssertionError("nothing should sleep without a terminal to watch it")

    monkeypatch.setattr(clock, "sleep", explode)
    assert invoke("demo", "--no-json").exit_code == 0


def test_demo_honours_the_output_options(workdir):
    target = workdir / "samples"
    result = invoke("demo", "--out", str(target))
    assert result.exit_code == 0
    assert all(name.endswith(".json") for name in reports(target))

    assert invoke("demo", "--no-json").exit_code == 0
    assert reports(workdir) == []


# --- where the report goes ------------------------------------------------
#
# The report, the JSON and the PDF all come off one `ScanResult`, so what's
# worth protecting here is the choosing: the flags mean what they say, the
# questions are only asked when there's somebody to answer them, and a scan
# that was told to write a PDF has written one by the time it says so.


def files(directory, suffix):
    return sorted(path.name for path in directory.glob(f"preflight-report-*{suffix}"))


def test_the_pdf_is_written_and_named_before_it_is_announced(workdir, sample_account):
    result = invoke("scan", "--role-arn", ROLE, "--pdf", "--yes")
    assert result.exit_code == 0
    written = files(workdir, ".pdf")
    assert len(written) == 1
    assert (workdir / written[0]).read_bytes().startswith(b"%PDF")
    assert written[0] in result.stderr


def test_the_pdf_still_says_the_number_in_the_terminal(workdir, sample_account):
    """Whoever ran the scan shouldn't have to open the PDF for the headline."""
    result = invoke("scan", "--role-arn", ROLE, "--pdf", "--yes")
    assert "findings, about $" in result.stderr
    assert "Saved the report" in result.stderr


def test_the_pdf_replaces_the_terminal_report_rather_than_joining_it(workdir, sample_account):
    result = invoke("scan", "--role-arn", ROLE, "--pdf", "--yes")
    assert "How these numbers were worked out" not in result.stderr
    assert "--terminal" in result.stderr


def test_the_pdf_and_the_json_are_written_side_by_side(workdir, sample_account):
    invoke("scan", "--role-arn", ROLE, "--pdf", "--yes")
    pdfs, jsons = files(workdir, ".pdf"), files(workdir, ".json")
    assert len(pdfs) == len(jsons) == 1
    assert pdfs[0].removesuffix(".pdf") == jsons[0].removesuffix(".json")


def test_the_pdf_can_be_the_only_thing_written(workdir, sample_account):
    assert invoke("scan", "--role-arn", ROLE, "--pdf", "--no-json", "--yes").exit_code == 0
    assert files(workdir, ".pdf") and not files(workdir, ".json")


def test_the_terminal_is_still_what_you_get_without_asking_for_anything(workdir, sample_account):
    result = invoke("scan", "--role-arn", ROLE, "--yes")
    assert files(workdir, ".pdf") == []
    assert "How these numbers were worked out" in result.stderr


def test_asking_for_both_formats_is_refused_rather_than_guessed_at(workdir, sample_account):
    result = invoke("scan", "--role-arn", ROLE, "--pdf", "--terminal", "--yes")
    assert result.exit_code == 2
    assert "ask for different things" in result.stderr
    assert reports(workdir) == []


def test_redaction_reaches_the_pdf_too(workdir, sample_account):
    invoke("scan", "--role-arn", ROLE, "--pdf", "--redact", "--yes")
    for path in workdir.glob("preflight-report-*"):
        assert b"123456789012" not in path.read_bytes()


def test_nothing_is_asked_when_there_is_nobody_to_ask(workdir, sample_account):
    """A pipe or a CI job gets the defaults, not a question it can't answer."""
    result = invoke("scan", "--role-arn", ROLE)
    assert result.exit_code == 0
    assert "Where do you want the report?" not in result.stderr
    assert files(workdir, ".json") and not files(workdir, ".pdf")


def test_yes_means_do_not_ask_about_the_output_either(workdir, sample_account, monkeypatch):
    monkeypatch.setattr("preflight.cli._interactive", lambda: True)
    result = invoke("scan", "--role-arn", ROLE, "--yes")
    assert result.exit_code == 0
    assert "Where do you want the report?" not in result.stderr


def test_the_questions_choose_the_pdf(workdir, sample_account, monkeypatch):
    monkeypatch.setattr("preflight.cli._interactive", lambda: True)
    result = invoke("scan", "--role-arn", ROLE, input="pdf\nn\ny\n")
    assert result.exit_code == 0
    assert "Where do you want the report?" in result.stderr
    assert files(workdir, ".pdf") and not files(workdir, ".json")


def test_a_format_flag_still_leaves_the_json_question(workdir, sample_account, monkeypatch):
    monkeypatch.setattr("preflight.cli._interactive", lambda: True)
    result = invoke("scan", "--role-arn", ROLE, "--pdf", input="n\ny\n")
    assert result.exit_code == 0
    assert "Where do you want the report?" not in result.stderr
    assert files(workdir, ".pdf") and not files(workdir, ".json")


def test_no_json_leaves_nothing_to_ask_about_the_json(workdir, sample_account, monkeypatch):
    monkeypatch.setattr("preflight.cli._interactive", lambda: True)
    result = invoke("scan", "--role-arn", ROLE, "--no-json", input="pdf\ny\n")
    assert result.exit_code == 0
    assert "Save the JSON export" not in result.stderr
    assert files(workdir, ".pdf") and not files(workdir, ".json")


def test_the_output_is_settled_before_the_account_is_read(workdir, sample_account, monkeypatch):
    """Asked first, so a scan nobody is watching still finishes by writing."""
    monkeypatch.setattr("preflight.cli._interactive", lambda: True)
    result = invoke("scan", "--role-arn", ROLE, input="pdf\ny\nn\n")
    assert result.exit_code == 1
    assert "Nothing was read" in result.stderr
    assert reports(workdir) == []


def typing(monkeypatch, presses):
    """Drive the arrow picker from a list of keypresses."""
    from preflight import cli, keys

    pressed = iter(presses)
    monkeypatch.setattr(keys, "supported", lambda: True)
    monkeypatch.setattr(keys, "read_key", lambda: next(pressed))
    monkeypatch.setattr(cli, "_interactive", lambda: True)


def test_the_arrow_keys_choose_the_format(workdir, sample_account, monkeypatch):
    from preflight import keys

    typing(monkeypatch, [keys.DOWN, keys.ENTER])
    result = invoke("scan", "--role-arn", ROLE, "--no-json", input="y\n")
    assert result.exit_code == 0
    assert "Report as: PDF" in result.stderr
    assert files(workdir, ".pdf")


def test_enter_on_the_first_row_keeps_the_terminal(workdir, sample_account, monkeypatch):
    from preflight import keys

    typing(monkeypatch, [keys.ENTER])
    result = invoke("scan", "--role-arn", ROLE, "--no-json", input="y\n")
    assert result.exit_code == 0
    assert "Report as: Terminal" in result.stderr
    assert files(workdir, ".pdf") == []


def test_the_cursor_wraps_round_the_ends_of_the_list(workdir, sample_account, monkeypatch):
    from preflight import keys

    typing(monkeypatch, [keys.UP, keys.ENTER])
    result = invoke("scan", "--role-arn", ROLE, "--no-json", input="y\n")
    assert result.exit_code == 0
    assert "Report as: PDF" in result.stderr


def test_a_key_that_means_nothing_leaves_the_choice_alone(workdir, sample_account, monkeypatch):
    from preflight import keys

    typing(monkeypatch, ["x", "9", keys.DOWN, keys.ENTER])
    result = invoke("scan", "--role-arn", ROLE, "--no-json", input="y\n")
    assert result.exit_code == 0
    assert "Report as: PDF" in result.stderr


def test_the_picker_marks_the_row_it_is_on_rather_than_numbering_them(
    workdir, sample_account, monkeypatch
):
    from preflight import keys

    typing(monkeypatch, [keys.ENTER])
    result = invoke("scan", "--role-arn", ROLE, "--no-json", input="y\n")
    assert ">  Terminal" in result.stderr
    assert "[x]" not in result.stderr
    assert "(*)" not in result.stderr
    assert "1  Terminal" not in result.stderr


def test_demo_writes_a_pdf_too(workdir):
    result = invoke("demo", "--pdf")
    assert result.exit_code == 0
    assert len(files(workdir, ".pdf")) == 1
    assert (workdir / files(workdir, ".pdf")[0]).read_bytes().startswith(b"%PDF")


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
