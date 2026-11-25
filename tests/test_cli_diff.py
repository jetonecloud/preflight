"""End-to-end tests for `preflight diff`."""

from __future__ import annotations

import json

from test_compare import LATER, export, item
from typer.testing import CliRunner

from preflight.cli import app

ENV = {"COLUMNS": "200", "TERM": "dumb", "NO_COLOR": "1"}

runner = CliRunner()


def invoke(*args):
    return runner.invoke(app, [str(arg) for arg in args], env=ENV)


def write(path, data):
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def pair(tmp_path, before, after, **later):
    old = write(tmp_path / "old.json", export(before))
    new = write(tmp_path / "new.json", export(after, when=LATER, **later))
    return old, new


def test_says_what_was_fixed_and_what_is_new(tmp_path):
    kept = item(resource="vol-0aaa", monthly=10.0)
    gone = item(resource="vol-0bbb", monthly=100.0)
    arrived = item(resource="vol-0ccc", monthly=25.0)
    result = invoke("diff", *pair(tmp_path, [kept, gone], [kept, arrived]))
    assert result.exit_code == 0, result.stderr
    assert "$100/month fixed" in result.stderr
    assert "Fixed - gone since" in result.stderr
    assert "vol-0bbb" in result.stderr
    assert "New - not in the earlier scan" in result.stderr
    assert "vol-0ccc" in result.stderr
    assert "1 finding open in both scans" in result.stderr
    assert result.stdout == "", "nothing to pipe unless asked"


def test_nothing_moved(tmp_path):
    same = item()
    result = invoke("diff", *pair(tmp_path, [same], [same]))
    assert result.exit_code == 0
    assert "Nothing moved." in result.stderr


def test_a_skipped_check_shows_up_as_cant_tell(tmp_path):
    gone = item()
    old, new = pair(tmp_path, [gone], [], checks={"unattached-ebs-volumes": "skipped"})
    result = invoke("diff", old, new)
    assert result.exit_code == 0
    assert "Can't tell" in result.stderr
    assert "unattached-ebs-volumes was skipped" in result.stderr
    assert "Fixed - gone" not in result.stderr


def test_an_unpriced_comparison_has_no_dollar_panel(tmp_path):
    alarm = item("alarms-notify-nobody", "web-5xx", module="observability", monthly=None)
    old, new = pair(tmp_path, [alarm], [], checks={"alarms-notify-nobody": "ran"})
    result = invoke("diff", old, new)
    assert result.exit_code == 0
    assert "$" not in result.stderr


def test_refusals_exit_2_with_a_hint(tmp_path):
    old, new = pair(tmp_path, [], [], account="210987654321")
    result = invoke("diff", old, new)
    assert result.exit_code == 2
    assert "two different accounts" in result.stderr
    assert "one account over time" in result.stderr


def test_a_missing_file_exits_2(tmp_path):
    old, _ = pair(tmp_path, [], [])
    result = invoke("diff", old, tmp_path / "nope.json")
    assert result.exit_code == 2
    assert "Couldn't read" in result.stderr


# --- finding the scans on its own --------------------------------------------


def report(directory, data, account="123456789012", stamp="20261101-090000"):
    return write(directory / f"preflight-report-{account}-{stamp}.json", data)


def test_no_arguments_compares_the_last_two_scans(tmp_path):
    from test_compare import EARLIER

    first, second, third = item(resource="vol-0aaa"), item(resource="vol-0bbb"), item()
    report(tmp_path, export([first], when=EARLIER - (LATER - EARLIER)), stamp="20261018-090000")
    report(tmp_path, export([first, second]), stamp="20261101-090000")
    report(tmp_path, export([second, third], when=LATER), stamp="20261115-090000")
    (tmp_path / "preflight-report-123456789012-20261115-090000.pdf").write_bytes(b"%PDF")
    result = invoke("diff", "--in", tmp_path)
    assert result.exit_code == 0, result.stderr
    assert "20261101-090000.json with" in result.stderr
    assert "20261115-090000.json" in result.stderr
    assert "vol-0aaa" in result.stderr, "fixed between the last two"


def test_naming_the_earlier_scan_finds_the_newest_since(tmp_path):
    old = report(tmp_path, export([item()]), stamp="20261101-090000")
    report(tmp_path, export([], when=LATER), stamp="20261115-090000")
    result = invoke("diff", old, "--in", tmp_path)
    assert result.exit_code == 0, result.stderr
    assert "Fixed - gone" in result.stderr


def test_another_accounts_newer_scan_is_left_alone(tmp_path):
    report(tmp_path, export([item()]), stamp="20261101-090000")
    report(tmp_path, export([], when=LATER), stamp="20261115-090000")
    report(
        tmp_path,
        export([], when=LATER, account="210987654321"),
        account="210987654321",
        stamp="20261116-090000",
    )
    result = invoke("diff", "--in", tmp_path)
    assert result.exit_code == 2
    assert "Only one scan of 210987654321" in result.stderr


def test_redacted_exports_are_passed_over(tmp_path):
    report(tmp_path, export([item()]), stamp="20261101-090000")
    report(tmp_path, export([], when=LATER), stamp="20261115-090000")
    report(tmp_path, export([], when=LATER, redacted=True), stamp="20261116-090000")
    result = invoke("diff", "--in", tmp_path)
    assert result.exit_code == 0, result.stderr


def test_an_empty_directory_says_what_to_do(tmp_path):
    result = invoke("diff", "--in", tmp_path)
    assert result.exit_code == 2
    assert "No Preflight exports" in result.stderr


def test_nothing_newer_than_the_named_scan(tmp_path):
    old = report(tmp_path, export([item()]), stamp="20261101-090000")
    result = invoke("diff", old, "--in", tmp_path)
    assert result.exit_code == 2
    assert "No later scan" in result.stderr


# --- scripts and CI -----------------------------------------------------------


def test_json_goes_to_stdout_and_parses(tmp_path):
    from preflight.core.compare import DIFF_SCHEMA_VERSION

    kept, gone = item(resource="vol-0aaa", monthly=10.0), item(resource="vol-0bbb", monthly=90.0)
    worse = item(resource="vol-0aaa", monthly=30.0)
    result = invoke("diff", *pair(tmp_path, [kept, gone], [worse]), "--json")
    assert result.exit_code == 0, result.stderr
    data = json.loads(result.stdout)
    assert data["schema_version"] == DIFF_SCHEMA_VERSION
    assert data["summary"]["fixed"] == 1
    assert data["summary"]["fixed_monthly_usd"] == 90.0
    assert data["summary"]["like_for_like"] is True
    assert [f["id"] for f in data["fixed"]] == [gone["id"]]
    (change,) = data["changed"]
    assert change["monthly_usd"] == {"before": 10.0, "after": 30.0}
    assert data["still_open"] == [kept["id"]]
    assert "Fixed - gone" in result.stderr, "the human copy still goes to stderr"


def test_json_carries_the_reason_a_finding_cant_be_vouched_for(tmp_path):
    old, new = pair(tmp_path, [item()], [], checks={"unattached-ebs-volumes": "skipped"})
    data = json.loads(invoke("diff", old, new, "--json").stdout)
    (entry,) = data["unverified"]
    assert entry["reason"] == "unattached-ebs-volumes was skipped"
    assert data["summary"]["like_for_like"] is False


def test_fail_on_new_fails_when_something_is_new(tmp_path):
    old, new = pair(tmp_path, [], [item()])
    result = invoke("diff", old, new, "--fail-on-new")
    assert result.exit_code == 1
    assert "1 new finding since the last scan" in result.stderr


def test_fail_on_new_passes_when_nothing_is_new(tmp_path):
    old, new = pair(tmp_path, [item()], [])
    assert invoke("diff", old, new, "--fail-on-new").exit_code == 0


def test_fail_on_new_ignores_findings_the_earlier_scan_couldnt_see(tmp_path):
    """Widening a scan to a new region shouldn't fail the build."""
    old = write(tmp_path / "old.json", export([], regions=("us-east-1",)))
    new = write(tmp_path / "new.json", export([item(region="eu-west-1")], when=LATER))
    assert invoke("diff", old, new, "--fail-on-new").exit_code == 0
