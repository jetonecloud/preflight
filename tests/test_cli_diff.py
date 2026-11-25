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
