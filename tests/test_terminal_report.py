"""The report, as it appears in the terminal.

The terminal is the report now, so the things the HTML used to promise are
promised here instead: it leads with the number, it says what to do, it
admits what it couldn't read, and it shows its arithmetic. And it is ASCII
all the way down — no box-drawing characters, no em-dashes, nothing that
turns into a question mark down a pipe or in a ticket.
"""

from __future__ import annotations

import pytest
from test_report import finding, outcome, result

from preflight import ui


@pytest.fixture(autouse=True)
def wide(monkeypatch):
    """A fixed, generous width, so nothing under test is wrapped away."""
    monkeypatch.setattr(ui.console, "_width", 200)


def render(report) -> str:
    with ui.console.capture() as captured:
        ui.print_report(report)
    return captured.get()


def test_the_report_leads_with_the_number_and_the_fix():
    text = render(result([outcome([finding(monthly=123.0)])]))
    assert "Estimated saving" in text
    assert "$123/month" in text
    assert "Start here" in text
    assert "Delete it." in text
    assert "500 GB at $0.08/GB-month" in text


def test_every_finding_is_listed_with_its_evidence():
    text = render(result([outcome([finding(), finding(resource_id="vol-0bbb2222cccc3333b")])]))
    assert "Everything we found" in text
    assert "vol-0aaa1111bbbb2222a" in text
    assert "vol-0bbb2222cccc3333b" in text
    assert "is attached to nothing" in text
    assert "What to do:" in text


def test_what_was_checked_is_a_table_of_every_check():
    text = render(result([outcome([finding()]), outcome([], examined=12, check=None)]))
    assert "What was checked" in text
    assert "Unattached EBS volumes" in text
    assert "Looked at" in text


def test_the_report_admits_to_what_it_could_not_read():
    skipped = outcome(
        status="skipped",
        reason="the role can't call ec2:DescribeImages",
        missing_action="ec2:DescribeImages",
    )
    text = render(result([skipped], notes=("ap-south-1 couldn't be read.",)))
    assert "What this scan couldn't see" in text
    assert "ec2:DescribeImages" in text
    assert "ap-south-1" in text
    assert "preflight scan --modules cost --save" in text


def test_the_arithmetic_is_always_shown():
    text = render(result([outcome([finding()])]))
    assert "How these numbers were worked out" in text
    assert "list price" in text
    assert "Savings Plans" in text


def test_a_clean_report_says_so_rather_than_showing_an_empty_list():
    text = render(result([outcome([], examined=40)]))
    assert "Nothing worth flagging" in text
    assert "Start here" not in text
    assert "Everything we found" not in text


def test_the_demo_banner_is_unmissable():
    assert "Sample data" in render(result([outcome([finding()])], demo=True))


def test_a_redacted_report_says_it_is_redacted():
    assert "Redacted" in render(result([outcome([finding()])]).redact())


@pytest.mark.parametrize(
    "report",
    [
        result([outcome([finding()])]),
        result([outcome([], examined=40)]),
        result([outcome(status="skipped", reason="no", missing_action="ec2:DescribeVolumes")]),
        result([outcome([finding()])], demo=True),
    ],
    ids=["findings", "clean", "skipped", "demo"],
)
def test_the_whole_report_is_ascii(report):
    text = render(report)
    offenders = sorted({character for character in text if ord(character) > 127})
    assert not offenders, f"non-ASCII in the report: {offenders}"
