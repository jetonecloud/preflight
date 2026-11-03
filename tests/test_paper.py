"""The report, as it appears on paper.

The PDF goes to someone who didn't watch the scan run, so it has to carry
everything they'd need to judge it on its own: the number, what to do first,
every finding with its evidence and arithmetic, and what the scan couldn't
see. Those promises are the same ones the terminal report makes, and they're
asserted the same way - by reading the output back.
"""

from __future__ import annotations

from test_pdf import strings, text_of
from test_report import finding, outcome, result

from preflight.core import paper
from preflight.core.scan import CheckOutcome
from preflight.modules.cost import COST


def render(report) -> str:
    return text_of(paper.build(report))


def test_it_leads_with_the_number_and_the_fix():
    text = render(result([outcome([finding(monthly=123.0)])]))
    assert "Estimated saving" in text
    assert "$123 a month" in text
    assert "Start here" in text
    assert "Delete it." in text


def test_every_finding_is_printed_with_its_evidence_and_arithmetic():
    report = result([outcome([finding(), finding(resource_id="vol-0bbb2222cccc3333b")])])
    text = render(report)
    assert "vol-0aaa1111bbbb2222a" in text
    assert "vol-0bbb2222cccc3333b" in text
    assert "is attached to nothing." in text
    assert "What to do:" in text
    assert "500 GB at $0.08/GB-month" in text


def test_nothing_is_hidden_behind_a_keypress():
    """Paper has no pager, so a long report prints all of it."""
    findings = [finding(resource_id=f"vol-{index:017d}") for index in range(40)]
    text = render(result([outcome(findings)]))
    for index in (0, 17, 39):
        assert f"vol-{index:017d}" in text


def test_the_index_and_the_detail_number_the_findings_the_same_way():
    report = result([outcome([finding(monthly=90.0), finding(resource_id="vol-b", monthly=10.0)])])
    drawn = strings(paper.build(report))
    # The index lists 1 and 2; the detail repeats them as 1. and 2.
    assert "1." in drawn and "2." in drawn
    assert drawn.index("1.") < drawn.index("2.")


def test_what_was_checked_includes_the_checks_that_found_nothing():
    text = render(result([outcome([finding()]), outcome([], examined=12, check=COST.checks[1])]))
    assert "What was checked" in text
    assert "clear" in text


def test_it_admits_to_what_it_could_not_read():
    skipped = CheckOutcome(
        COST.checks[1],
        "skipped",
        (),
        reason="the role can't call ec2:DescribeImages",
        missing_action="ec2:DescribeImages",
    )
    text = render(result([outcome([finding()]), skipped]))
    assert "What this scan couldn't see" in text
    assert "can't call ec2:DescribeImages" in text
    assert "Missing: ec2:DescribeImages" in text


def test_the_method_is_stated_on_every_report():
    text = render(result([outcome([finding()])]))
    assert "How these numbers were worked out" in text
    assert "us-east-1" in text
    assert "Savings Plans" in text
    assert "Get, List and Describe" in text


def test_a_clean_account_says_so_rather_than_printing_an_empty_table():
    text = render(result([outcome([], examined=9)]))
    assert "Nothing worth flagging" in text
    assert "Estimated saving" not in text


def test_the_sample_report_says_it_is_a_sample_on_every_page():
    report = result([outcome([finding()])], demo=True)
    drawn = strings(paper.build(report))
    assert "Sample data." in drawn
    footers = [line for line in drawn if line.startswith("Preflight ") and "Sample data" in line]
    assert len(footers) == paper.lay_out(report).pages


def test_a_redacted_report_carries_no_account_number_anywhere():
    report = result([outcome([finding()])]).redact()
    data = paper.build(report)
    assert b"123456789012" not in data
    assert "Redacted." in text_of(data)


def test_the_footer_names_the_account_and_who_made_the_report():
    report = result([outcome([finding(monthly=40.0)])])
    note = paper._footer_note(report)
    assert "Account 123456789012" in note
    assert "Powered by Jet1" in note


def test_the_contents_only_lists_sections_the_report_actually_has():
    clean = paper._contents(result([outcome([], examined=4)]))
    assert not any("Start here" in title for title in clean)
    assert any("What was checked" in title for title in clean)

    found = paper._contents(result([outcome([finding()])]))
    assert any("Start here" in title for title in found)


def test_writing_it_names_the_file_after_the_account_and_the_scan(tmp_path):
    report = result([outcome([finding()])])
    written = paper.write(report, tmp_path)
    assert written.path.name == f"{report.filename_stem()}.pdf"
    assert written.path.read_bytes().startswith(b"%PDF")
    assert written.pages == paper.lay_out(report).pages


def test_the_same_scan_always_produces_the_same_bytes():
    report = result([outcome([finding()])])
    assert paper.build(report) == paper.build(report)


# --- whose report this is -------------------------------------------------


def test_it_says_who_made_it_and_carries_the_mark():
    """The PDF leaves the machine, so it says where it came from."""
    from preflight.core import brand

    report = result([outcome([finding()])])
    data = paper.build(report)
    text = text_of(data)
    assert "Powered by Jet1" in text
    assert brand.TAGLINE in text
    assert brand.SITE in text
    assert brand.BOOK in text
    # The mark itself, byte for byte, drawn on the cover and the colophon.
    assert brand.mark().data in data
    assert data.count(b"/Imlogo Do") == 2


def test_the_mark_is_embedded_once_however_many_pages_draw_it():
    report = result([outcome([finding()])])
    assert paper.build(report).count(b"/Subtype /Image") == 1


def test_a_reader_is_told_what_preflight_is_without_having_run_it():
    """Asserted in fragments: these sentences are long enough to wrap."""
    text = render(result([outcome([finding()])]))
    assert "managed DevOps team" in text
    assert "read-only AWS audit" in text
