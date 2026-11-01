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
from preflight.modules.cost import COST


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


# --- sections and the pager ----------------------------------------------


def paged_report():
    """A report with enough in it to be worth paging through."""
    return result(
        [
            outcome([finding(), finding(resource_id="vol-0bbb2222cccc3333b")]),
            outcome([], examined=12, check=COST.checks[1]),
            outcome(status="skipped", reason="no", missing_action="ec2:DescribeVolumes"),
        ]
    )


def titles(report) -> list[str]:
    return [page.title for page in ui.report_pages(report)]


@pytest.fixture
def keypresses(monkeypatch):
    """Feed the pager a canned sequence, and hand back what's left of it."""

    def feed(*presses):
        remaining = list(presses)
        monkeypatch.setattr(ui.keys, "read_key", lambda: remaining.pop(0))
        return remaining

    return feed


def page_through(report) -> str:
    with ui.console.capture() as captured:
        ui._run_pager(ui.report_pages(report))
    return captured.get()


def test_the_report_is_cut_into_sections_a_reader_would_recognise():
    assert titles(paged_report()) == [
        "Cost Check",
        "Start here",
        "Everything we found",
        "Unattached EBS volumes",
        "What was checked",
        "What this scan couldn't see",
        "How these numbers were worked out",
    ]


def test_sections_nothing_went_into_are_left_out():
    sections = titles(result([outcome([], examined=40)]))
    assert "Start here" not in sections
    assert "Everything we found" not in sections
    assert "What this scan couldn't see" not in sections
    assert sections[0] == "Cost Check"


def many_findings(count=5):
    return result(
        [outcome([finding(resource_id=f"vol-0aaa1111bbbb2222{n}") for n in range(count)])]
    )


@pytest.mark.parametrize("room", [8, 14, 30])
def test_every_page_fits_the_window_it_was_cut_for(room):
    """A page is measured, not guessed, so nothing scrolls off the top."""
    for page in ui.report_pages(many_findings(12), room=room):
        height = ui._height(page.render)
        # One finding or one table row can exceed the room on its own; what
        # must not happen is two of them being put on a page together.
        assert height <= room or page.note is None or page.note.endswith("of 12")


def test_both_the_long_sections_are_split():
    sections = [page.title for page in ui.report_pages(many_findings(12), room=10)]
    assert sections.count("Unattached EBS volumes") > 1
    assert sections.count("Everything we found") > 1


def test_a_split_section_says_which_page_of_it_you_are_on():
    notes = {page.note for page in ui.report_pages(many_findings(12), room=14)}
    assert any(note and note.startswith("page 1 of ") for note in notes)
    assert None in notes, "a section that fits should not be numbered"


def test_no_window_means_no_splitting():
    """Down a pipe there is no window to fit, so a section is one section."""
    sections = [page.title for page in ui.report_pages(many_findings(20))]
    assert sections.count("Unattached EBS volumes") == 1
    assert sections.count("Everything we found") == 1


def test_a_finding_too_tall_to_fit_still_gets_a_page_of_its_own():
    pages = ui.report_pages(many_findings(3), room=4)
    assert [page.note for page in pages if page.title == "Unattached EBS volumes"] == [
        "page 1 of 3",
        "page 2 of 3",
        "page 3 of 3",
    ]


def test_enter_walks_forward_and_the_last_section_leaves(keypresses):
    pages = ui.report_pages(paged_report())
    left = keypresses(*[ui.keys.ENTER] * len(pages))
    with ui.console.capture() as captured:
        ui._run_pager(pages)
    assert left == [], "the pager should read exactly one key per section"
    assert "How these numbers were worked out" in captured.get()


def test_the_arrows_go_both_ways(keypresses):
    keypresses(ui.keys.RIGHT, ui.keys.LEFT, "q")
    text = page_through(paged_report())
    assert text.count("section 1 of 7") == 2, "Left should have come back to the first section"
    assert "section 2 of 7" in text


def test_up_and_down_drive_it_too(keypresses):
    keypresses(ui.keys.DOWN, ui.keys.UP, "q")
    assert page_through(paged_report()).count("section 1 of 7") == 2


def test_back_from_the_first_section_stays_put(keypresses):
    keypresses(ui.keys.LEFT, "q")
    assert page_through(paged_report()).count("section 1 of 7") == 2


def test_q_leaves_without_reading_the_rest(keypresses):
    keypresses("q")
    assert "Everything we found" not in page_through(paged_report())


def test_a_prints_the_whole_thing_at_once(keypresses):
    keypresses("a")
    text = page_through(paged_report())
    for section in ("Estimated saving", "Everything we found", "What was checked"):
        assert section in text


def test_an_abandoned_pager_is_not_an_error(monkeypatch):
    def walk_out() -> str:
        raise KeyboardInterrupt

    monkeypatch.setattr(ui.keys, "read_key", walk_out)
    ui._run_pager(ui.report_pages(paged_report()))


def test_without_a_terminal_every_section_is_printed(monkeypatch):
    monkeypatch.setattr(ui.keys, "supported", lambda: True)
    monkeypatch.setattr(type(ui.console), "is_terminal", property(lambda self: False))
    with ui.console.capture() as captured:
        ui.show_report(paged_report(), json_path="./out.json")
    text = captured.get()
    assert "The report follows." in text
    assert "How these numbers were worked out" in text


# --- pacing ---------------------------------------------------------------


def slept(monkeypatch) -> list[float]:
    waits: list[float] = []
    monkeypatch.setattr(ui.time, "sleep", waits.append)
    return waits


def test_a_pause_waits_when_somebody_is_watching(monkeypatch):
    monkeypatch.setattr(type(ui.console), "is_terminal", property(lambda self: True))
    waits = slept(monkeypatch)
    ui.pause(0.4)
    assert waits == [0.4]


def test_a_pause_is_nothing_at_all_without_a_terminal(monkeypatch):
    monkeypatch.setattr(type(ui.console), "is_terminal", property(lambda self: False))
    waits = slept(monkeypatch)
    ui.pause(0.4)
    assert waits == []


# --- the intro ------------------------------------------------------------


def test_the_intro_says_what_we_found_and_where_the_json_went():
    with ui.console.capture() as captured:
        ui.print_intro(paged_report(), json_path="./out.json", paged=False, sections=7)
    text = captured.get()
    assert "Done." in text
    assert "2 findings" in text
    assert "./out.json" in text
    assert "The report follows." in text


def test_the_intro_explains_the_keys_when_it_is_going_to_page():
    with ui.console.capture() as captured:
        ui.print_intro(paged_report(), json_path=None, paged=True, sections=7)
    text = captured.get()
    assert "7 sections" in text
    assert "q to quit" in text
    assert "Arrows to move" in text
    assert "Press Enter to start" in text


def test_a_clean_intro_leads_with_the_good_news():
    with ui.console.capture() as captured:
        ui.print_intro(result([outcome([], examined=40)]), json_path=None, paged=False, sections=3)
    assert "Nothing worth flagging, from 40 resources" in captured.get()


def test_quitting_at_the_intro_skips_the_report(monkeypatch):
    monkeypatch.setattr(ui.keys, "supported", lambda: True)
    monkeypatch.setattr(type(ui.console), "is_terminal", property(lambda self: True))
    monkeypatch.setattr(ui.keys, "read_key", lambda: "q")
    with ui.console.capture() as captured:
        ui.show_report(paged_report(), json_path="./out.json")
    text = captured.get()
    assert "./out.json" in text
    assert "Everything we found" not in text
