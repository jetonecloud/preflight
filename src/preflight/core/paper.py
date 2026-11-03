"""The report, laid out on paper.

The terminal report is for the person who ran the scan. This one is for the
person they send it to: the same `ScanResult`, the same sections in the same
order, the same arithmetic under every number - but paginated, so it can go
in an email to a founder or an attachment on a ticket.

It is the third thing that comes off a `ScanResult`, after the terminal and
the JSON, and like them it fetches nothing: the fonts are the ones every PDF
reader already has, the only image ships in the wheel, and no link in it
points anywhere but at a page of itself.

Colour does the same job here that it does in the terminal - severity, the
headline figure, a heading you can find while scrolling - and never on its
own: every coloured thing has its word written next to it, so the report
means the same in greyscale, and nothing is set in capitals to make a point
that type can make on its own.

Where the two reports differ, they differ because paper is not a terminal:
there are no arrow keys, so nothing is hidden behind a keypress and every
finding is printed; and there is a contents page, because a reader who got
this as an attachment did not watch the scan run.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any, NamedTuple

from preflight.core import brand, pdf
from preflight.core.pdf import BOLD, ITALIC, MONO, REGULAR, Cell, Column, Document

if TYPE_CHECKING:  # pragma: no cover - typing only
    from preflight.core.report import ScanResult

#: The gap above a section heading.
_SECTION_GAP = 18.0

#: Severity to ink, the same ordering the terminal paints in its own palette.
_SEVERITY_INK = {"high": pdf.HIGH, "medium": pdf.MEDIUM, "low": pdf.LOW}


def _ink(level: Any) -> Any:
    """The colour for a severity, defaulting to ink for one we don't know."""
    return _SEVERITY_INK.get(level.label, pdf.BLACK)


class Written(NamedTuple):
    """Where the PDF went, and how long it came out."""

    path: Path
    pages: int


def lay_out(result: ScanResult) -> Document:
    """The report, laid out on pages, ready to render."""
    doc = Document(
        title=f"Preflight report - account {result.account.id}",
        created=result.finished_at,
    )
    doc.footer(_footer_note(result))

    _cover(doc, result)
    _start_here(doc, result)
    _index(doc, result)
    _detail(doc, result)
    _checked(doc, result)
    _gaps(doc, result)
    _method(doc, result)
    return doc


def build(result: ScanResult) -> bytes:
    """The whole report as PDF bytes."""
    return lay_out(result).render()


def write(result: ScanResult, directory: Any) -> Written:
    """Write the PDF into `directory`, returning where it went and how long it is."""
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{result.filename_stem()}.pdf"
    doc = lay_out(result)
    path.write_bytes(doc.render())
    return Written(path, doc.pages)


def _footer_note(result: ScanResult) -> str:
    """The line along the bottom of every page: whose account, and when."""
    when = result.finished_at.strftime("%d %B %Y")
    where = "Sample data" if result.demo else f"Account {result.account.id}"
    return f"Preflight {result.version}  -  {where}  -  {when}  -  Powered by {brand.NAME}"


# --- the cover ------------------------------------------------------------


def _cover(doc: Document, result: ScanResult) -> None:
    """What this is, what it found, and what's in it.

    Laid out like the front of a printed report: a rule under the masthead,
    the title, then the particulars as a list of labelled lines. One panel,
    for the one figure, and nothing else that needs explaining.
    """
    from preflight.core.report import money, percent, plural

    _masthead(doc)

    doc.space(30.0)
    doc.line("Cost and waste report", font=BOLD, size=20)
    doc.space(10.0)
    doc.rule(width=1.2, colour=pdf.ACCENT)
    doc.space(16.0)

    _particulars(
        doc,
        (
            ("Account", result.account.id),
            (
                "Regions",
                f"{len(result.regions)} ({', '.join(result.regions)})"
                if len(result.regions) <= 6
                else f"{len(result.regions)} regions",
            ),
            ("Usage window", f"{result.lookback_days} days"),
            ("Scan completed", result.finished_at.strftime("%d %B %Y at %H:%M UTC")),
            ("Produced by", f"Preflight {result.version}"),
        ),
    )
    doc.space(20.0)

    if result.demo:
        _callout(
            doc,
            "Sample data.",
            "This report came from a made-up account so you can see the shape of "
            "one. Nothing here was read from AWS.",
        )
    if result.redacted:
        _callout(
            doc,
            "Redacted.",
            "Account and resource identifiers have been replaced with stable "
            "pseudonyms. The same resource keeps the same label throughout, and "
            "the arithmetic is unchanged.",
        )

    # The number gets the one panel in the report, because it is the reason
    # the report exists and the reason somebody forwarded it.
    if result.findings:
        share = ""
        if result.share_of_spend is not None:
            share = f", or {percent(result.share_of_spend)} of last month's bill"
        _headline(
            doc,
            "Estimated saving",
            f"{money(result.monthly_usd)} a month",
            f"{money(result.annual_usd)} a year{share}.",
        )
    else:
        _headline(
            doc,
            "Nothing worth flagging",
            "No findings",
            f"{result.examined} resources checked across "
            f"{len(result.regions)} {plural(len(result.regions), 'region')}.",
        )
    doc.space(18.0)

    counts = result.by_severity
    doc.table(
        [
            Column("Findings", 1.0, align="right", font=BOLD),
            Column("High", 1.0, align="right", colour=pdf.HIGH),
            Column("Medium", 1.0, align="right", colour=pdf.MEDIUM),
            Column("Low", 1.0, align="right", colour=pdf.LOW),
            Column("Checks run", 1.2, align="right"),
            Column("Resources", 1.0, align="right"),
        ],
        [
            [
                str(len(result.findings)),
                str(counts["high"]),
                str(counts["medium"]),
                str(counts["low"]),
                f"{len(result.ran)} of {len(result.outcomes)}",
                str(result.examined),
            ]
        ],
        size=9.5,
    )
    doc.space(20.0)

    doc.line("Contents", font=BOLD, size=11, colour=pdf.ACCENT)
    doc.space(6.0)
    for number, title in enumerate(_contents(result), start=1):
        doc.hanging(
            f"{number}.",
            title,
            size=10,
            gutter=16.0,
            marker_font=BOLD,
            marker_colour=pdf.ACCENT,
        )
    doc.space(16.0)
    doc.line(
        "Every figure in this report shows the arithmetic behind it. How these "
        "numbers were worked out is the last section.",
        font=ITALIC,
        size=9,
        colour=pdf.DIM,
    )


def _headline(doc: Document, label: str, figure: str, note: str) -> None:
    """The figure the report exists to state, in the one panel it gets."""
    height = 74.0
    doc.ensure(height + 8.0)
    top, _bottom = doc.rect(height, fill=pdf.WASH, edge=pdf.ACCENT)
    left = doc.left + 18.0
    doc.at(label, x=left, y=top - 22.0, font=BOLD, size=9, colour=pdf.ACCENT)
    doc.at(figure, x=left, y=top - 47.0, font=BOLD, size=19, colour=pdf.ACCENT)
    doc.at(note, x=left, y=top - 63.0, font=ITALIC, size=9.5, colour=pdf.DIM)


def _masthead(doc: Document) -> None:
    """The mark, the name, and a rule - the top of the first page."""
    top = doc.y
    size = 34.0
    doc.image(brand.mark(), x=doc.left, y=top - size, width=size)
    text_left = doc.left + size + 12.0
    doc.at("Preflight", x=text_left, y=top - 13.0, font=BOLD, size=14, colour=pdf.ACCENT)
    doc.at(
        f"A read-only AWS audit by {brand.NAME}",
        x=text_left,
        y=top - 26.0,
        font=ITALIC,
        size=9.5,
        colour=pdf.DIM,
    )
    doc.space(size + 8.0)
    doc.rule(width=1.2, colour=pdf.ACCENT)


def _particulars(doc: Document, rows: tuple[tuple[str, str], ...]) -> None:
    """Labelled lines, the way the front of a report states its particulars."""
    label_width = max(pdf.text_width(f"{label}  ", REGULAR, 10) for label, _ in rows)
    for label, value in rows:
        top = doc.y
        doc.at(f"{label}", x=doc.left, y=top - 12.0, size=10, colour=pdf.DIM)
        doc.at(value, x=doc.left + label_width, y=top - 12.0, font=BOLD, size=10)
        doc.space(15.0)


def _contents(result: ScanResult) -> list[str]:
    """The sections this report will actually have, in order."""
    titles: list[str] = []
    if result.headline:
        titles.append(f"Start here - the {len(result.headline)} worth doing first")
    if result.findings:
        titles.append("Everything we found - an index of every finding")
        titles.append("The findings in full, grouped by the check that found them")
    titles.append("What was checked")
    if result.skipped or result.failed or result.notes:
        titles.append("What this scan couldn't see")
    titles.append("How these numbers were worked out")
    return titles


def _callout(doc: Document, label: str, body: str) -> None:
    """A note the reader has to see before they read the number."""
    doc.line(label, font=BOLD, size=10, colour=pdf.MEDIUM)
    doc.line(body, font=ITALIC, size=9, colour=pdf.DIM)
    doc.space(14.0)


# --- sections -------------------------------------------------------------


def _heading(doc: Document, title: str, note: str | None = None) -> None:
    """A section heading: a rule over it, the title, and the note in italic."""
    doc.space(_SECTION_GAP)
    doc.ensure(80.0)
    doc.rule(width=1.2, colour=pdf.ACCENT)
    doc.space(6.0)
    doc.line(title, font=BOLD, size=13, colour=pdf.ACCENT)
    if note:
        doc.space(1.0)
        doc.line(note, font=ITALIC, size=9, colour=pdf.DIM)
    doc.space(10.0)


def _start_here(doc: Document, result: ScanResult) -> None:
    from preflight.core.report import money

    if not result.headline:
        return
    doc.page_break()
    _heading(
        doc,
        "Start here",
        f"The {len(result.headline)} worth doing first, by what they save.",
    )
    for index, finding in enumerate(result.headline, start=1):
        doc.ensure(56.0)
        doc.hanging(
            f"{index}.",
            f"{finding.title}",
            font=BOLD,
            size=11,
            gutter=18.0,
            marker_colour=pdf.ACCENT,
        )
        doc.hanging(
            f"{money(finding.monthly_usd)}/month",
            f"{finding.resource.label} - {finding.resource.region}",
            font=ITALIC,
            size=9.5,
            colour=pdf.DIM,
            marker_font=BOLD,
            marker_colour=_ink(finding.level),
            indent=18.0,
            gutter=pdf.text_width(f"{money(finding.monthly_usd)}/month   ", BOLD, 9.5),
        )
        doc.line(finding.recommendation, size=10, indent=18.0)
        doc.space(10.0)


def _index(doc: Document, result: ScanResult) -> None:
    """Every finding in one table, numbered the way the detail numbers them."""
    from preflight.core.report import money

    numbered = _numbered(result)
    if not numbered:
        return
    doc.page_break()
    _heading(
        doc,
        "Everything we found",
        f"{len(result.findings)} findings, worst first. The numbers match the "
        "sections that follow.",
    )
    doc.table(
        [
            Column("#", 0.4, align="right"),
            Column("Check", 1.9),
            Column("Resource", 2.6, font=BOLD),
            Column("Region", 1.0),
            Column("Severity", 0.9, font=BOLD),
            Column("$/month", 0.9, align="right", font=BOLD),
        ],
        [
            [
                str(number),
                finding.check,
                finding.resource.label,
                finding.resource.region,
                Cell(finding.level.label, _ink(finding.level)),
                money(finding.monthly_usd),
            ]
            for number, finding in numbered
        ],
    )


def _numbered(result: ScanResult) -> list[tuple[int, Any]]:
    """Findings numbered once, in reading order, so index and detail agree."""
    rows: list[tuple[int, Any]] = []
    number = 0
    for group in result.groups():
        for finding in group["findings"]:
            number += 1
            rows.append((number, finding))
    return rows


def _detail(doc: Document, result: ScanResult) -> None:
    """Each check's findings in full, grouped the way the terminal groups them."""
    from preflight.core.report import money, plural

    groups = result.groups()
    if not groups:
        return
    doc.page_break()
    _heading(
        doc,
        "The findings in full",
        "Grouped by the check that found them, with the evidence and the arithmetic for each.",
    )
    number = 0
    for group in groups:
        count = len(group["findings"])
        doc.space(10.0)
        doc.ensure(90.0)
        doc.line(group["check"].title, font=BOLD, size=11.5, colour=pdf.ACCENT)
        doc.line(
            f"{count} {plural(count, 'finding')} - {money(group['monthly_usd'])}/month - "
            f"looked at {group['outcome'].examined}",
            size=8.5,
            colour=pdf.DIM,
        )
        doc.line(group["check"].looks_for, size=8.5, colour=pdf.DIM)
        doc.space(8.0)
        for finding in group["findings"]:
            number += 1
            _finding(doc, number, finding)


def _finding(doc: Document, number: int, finding: Any) -> None:
    """One finding: what it is, what it costs, the evidence, and what to do."""
    from preflight.core.report import money

    doc.ensure(72.0)
    resource = finding.resource
    indent = 26.0
    doc.hanging(
        f"{number}.",
        f"{finding.title}  -  {money(finding.monthly_usd)}/month",
        font=BOLD,
        size=10.5,
        gutter=indent,
        marker_colour=_ink(finding.level),
    )
    meta = [
        f"{finding.confidence.label} confidence",
        resource.id,
        resource.region,
    ]
    if resource.name:
        meta.append(f'"{resource.name}"')
    if resource.owner:
        meta.append(f"owner: {resource.owner}")
    severity = f"{finding.level.label} severity"
    doc.hanging(
        severity,
        " - ".join(meta),
        font=ITALIC,
        size=8.5,
        colour=pdf.DIM,
        marker_font=BOLD,
        marker_colour=_ink(finding.level),
        indent=indent,
        gutter=pdf.text_width(f"{severity}  -  ", BOLD, 8.5),
    )
    doc.space(3.0)
    for line in finding.evidence:
        doc.hanging(
            "-",
            line,
            size=9.5,
            indent=indent,
            colour=pdf.BLACK,
            marker_colour=pdf.ACCENT,
            marker_font=BOLD,
            gutter=10.0,
        )
    doc.hanging(
        "What to do:",
        finding.recommendation,
        size=9.5,
        indent=indent,
        gutter=pdf.text_width("What to do:  ", BOLD, 9.5),
        marker_font=BOLD,
        marker_colour=pdf.ACCENT,
    )
    if finding.estimate:
        doc.line(
            f"How the number was worked out: {finding.estimate.basis}",
            font=ITALIC,
            size=8.5,
            colour=pdf.DIM,
            indent=indent,
        )
    doc.space(13.0)


def _checked(doc: Document, result: ScanResult) -> None:
    """Every check that ran, found nothing, or couldn't run."""
    from preflight.core.report import UNKNOWN

    if not result.outcomes:
        return
    _heading(
        doc,
        "What was checked",
        "Including the checks that found nothing, which is the good news.",
    )
    doc.table(
        [
            Column("Check", 1.8, font=BOLD),
            Column("What it looks for", 3.4),
            Column("Looked at", 0.8, align="right"),
            Column("Found", 0.7, align="right"),
            Column("Status", 1.0, font=BOLD),
        ],
        [
            [
                outcome.check.title,
                outcome.check.looks_for,
                str(outcome.examined) if outcome.status != "skipped" else UNKNOWN,
                str(len(outcome.findings)) if outcome.ran else UNKNOWN,
                Cell(_status(outcome), _status_ink(outcome)),
            ]
            for outcome in result.outcomes
        ],
    )


def _status(outcome: Any) -> str:
    if outcome.clean:
        return "clear"
    if outcome.ran:
        return f"{len(outcome.findings)} to look at"
    return "skipped" if outcome.status == "skipped" else "failed"


def _status_ink(outcome: Any) -> Any:
    """Clear is good news, a check that couldn't run is not, and the rest is ink."""
    if outcome.clean:
        return pdf.GOOD
    if outcome.ran:
        return pdf.BLACK
    return pdf.MEDIUM if outcome.status == "skipped" else pdf.HIGH


def _gaps(doc: Document, result: ScanResult) -> None:
    """What the scan couldn't see, said out loud rather than left in a log."""
    if not (result.skipped or result.failed or result.notes):
        return
    _heading(
        doc,
        "What this scan couldn't see",
        "So you can judge how complete the rest of it is.",
    )
    for outcome in result.skipped:
        doc.hanging(
            "Skipped",
            f"{outcome.check.title}: {outcome.reason}",
            size=9.5,
            gutter=52.0,
            marker_font=BOLD,
            marker_colour=pdf.MEDIUM,
        )
    for outcome in result.failed:
        doc.hanging(
            "Failed",
            f"{outcome.check.title}: {outcome.reason}",
            size=9.5,
            gutter=52.0,
            marker_font=BOLD,
            marker_colour=pdf.HIGH,
        )
    for note in result.notes:
        doc.hanging(
            "Note",
            note,
            size=9.5,
            gutter=52.0,
            marker_font=BOLD,
            marker_colour=pdf.ACCENT,
        )
    if result.missing_actions:
        doc.space(10.0)
        doc.line(f"Missing: {', '.join(result.missing_actions)}", size=9.5)
        doc.line("Regenerate a role with everything the checks need:", size=9.5)
        doc.space(2.0)
        doc.line("preflight scan --modules cost --save", font=MONO, size=9, indent=12.0)


def _method(doc: Document, result: ScanResult) -> None:
    """The arithmetic, stated rather than implied.

    The same notes the terminal prints, for the same reason: a number you
    can't check is a number you shouldn't trust, and the person reading the
    PDF is further from the scan than the person who ran it.
    """
    _heading(
        doc,
        "How these numbers were worked out",
        "Every figure in this report, and what it does and doesn't account for.",
    )
    notes = (
        "Every figure is a list price for us-east-1, the cheapest region for "
        f"everything priced here, reviewed {result.prices_reviewed}. In any other "
        "region the real saving is the same or larger.",
        "Nothing accounts for Savings Plans, Reserved Instances, credits or "
        "private pricing. If you have those, treat the figures as an upper bound "
        "on list and a lower bound on effort.",
        "Snapshots are billed incrementally, so they're costed at a third of "
        "their volume's size rather than all of it.",
        f"Usage-based checks look back {result.lookback_days} days and ignore "
        "anything that hasn't existed for that long. CPU is a proxy for "
        '"busy", not a measurement of it - check memory and disk before '
        "resizing anything.",
        "Resources tagged preflight:ignore are skipped everywhere, so you can "
        "silence a finding you've already decided about.",
        "Preflight only ever made Get, List and Describe calls to produce this. "
        "It cannot change anything in the account, by construction.",
    )
    for number, note in enumerate(notes, start=1):
        doc.hanging(
            f"{number}.",
            note,
            size=9.5,
            gutter=18.0,
            marker_font=BOLD,
            marker_colour=pdf.ACCENT,
        )
        doc.space(4.0)

    if result.command:
        doc.space(12.0)
        doc.line("Reproduce this scan:", font=ITALIC, size=9, colour=pdf.DIM)
        doc.space(2.0)
        doc.line(result.command, font=MONO, size=8.5, indent=12.0)

    _colophon(doc)


def _colophon(doc: Document) -> None:
    """Who made the thing you're reading, at the end where a colophon goes."""
    doc.space(24.0)
    # Enough for all of it - the mark, both paragraphs and the last line -
    # because a colophon with one line stranded on a page of its own is
    # worse than a page break one line earlier.
    doc.ensure(190.0)
    doc.rule(width=1.2, colour=pdf.ACCENT)
    doc.space(12.0)

    size = 26.0
    top = doc.y
    doc.image(brand.mark(), x=doc.left, y=top - size, width=size)
    text_left = doc.left + size + 12.0
    doc.at(
        f"Powered by {brand.NAME}",
        x=text_left,
        y=top - 10.0,
        font=BOLD,
        size=10.5,
        colour=pdf.ACCENT,
    )
    doc.at(
        brand.TAGLINE,
        x=text_left,
        y=top - 22.0,
        font=ITALIC,
        size=9.5,
        colour=pdf.DIM,
    )
    doc.space(size + 10.0)

    doc.line(brand.WHO, size=9.5, colour=pdf.DIM)
    doc.space(6.0)
    doc.line(brand.WHAT, size=9.5, colour=pdf.DIM)
    doc.space(8.0)
    doc.line(f"{brand.SITE}  -  Want a hand fixing these? {brand.BOOK}", size=9.5)
