"""The PDF writer, on the things a reader's software will hold us to.

We write the bytes ourselves, so the structure is the contract: a reader
finds objects through the cross-reference table, and an offset that's wrong
by one byte is a file that won't open. None of that is visible by looking at
a rendered page, so it's asserted here.

Text is checked by reading it back out of the content streams, which is
possible because they're left uncompressed on purpose.
"""

from __future__ import annotations

import re

import pytest

from preflight.core import pdf
from preflight.core.pdf import BOLD, ITALIC, MONO, REGULAR, Cell, Column, Document


def document(**kwargs) -> Document:
    return Document(title="Test report", **kwargs)


def strings(data: bytes) -> list[str]:
    """Every literal string drawn into the document, in order."""
    return [
        match.decode("latin-1") for match in re.findall(rb"\((.*?)\) Tj", data, flags=re.DOTALL)
    ]


def text_of(data: bytes) -> str:
    return "\n".join(strings(data))


# --- the file a reader has to open ----------------------------------------


def test_it_is_a_pdf_a_reader_can_find_its_way_around():
    data = document().render()
    assert data.startswith(b"%PDF-1.4")
    assert data.rstrip().endswith(b"%%EOF")
    assert b"/Type /Catalog" in data
    assert b"/Type /Pages" in data


def test_every_cross_reference_offset_points_at_its_object():
    """The table is how a reader finds anything, so each entry is checked."""
    doc = document()
    for index in range(80):  # enough text to run to a second page
        doc.line(f"line {index}")
    data = doc.render()

    start = int(re.search(rb"startxref\s+(\d+)", data).group(1))
    assert data[start : start + 4] == b"xref"
    entries = re.findall(rb"^(\d{10}) (\d{5}) ([nf]) $", data[start:], flags=re.M)
    assert entries, "no cross-reference entries"
    assert entries[0][2] == b"f"  # object 0 is always the free head
    for number, (offset, _generation, kind) in enumerate(entries[1:], start=1):
        assert kind == b"n"
        at = int(offset)
        assert data[at:].startswith(b"%d 0 obj" % number), f"object {number} is not at {at}"


def test_the_object_count_in_the_trailer_matches_what_was_written():
    data = document().render()
    size = int(re.search(rb"/Size (\d+)", data).group(1))
    assert len(re.findall(rb"^\d+ 0 obj$", data, flags=re.M)) == size - 1


def test_pages_are_counted_and_linked():
    doc = document()
    doc.page_break()
    doc.page_break()
    data = doc.render()
    assert doc.pages == 3
    assert b"/Count 3" in data
    assert len(re.findall(rb"/Type /Page\b", data)) == 3


def test_the_creation_date_comes_from_the_scan_so_the_file_is_reproducible():
    from datetime import UTC, datetime

    when = datetime(2026, 6, 15, 12, 30, 5, tzinfo=UTC)
    first = document(created=when).render()
    second = document(created=when).render()
    assert b"/CreationDate (D:20260615123005Z)" in first
    assert first == second


# --- text -----------------------------------------------------------------


def test_text_reaches_the_page():
    doc = document()
    doc.line("Unattached EBS volumes")
    assert "Unattached EBS volumes" in text_of(doc.render())


def test_the_three_characters_that_would_break_a_literal_are_escaped():
    doc = document()
    doc.line(r"a (b) c \ d")
    data = doc.render()
    assert rb"(a \(b\) c \\ d) Tj" in data


def test_a_character_no_base_font_has_becomes_a_substitute_rather_than_breaking():
    doc = document()
    doc.line("em — dash and 中")
    data = doc.render()
    assert b"Tj" in data
    data.decode("latin-1")  # the whole file stays encodable


def test_every_font_asked_for_is_declared_in_the_resources():
    doc = document()
    doc.line("regular", font=REGULAR)
    doc.line("bold", font=BOLD)
    doc.line("italic", font=ITALIC)
    doc.line("mono", font=MONO)
    data = doc.render()
    for name in (b"/Helvetica", b"/Helvetica-Bold", b"/Helvetica-Oblique", b"/Courier"):
        assert name in data
    assert data.count(b"/WinAnsiEncoding") == 4


# --- measuring and wrapping -----------------------------------------------


def test_width_is_measured_in_the_font_the_text_is_drawn_in():
    """Bold is wider than regular, and Courier is the same for every letter."""
    assert pdf.text_width("nnnn", BOLD, 10) > pdf.text_width("nnnn", REGULAR, 10)
    assert pdf.text_width("iiii", MONO, 10) == pytest.approx(pdf.text_width("WWWW", MONO, 10))


def test_wrapping_never_exceeds_the_width_it_was_given():
    body = (
        "Running instances whose peak CPU never approaches what they're paying "
        "for, over a fourteen day window."
    )
    for line in pdf.wrap(body, REGULAR, 9.0, 120.0):
        assert pdf.text_width(line, REGULAR, 9.0) <= 120.0


def test_a_word_with_nowhere_to_break_is_broken_rather_than_run_off_the_page():
    arn = "arn:aws:ec2:us-east-1:123456789012:volume/vol-0aaa1111bbbb2222a"
    lines = pdf.wrap(arn, REGULAR, 9.0, 60.0)
    assert len(lines) > 1
    assert "".join(lines) == arn
    for line in lines:
        assert pdf.text_width(line, REGULAR, 9.0) <= 60.0


def test_wrapping_keeps_every_word():
    body = "one two three four five six seven eight nine ten"
    assert " ".join(pdf.wrap(body, REGULAR, 9.0, 40.0)).split() == body.split()


# --- the page turning itself ----------------------------------------------


def test_text_past_the_bottom_starts_a_new_page():
    doc = document()
    for index in range(200):
        doc.line(f"line {index}")
    assert doc.pages > 1
    assert "line 199" in text_of(doc.render())


def test_space_never_pushes_the_cursor_off_the_page():
    doc = document()
    doc.space(10_000.0)
    assert doc.pages == 1
    assert doc.y >= doc.margin


def test_the_footer_is_on_every_page_with_its_number():
    doc = document()
    doc.footer("Account 123456789012")
    doc.page_break()
    drawn = strings(doc.render())
    assert drawn.count("Account 123456789012") == 2
    assert "1 of 2" in drawn
    assert "2 of 2" in drawn


def test_rendering_twice_does_not_draw_the_footer_twice():
    doc = document()
    doc.footer("once")
    doc.render()
    assert strings(doc.render()).count("once") == 1


# --- tables ---------------------------------------------------------------

COLUMNS = (
    Column("Check", 2.0),
    Column("Resource", 2.0, font=BOLD),
    Column("$/month", 1.0, align="right"),
)


def test_a_table_draws_its_header_and_every_cell():
    doc = document()
    doc.table(COLUMNS, [["unattached-ebs-volumes", "vol-0aaa1111", "$40"]])
    drawn = text_of(doc.render())
    headers = ("Check", "Resource", "$/month")
    cells = ("unattached-ebs-volumes", "vol-0aaa1111", "$40")
    for expected in headers + cells:
        assert expected in drawn


def test_a_cell_can_be_coloured_where_its_column_cannot_be():
    """Severity is one column, but each word in it wants its own ink."""
    doc = document()
    doc.table(
        COLUMNS,
        [
            ["unattached-ebs-volumes", Cell("high", pdf.HIGH), "$40"],
            ["idle-nat-gateways", Cell("low", pdf.LOW), "$2"],
        ],
    )
    data = doc.render().decode("latin-1")
    assert f"BT {pdf.HIGH} rg" in data
    assert f"BT {pdf.LOW} rg" in data
    # The column's own colour still draws the cells that didn't ask.
    assert "(unattached-ebs-volumes) Tj" in data


def test_a_long_table_repeats_its_header_on_the_next_page():
    doc = document()
    doc.table(COLUMNS, [[f"check-{index}", f"vol-{index}", "$1"] for index in range(120)])
    data = doc.render()
    assert doc.pages > 1
    # One header per page, so a reader who turns the page still has the columns.
    assert strings(data).count("$/month") == doc.pages
    assert "check-119" in text_of(data)


# --- images ---------------------------------------------------------------


def test_a_png_is_taken_apart_into_what_a_pdf_needs():
    from preflight.core import brand

    mark = brand.mark()
    assert (mark.width, mark.height) == (200, 200)
    assert mark.colours == 3
    assert mark.depth == 8
    assert mark.colour_space == "/DeviceRGB"


def test_the_pixel_data_is_copied_in_rather_than_decoded():
    """PNG filtering is PDF predictor 15, which is the whole trick."""
    from preflight.core import brand

    mark = brand.mark()
    doc = document()
    doc.image(mark, x=0, y=0, width=40)
    data = doc.render()
    assert b"/Subtype /Image" in data
    assert b"/Predictor 15" in data
    assert b"/Width 200 /Height 200" in data
    assert mark.data in data


def test_an_image_drawn_on_every_page_is_stored_once():
    from preflight.core import brand

    doc = document()
    doc.image(brand.mark(), x=0, y=0, width=40)
    doc.page_break()
    doc.image(brand.mark(), x=0, y=0, width=40)
    data = doc.render()
    assert data.count(b"/Subtype /Image") == 1
    assert data.count(b"/Imlogo Do") == 2
    # Both pages have to name it in their resources to be allowed to draw it.
    assert data.count(b"/XObject <<") == 2


def test_a_page_that_draws_nothing_declares_no_images():
    from preflight.core import brand

    doc = document()
    doc.image(brand.mark(), x=0, y=0, width=40)
    doc.page_break()
    doc.line("no mark on this page")
    assert doc.render().count(b"/XObject <<") == 1


def test_a_png_we_cannot_pass_through_says_so_rather_than_writing_nonsense():
    with pytest.raises(ValueError, match="not a PNG"):
        pdf.read_png(b"certainly not a png")

    palette = _png_header(colour_type=3)
    with pytest.raises(ValueError, match="truecolour"):
        pdf.read_png(palette)

    interlaced = _png_header(colour_type=2, interlace=1)
    with pytest.raises(ValueError, match="interlaced"):
        pdf.read_png(interlaced)

    deep = _png_header(colour_type=2, depth=16)
    with pytest.raises(ValueError, match="8-bit"):
        pdf.read_png(deep)


def _png_header(*, colour_type: int, depth: int = 8, interlace: int = 0) -> bytes:
    """A PNG with a believable IHDR and nothing else."""
    import struct
    import zlib

    body = struct.pack(">IIBBBBB", 4, 4, depth, colour_type, 0, 0, interlace)
    chunk = struct.pack(">I", len(body)) + b"IHDR" + body
    chunk += struct.pack(">I", zlib.crc32(b"IHDR" + body))
    return pdf.PNG_SIGNATURE + chunk
