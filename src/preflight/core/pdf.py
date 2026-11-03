"""Writing a PDF, with nothing to install.

The report can leave the terminal as a file you send someone, and the only
honest way to do that in a tool shipped as a single binary is to write the
PDF ourselves. Helvetica and Courier are in every PDF reader by
specification, so a document that asks for them carries no fonts of its own,
and this module carries no dependency: no rendering engine, no system
libraries, no HTML in the middle. Images go in the same way - a plain PNG's
pixel data is already in the one compressed form a PDF understands, so it's
copied in rather than decoded.

Content streams are left uncompressed on purpose. A report about somebody's
account should be a file they can read with `strings` and satisfy themselves
about, which is the same reason the role template is YAML you read before
you deploy it.

This is the writer - pages, text, rules, tables, and the object graph that
holds them. What goes *on* the pages is `core.paper`'s problem.
"""

from __future__ import annotations

import struct
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, NamedTuple

#: The eight bytes every PNG starts with.
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"

#: A4, in points, which is the only unit a PDF has.
PAGE_WIDTH = 595.28
PAGE_HEIGHT = 841.89

#: Enough margin to print on, and to write in.
MARGIN = 56.0

#: The fonts, by the names a reader already has them under. Helvetica
#: rather than Times: most people read this on a screen rather than on
#: paper, and at the sizes a dense report uses, Times' thin strokes and
#: small x-height are exactly what makes it hard going. Courier is the only
#: fixed-pitch face the specification guarantees, so commands get that.
REGULAR = "regular"
BOLD = "bold"
ITALIC = "italic"
MONO = "mono"

_BASE_FONTS = {
    REGULAR: "Helvetica",
    BOLD: "Helvetica-Bold",
    ITALIC: "Helvetica-Oblique",
    MONO: "Courier",
}
_FONT_KEYS = {REGULAR: "F1", BOLD: "F2", ITALIC: "F3", MONO: "F4"}

#: Character widths at size 1000, for ASCII 32-126, in that order. Adobe's
#: metrics for the base fonts; every PDF reader uses the same ones, which is
#: what makes wrapping measured here match wrapping on the page.
_WIDTHS_REGULAR = (
    "278 278 355 556 556 889 667 191 333 333 389 584 278 333 278 278 "
    "556 556 556 556 556 556 556 556 556 556 "
    "278 278 584 584 584 556 1015 "
    "667 667 722 722 667 611 778 722 278 500 667 556 833 722 778 667 778 "
    "722 667 611 722 667 944 667 667 611 "
    "278 278 278 469 556 333 "
    "556 556 500 556 556 278 556 556 222 222 500 222 833 556 556 556 556 "
    "333 500 278 556 500 722 500 500 500 "
    "334 260 334 584"
)
_WIDTHS_BOLD = (
    "278 333 474 556 556 889 722 238 333 333 389 584 278 333 278 278 "
    "556 556 556 556 556 556 556 556 556 556 "
    "333 333 584 584 584 611 975 "
    "722 722 722 722 667 611 778 722 278 556 722 611 833 722 778 667 778 "
    "722 667 611 722 667 944 667 667 611 "
    "333 278 333 584 556 333 "
    "556 611 556 611 556 333 611 611 278 278 556 278 889 611 611 611 611 "
    "389 556 333 611 556 778 556 556 500 "
    "389 280 389 584"
)
#: Helvetica-Oblique is Helvetica, slanted - the same metrics to the unit.
_WIDTHS_ITALIC = _WIDTHS_REGULAR


def _metrics(widths: str) -> tuple[int, ...]:
    table = tuple(int(width) for width in widths.split())
    if len(table) != 95:  # pragma: no cover - a typo in the table above
        raise ValueError(f"expected 95 character widths, got {len(table)}")
    return table


_METRICS = {
    REGULAR: _metrics(_WIDTHS_REGULAR),
    BOLD: _metrics(_WIDTHS_BOLD),
    ITALIC: _metrics(_WIDTHS_ITALIC),
    MONO: (600,) * 95,
}

#: What an unprintable character becomes. The report is ASCII throughout, so
#: this is a backstop for a resource name somebody tagged in another script,
#: not the normal path.
_SUBSTITUTE = "?"


def text_width(body: str, font: str, size: float) -> float:
    """How wide `body` comes out, in points, in the font it'll be drawn in."""
    table = _METRICS[font]
    total = 0
    for char in body:
        index = ord(char) - 32
        total += table[index] if 0 <= index < 95 else table[ord("n") - 32]
    return total * size / 1000.0


def wrap(body: str, font: str, size: float, width: float) -> list[str]:
    """Break `body` into lines no wider than `width`.

    Measured in the font's own metrics rather than counted in characters,
    because a column of resource IDs and a column of prose fit very
    different numbers of them. A single word too long to fit is broken
    rather than allowed to run off the page - an ARN has no spaces in it.
    """
    lines: list[str] = []
    for paragraph in body.split("\n"):
        words = paragraph.split()
        if not words:
            lines.append("")
            continue
        current = ""
        for word in words:
            candidate = f"{current} {word}" if current else word
            if current and text_width(candidate, font, size) > width:
                lines.append(current)
                current = word
            else:
                current = candidate
            while text_width(current, font, size) > width and len(current) > 1:
                cut = _longest_prefix(current, font, size, width)
                lines.append(current[:cut])
                current = current[cut:]
        lines.append(current)
    return lines


def _longest_prefix(body: str, font: str, size: float, width: float) -> int:
    """How much of `body` fits in `width`, at least one character."""
    for cut in range(1, len(body)):
        if text_width(body[: cut + 1], font, size) > width:
            return cut
    return len(body)


@dataclass(frozen=True)
class Colour:
    """A colour, as the three numbers a PDF wants."""

    red: float
    green: float
    blue: float

    def __str__(self) -> str:
        return f"{self.red:.3f} {self.green:.3f} {self.blue:.3f}"


#: Ink, a grey for small print, and the rules. The colour here is deliberately
#: thin on the ground: a teal for headings and rules, three for severity, and
#: a wash for the one figure the report exists to state. Everything else is
#: ink on paper, because a number somebody is going to argue about reads best
#: in black, and all of it has to survive a greyscale printer - which these do,
#: because they differ in lightness and not only in hue.
BLACK = Colour(0.10, 0.11, 0.12)
DIM = Colour(0.42, 0.44, 0.46)
RULE = Colour(0.78, 0.80, 0.82)

#: The accent: headings, rules that mean something, and the mark's company.
ACCENT = Colour(0.06, 0.36, 0.44)
#: The same teal, wrung out, for the one panel that gets a fill.
WASH = Colour(0.93, 0.96, 0.96)

#: Severity, in the three colours everyone already reads as an ordering.
HIGH = Colour(0.70, 0.15, 0.12)
MEDIUM = Colour(0.60, 0.39, 0.03)
LOW = Colour(0.29, 0.33, 0.41)
#: Nothing to report, which is the good news and should look like it.
GOOD = Colour(0.10, 0.45, 0.28)


@dataclass(frozen=True)
class Column:
    """One column of a table: what to call it, how wide, how to align it."""

    title: str
    width: float
    align: str = "left"
    font: str = REGULAR
    colour: Colour = BLACK


class Cell(NamedTuple):
    """One cell that wants its own colour, where its column's won't do.

    A severity column is the whole reason this exists: the word is the same
    kind of thing in every row, but which word it is changes what it should
    look like.
    """

    body: str
    colour: Colour

    def __str__(self) -> str:
        return self.body


def escape(body: str) -> str:
    """A string as a PDF literal, with the three characters that bite escaped."""
    safe = body.encode("latin-1", "replace").decode("latin-1")
    safe = "".join(char if 32 <= ord(char) < 256 else _SUBSTITUTE for char in safe)
    for char, replacement in (("\\", "\\\\"), ("(", "\\("), (")", "\\)")):
        safe = safe.replace(char, replacement)
    return safe


@dataclass(frozen=True)
class Png:
    """A PNG, taken apart far enough to be handed to a PDF reader as-is.

    PNG's per-scanline filtering is exactly PDF's predictor 15, and both
    compress with deflate, so a plain truecolour PNG's pixel data can be
    copied into the file byte for byte - no decoding, no re-encoding, and
    nothing to install to do it. Interlaced and palette images can't be, and
    say so rather than coming out as garbage.
    """

    width: int
    height: int
    colours: int
    depth: int
    data: bytes

    @property
    def colour_space(self) -> str:
        return "/DeviceRGB" if self.colours == 3 else "/DeviceGray"


def read_png(raw: bytes) -> Png:
    """Pull the size and the compressed pixel data out of a PNG."""
    if raw[:8] != PNG_SIGNATURE:
        raise ValueError("not a PNG")
    width = height = depth = 0
    colour_type = interlace = 0
    pixels = bytearray()
    at = 8
    while at + 8 <= len(raw):
        length = struct.unpack(">I", raw[at : at + 4])[0]
        kind = raw[at + 4 : at + 8]
        body = raw[at + 8 : at + 8 + length]
        if kind == b"IHDR":
            width, height, depth, colour_type, _comp, _filter, interlace = struct.unpack(
                ">IIBBBBB", body[:13]
            )
        elif kind == b"IDAT":
            pixels += body
        elif kind == b"IEND":
            break
        at += 12 + length

    if interlace:
        raise ValueError("interlaced PNGs aren't supported")
    if colour_type not in (0, 2):
        raise ValueError("only greyscale and truecolour PNGs are supported")
    if depth != 8:
        raise ValueError("only 8-bit PNGs are supported")
    return Png(width, height, 3 if colour_type == 2 else 1, depth, bytes(pixels))


@dataclass
class _Page:
    """One page's drawing operations, in the order they were asked for."""

    ops: list[str] = field(default_factory=list)
    images: set[str] = field(default_factory=set)


class Document:
    """A PDF being written, a line at a time, top to bottom.

    The cursor runs down the page and the page turns itself: everything that
    draws asks for the room it needs first, so a table or a finding that
    won't fit starts on a fresh page instead of falling off this one.
    """

    def __init__(
        self,
        *,
        title: str,
        author: str = "Preflight",
        created: datetime | None = None,
        margin: float = MARGIN,
    ) -> None:
        self.title = title
        self.author = author
        self.created = created
        self.margin = margin
        self._pages: list[_Page] = []
        self._images: dict[str, Png] = {}
        self._y = 0.0
        self._footer = ""
        self._footed = False
        self._new_page()

    # --- geometry ---------------------------------------------------------

    @property
    def width(self) -> float:
        """Usable width between the margins."""
        return PAGE_WIDTH - 2 * self.margin

    @property
    def left(self) -> float:
        return self.margin

    @property
    def y(self) -> float:
        """How far down the page the cursor is, as a PDF coordinate."""
        return self._y

    @property
    def pages(self) -> int:
        return len(self._pages)

    def footer(self, note: str) -> None:
        """A line drawn along the bottom of every page, with the page number."""
        self._footer = note

    def _new_page(self) -> None:
        self._pages.append(_Page())
        self._y = PAGE_HEIGHT - self.margin

    def _bottom(self) -> float:
        # Room kept for the footer, so nothing is drawn over it.
        return self.margin + 18.0

    def room(self, height: float) -> bool:
        """Whether `height` still fits on this page."""
        return self._y - height >= self._bottom()

    def ensure(self, height: float) -> None:
        """Start a new page unless `height` fits on this one."""
        if not self.room(height):
            self.page_break()

    def page_break(self) -> None:
        self._new_page()

    def space(self, height: float) -> None:
        """Leave a gap, but never one that pushes the cursor off the page."""
        if self.room(height):
            self._y -= height

    # --- drawing ----------------------------------------------------------

    def _op(self, op: str, page: _Page | None = None) -> None:
        (page or self._pages[-1]).ops.append(op)

    def line(
        self,
        body: str,
        *,
        font: str = REGULAR,
        size: float = 9.5,
        colour: Colour = BLACK,
        indent: float = 0.0,
        leading: float | None = None,
        align: str = "left",
    ) -> None:
        """One line of text at the cursor, wrapped if it's too wide."""
        step = leading if leading is not None else size * 1.45
        width = self.width - indent
        for piece in wrap(body, font, size, width):
            self.ensure(step)
            x = self.left + indent
            if align == "right":
                x = self.left + self.width - text_width(piece, font, size)
            elif align == "centre":
                x += (width - text_width(piece, font, size)) / 2
            self._y -= step
            self._text(piece, x, self._y, font=font, size=size, colour=colour)

    def _text(
        self,
        body: str,
        x: float,
        y: float,
        *,
        font: str,
        size: float,
        colour: Colour,
        page: _Page | None = None,
    ) -> None:
        if not body:
            return
        self._op(
            f"BT {colour} rg /{_FONT_KEYS[font]} {size:.2f} Tf "
            f"1 0 0 1 {x:.2f} {y:.2f} Tm ({escape(body)}) Tj ET",
            page,
        )

    def hanging(
        self,
        marker: str,
        body: str,
        *,
        font: str = REGULAR,
        size: float = 9.5,
        colour: Colour = BLACK,
        marker_colour: Colour | None = None,
        marker_font: str | None = None,
        indent: float = 0.0,
        gutter: float = 14.0,
    ) -> None:
        """A marked line whose continuation lines align under its text."""
        step = size * 1.45
        self.ensure(step)
        top = self._y - step
        self._text(
            marker,
            self.left + indent,
            top,
            font=marker_font or font,
            size=size,
            colour=marker_colour or colour,
        )
        self.line(body, font=font, size=size, colour=colour, indent=indent + gutter)

    def rule(self, *, colour: Colour = RULE, width: float = 0.6, indent: float = 0.0) -> None:
        """A horizontal line across the usable width."""
        self.ensure(4.0)
        self._y -= 3.0
        self._op(
            f"{colour} RG {width:.2f} w {self.left + indent:.2f} {self._y:.2f} m "
            f"{self.left + self.width:.2f} {self._y:.2f} l S"
        )

    def rect(
        self,
        height: float,
        *,
        fill: Colour | None = None,
        border: Colour | None = None,
        edge: Colour | None = None,
        edge_width: float = 3.0,
        indent: float = 0.0,
    ) -> tuple[float, float]:
        """A box at the cursor, returning the top and bottom it occupies.

        `edge` paints a stripe down its left side - the cheapest way to make
        a panel look deliberate rather than like a box somebody drew.
        """
        self.ensure(height)
        top = self._y
        bottom = top - height
        x = self.left + indent
        box = f"{x:.2f} {bottom:.2f} {self.width - indent:.2f} {height:.2f} re"
        if fill is not None and border is not None:
            self._op(f"{fill} rg {border} RG 0.6 w {box} B")
        elif fill is not None:
            self._op(f"{fill} rg {box} f")
        elif border is not None:
            self._op(f"{border} RG 0.6 w {box} S")
        if edge is not None:
            self._op(f"{edge} rg {x:.2f} {bottom:.2f} {edge_width:.2f} {height:.2f} re f")
        self._y = bottom
        return top, bottom

    def at(
        self,
        body: str,
        *,
        x: float,
        y: float,
        font: str = REGULAR,
        size: float = 9.5,
        colour: Colour = BLACK,
    ) -> None:
        """Text at an absolute position, for things that fill a box."""
        self._text(body, x, y, font=font, size=size, colour=colour)

    def image(
        self,
        png: Png,
        *,
        x: float,
        y: float,
        width: float,
        name: str = "logo",
        page: _Page | None = None,
    ) -> None:
        """Draw an image at an absolute position, scaled to `width`.

        Registered once however many times it's drawn, so a mark that goes
        on every page is one copy of the bytes rather than one per page.
        """
        self._images.setdefault(name, png)
        height = width * png.height / png.width
        self._op(
            f"q {width:.2f} 0 0 {height:.2f} {x:.2f} {y:.2f} cm /{_image_key(name)} Do Q",
            page,
        )
        (page or self._pages[-1]).images.add(name)

    # --- tables -----------------------------------------------------------

    def table(
        self,
        columns: Sequence[Column],
        rows: Sequence[Sequence[Any]],
        *,
        size: float = 8.5,
        pad: float = 4.0,
        gap: float = 8.0,
    ) -> None:
        """A table with a ruled header, repeated when it runs over a page.

        Column widths are fractions of the usable width, so the same table
        reads the same whatever the margins are.
        """
        total = sum(column.width for column in columns) or 1.0
        widths = [self.width * column.width / total for column in columns]
        self._table_header(columns, widths, size, pad)
        for row in rows:
            cells = [
                wrap(str(value), column.font, size, width - gap)
                for value, column, width in zip(row, columns, widths, strict=False)
            ]
            inks = [value.colour if isinstance(value, Cell) else None for value in row]
            height = max(len(cell) for cell in cells) * size * 1.35 + pad
            if not self.room(height + 4.0):
                self.page_break()
                self._table_header(columns, widths, size, pad)
            self._row(columns, widths, cells, size=size, height=height, gap=gap, inks=inks)
        self.rule()
        self.space(4.0)

    def _table_header(
        self, columns: Sequence[Column], widths: Sequence[float], size: float, pad: float
    ) -> None:
        """The header, on a wash, with the rule under it in the accent.

        A tint rather than a bold line, because the thing a reader is looking
        for in a table is the row they care about, not the top of it.
        """
        self.ensure(size * 3)
        height = size * 1.35 + pad
        top = self._y
        self._op(f"{WASH} rg {self.left:.2f} {top - height:.2f} {self.width:.2f} {height:.2f} re f")
        self._row(
            columns,
            widths,
            [[column.title] for column in columns],
            size=size,
            height=height,
            gap=8.0,
            font=BOLD,
            colour=ACCENT,
        )
        self.rule(colour=ACCENT, width=0.8)
        self.space(2.0)

    def _row(
        self,
        columns: Sequence[Column],
        widths: Sequence[float],
        cells: Sequence[Sequence[str]],
        *,
        size: float,
        height: float,
        gap: float,
        font: str | None = None,
        colour: Colour | None = None,
        inks: Sequence[Colour | None] = (),
    ) -> None:
        top = self._y
        x = self.left
        step = size * 1.35
        for slot, (column, width, lines) in enumerate(zip(columns, widths, cells, strict=False)):
            face = font or column.font
            own = inks[slot] if slot < len(inks) else None
            ink = colour or own or column.colour
            for index, piece in enumerate(lines):
                position = x
                if column.align == "right":
                    position = x + width - gap - text_width(piece, face, size)
                elif column.align == "centre":
                    position = x + (width - gap - text_width(piece, face, size)) / 2
                self._text(
                    piece,
                    position,
                    top - step * (index + 1),
                    font=face,
                    size=size,
                    colour=ink,
                )
            x += width
        self._y = top - height

    # --- output -----------------------------------------------------------

    def render(self) -> bytes:
        """The whole document, as the bytes you write to a file."""
        self._draw_footers()
        objects: list[bytes] = []

        def add(body: str | bytes) -> int:
            objects.append(body.encode("latin-1") if isinstance(body, str) else body)
            return len(objects)

        font_ids = {
            key: add(
                f"<< /Type /Font /Subtype /Type1 /BaseFont /{name} /Encoding /WinAnsiEncoding >>"
            )
            for key, name in _BASE_FONTS.items()
        }
        resources = " ".join(f"/{_FONT_KEYS[key]} {font_ids[key]} 0 R" for key in _BASE_FONTS)

        # One image object however many pages draw it, so a mark on every
        # page costs its bytes once.
        image_ids = {
            name: add(
                b"<< /Type /XObject /Subtype /Image /Width %d /Height %d "
                b"/ColorSpace %s /BitsPerComponent %d /Filter /FlateDecode "
                b"/DecodeParms << /Predictor 15 /Colors %d /BitsPerComponent %d "
                b"/Columns %d >> /Length %d >>\nstream\n%s\nendstream"
                % (
                    png.width,
                    png.height,
                    png.colour_space.encode("latin-1"),
                    png.depth,
                    png.colours,
                    png.depth,
                    png.width,
                    len(png.data),
                    png.data,
                )
            )
            for name, png in self._images.items()
        }

        # The page objects need the Pages object's number and vice versa, so
        # its number is reserved now and its body filled in at the end.
        pages_id = add("")
        page_ids: list[int] = []
        for page in self._pages:
            stream = "\n".join(page.ops).encode("latin-1")
            content = add(b"<< /Length %d >>\nstream\n%s\nendstream" % (len(stream) + 1, stream))
            drawn = " ".join(
                f"/{_image_key(name)} {image_ids[name]} 0 R" for name in sorted(page.images)
            )
            xobjects = f"/XObject << {drawn} >> " if drawn else ""
            page_ids.append(
                add(
                    f"<< /Type /Page /Parent {pages_id} 0 R "
                    f"/MediaBox [0 0 {PAGE_WIDTH:.2f} {PAGE_HEIGHT:.2f}] "
                    f"/Resources << /Font << {resources} >> {xobjects}>> "
                    f"/Contents {content} 0 R >>"
                )
            )
        kids = " ".join(f"{page_id} 0 R" for page_id in page_ids)
        objects[pages_id - 1] = f"<< /Type /Pages /Count {len(page_ids)} /Kids [{kids}] >>".encode(
            "latin-1"
        )

        catalog_id = add(f"<< /Type /Catalog /Pages {pages_id} 0 R >>")
        info_id = add(
            f"<< /Title ({escape(self.title)}) /Author ({escape(self.author)}) "
            f"/Producer ({escape(self.author)}) /Creator ({escape(self.author)})"
            f"{self._date()} >>"
        )
        return _assemble(objects, catalog_id, info_id)

    def _date(self) -> str:
        """The creation date, taken from the scan so the file is reproducible."""
        if self.created is None:
            return ""
        return f" /CreationDate (D:{self.created.strftime('%Y%m%d%H%M%S')}Z)"

    def _draw_footers(self) -> None:
        """The footer line on every page, once the total is known.

        Drawn here rather than as each page is finished, because "3 of 11"
        isn't knowable until the last page exists.
        """
        if self._footed:
            return
        self._footed = True
        total = len(self._pages)
        size = 7.5
        y = self.margin - 10.0
        for number, page in enumerate(self._pages, start=1):
            self._op(
                f"{RULE} RG 0.5 w {self.left:.2f} {y + size + 3.0:.2f} m "
                f"{self.left + self.width:.2f} {y + size + 3.0:.2f} l S",
                page,
            )
            self._text(self._footer, self.left, y, font=REGULAR, size=size, colour=DIM, page=page)
            label = f"{number} of {total}"
            self._text(
                label,
                self.left + self.width - text_width(label, REGULAR, size),
                y,
                font=REGULAR,
                size=size,
                colour=DIM,
                page=page,
            )


def _image_key(name: str) -> str:
    """The name an image goes by inside a content stream.

    Derived from the name rather than numbered, so the same document always
    produces the same bytes.
    """
    return "Im" + "".join(char for char in name if char.isalnum())


def _assemble(objects: Sequence[bytes], catalog_id: int, info_id: int) -> bytes:
    """Objects, the cross-reference table that finds them, and the trailer."""
    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets: list[int] = []
    for number, body in enumerate(objects, start=1):
        offsets.append(len(out))
        out += b"%d 0 obj\n" % number
        out += body
        out += b"\nendobj\n"
    start = len(out)
    out += b"xref\n0 %d\n" % (len(objects) + 1)
    out += b"0000000000 65535 f \n"
    for offset in offsets:
        out += b"%010d 00000 n \n" % offset
    out += b"trailer\n<< /Size %d /Root %d 0 R /Info %d 0 R >>\n" % (
        len(objects) + 1,
        catalog_id,
        info_id,
    )
    out += b"startxref\n%d\n%%%%EOF\n" % start
    return bytes(out)
