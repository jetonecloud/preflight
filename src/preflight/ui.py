"""Terminal presentation for the CLI.

Everything the user reads goes to stderr; the only thing on stdout is output
they might pipe somewhere, so `preflight scan -m cost --print > role.yaml`
produces a clean file.

The report itself is one of the things you read here: it is printed in full,
in plain ASCII tables, so it survives a pipe into `less`, a copy into a
ticket, and a terminal that has never heard of a box-drawing character.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Collection, Mapping, Sequence
from dataclasses import dataclass
from functools import partial
from typing import Any

from rich import box
from rich.console import Console
from rich.markup import escape
from rich.padding import Padding
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text

from preflight import __version__, keys
from preflight.modules import Module, ModuleStatus

#: Every table and panel we draw. Rich's ASCII box uses `+`, `-` and `|`
#: only, which is the whole point.
BOX = box.ASCII

#: Chrome, prompts, errors.
console = Console(stderr=True, highlight=False)

#: Pipeable output only.
payload = Console()

BANNER = r"""
 ___  ___  ___  ___  _     ___   ___  _  _  _____
| _ \| _ \| __|| __|| |   |_ _| / __|| || ||_   _|
|  _/|   /| _| | _| | |__  | | | (_ || __ |  | |
|_|  |_|_\|___||_|  |____||___| \___||_||_|  |_|
"""

TAGLINE = "read-only AWS audit"


def print_banner() -> None:
    """Short wordmark and version, on stderr."""
    console.print(Text(BANNER.strip("\n"), style="bold cyan"))
    console.print(
        f"[dim] {TAGLINE} - v{__version__} - by[/dim] [cyan]Jet1[/cyan]\n",
        highlight=False,
    )


def clear_screen() -> None:
    """Wipe the terminal and leave the wordmark at the top.

    One step to a screen, so the thing being asked about is the only thing on
    it. Does nothing useful when output isn't a terminal (a pipe, or the test
    runner), so the escape codes are skipped there.
    """
    if console.is_terminal:
        console.clear()
    print_banner()


def _indented(markup: str, *, indent: int = 2) -> Padding:
    """Markup indented so wrapped lines line up with the first one."""
    return Padding(Text.from_markup(markup), (0, 0, 0, indent), expand=False)


def _hanging(marker: str, body: str, *, indent: int = 4) -> Padding:
    """A marked line whose continuation lines line up under its text.

    Two borderless columns rather than a literal prefix, so a long piece of
    evidence wraps into a block instead of falling back to the left margin.
    """
    label = Text.from_markup(marker)
    table = Table(box=None, show_header=False, pad_edge=False, padding=(0, 1, 0, 0))
    table.add_column(width=label.cell_len, no_wrap=True)
    table.add_column(overflow="fold")
    table.add_row(label, Text.from_markup(body))
    return Padding(table, (0, 0, 0, indent), expand=False)


def print_step(number: int, total: int, title: str) -> None:
    console.print(f"[cyan]+--[/cyan] [bold]Step {number} of {total}[/bold] - {title}")
    console.print("[cyan]+--------------------------------------[/cyan]\n")


def print_heading(title: str, note: str | None = None) -> None:
    """A section heading in the report, underlined in ASCII."""
    line = f"{title} - {note}" if note else title
    tail = f" [dim]- {escape(note)}[/dim]" if note else ""
    console.print(f"  [bold]{escape(title)}[/bold]{tail}")
    console.print(f"  [dim]{'-' * len(line)}[/dim]")


def modules_table(modules: Sequence[Module]) -> Table:
    """The module picker, numbered for the modules that can run today."""
    table = Table(
        box=None,
        pad_edge=False,
        padding=(0, 2, 0, 0),
        header_style="dim",
    )
    table.add_column("#", justify="right", width=2)
    table.add_column("Module", style="bold", no_wrap=True)
    table.add_column("Looks for")
    table.add_column("Actions", justify="right")
    table.add_column("Status", no_wrap=True)

    for choice, module in enumerate((m for m in modules if m.is_available), start=1):
        number = Text(str(choice), style="cyan")
        status = Text(ModuleStatus.AVAILABLE.label, style="green")
        actions = Text(str(len(module.iam_actions)))
        table.add_row(number, Text(module.name), Text(module.summary), actions, status)
    return table


def print_modules(modules: Sequence[Module]) -> None:
    console.print(modules_table(modules))
    coming_soon = [module.name for module in modules if not module.is_available]
    if coming_soon:
        console.print(f"\n[dim]  + coming soon: {', '.join(coming_soon)}[/dim]")
    console.print()


#: Built as `Text`, not markup: `[x]` in a markup string reads as a style tag.
CHECKED = Text("[x]", style="bold green")
UNCHECKED = Text("[ ]", style="dim")


#: The label of the row that leaves the picker, drawn under the services.
CONTINUE_ROW = "Continue"


def permissions_table(
    groups: Mapping[str, Sequence[str]],
    picked: Collection[str],
    *,
    cursor: int | None = None,
) -> Table:
    """The permission picker: one checkbox per AWS service.

    `cursor` is the index of the highlighted row when the arrow-key picker is
    driving - `len(groups)` being the Continue row below the services. Left as
    `None` the same table doubles as the read-only summary and the numbered
    fallback for terminals we can't read keypresses from.
    """
    table = Table(
        box=None,
        pad_edge=False,
        padding=(0, 2, 0, 0),
        header_style="dim",
        show_header=cursor is None,
    )
    table.add_column(" ", width=1)
    table.add_column(" ", width=3)
    table.add_column("#", justify="right", width=2)
    table.add_column("Service", style="bold", no_wrap=True)
    table.add_column("Actions", justify="right")
    table.add_column("Reads", overflow="fold")

    for index, (service, actions) in enumerate(groups.items()):
        on = service in picked
        here = index == cursor
        verbs = ", ".join(sorted({action.split(":", 1)[1] for action in actions}))
        table.add_row(
            Text(">" if here else " ", style="bold cyan"),
            CHECKED if on else UNCHECKED,
            Text(str(index + 1), style="cyan"),
            Text(service, style=_row_style(on, here)),
            Text(str(len(actions)), style="" if on else "dim"),
            Text(verbs, style="dim" if on else "dim italic"),
        )

    if cursor is not None:
        at_end = cursor == len(groups)
        table.add_row(
            Text(">" if at_end else " ", style="bold cyan"),
            Text(""),
            Text(""),
            Text(CONTINUE_ROW, style="bold cyan" if at_end else "dim"),
            Text(""),
            Text("done picking, go to the next step", style="dim"),
        )
    return table


def _row_style(on: bool, here: bool) -> str:
    if here:
        return "bold cyan"
    return "bold" if on else "dim"


def print_permissions(
    groups: Mapping[str, Sequence[str]],
    picked: Collection[str],
    *,
    always: Sequence[str] = (),
    cursor: int | None = None,
    keys: str | None = None,
) -> None:
    """Draw the picker, the locked-in actions, and (when asking) how to drive it."""
    console.print(permissions_table(groups, picked, cursor=cursor))
    console.print()
    if always:
        console.print(_indented(f"[dim]Always included: {', '.join(always)}[/dim]"))
    total = sum(len(groups[service]) for service in groups if service in picked) + len(always)
    console.print(
        _indented(
            f"[dim]{len(picked)} of {len(groups)} services - "
            f"{total} read-only action{'' if total == 1 else 's'} in the role[/dim]\n"
        )
    )
    if keys:
        console.print(_indented(f"[dim]{keys}[/dim]"))
        console.print()


def print_checks(module: Module) -> None:
    """Every check in a module, with the permissions each one needs."""
    table = Table(box=None, pad_edge=False, padding=(0, 2, 0, 0), header_style="dim")
    table.add_column("Check", style="bold", no_wrap=True)
    table.add_column("Looks for")
    table.add_column("Reads", overflow="fold")
    for check in module.checks:
        table.add_row(
            Text(check.key),
            Text(check.looks_for),
            Text(", ".join(check.actions), style="dim"),
        )
    console.print(f"  [bold]{module.name}[/bold] [dim]({module.key})[/dim]\n")
    console.print(table)
    console.print()
    console.print(_indented("[dim]Run one on its own: [/dim][bold]--only <check>[/bold]\n"))


def print_checking(modules: Sequence[Module]) -> None:
    """One line naming what step 1 settled on, above the permission picker."""
    names = ", ".join(module.name for module in modules)
    console.print(f"  [dim]Checking:[/dim] [bold]{names}[/bold]\n")


def print_selection(modules: Sequence[Module], actions: Sequence[str]) -> None:
    """Confirm what was selected and what permissions that implies."""
    names = ", ".join(module.name for module in modules)
    services = sorted({action.split(":", 1)[0] for action in actions})
    console.print(_indented(f"[bold]{names}[/bold]"))
    console.print(
        _indented(
            f"[bold]{len(actions)}[/bold] read-only actions "
            f"across [bold]{len(services)}[/bold] services: "
            f"[dim]{', '.join(services)}[/dim]"
        )
    )
    console.print(
        _indented("[dim]Get, List and Describe only. No write actions, no wildcards.[/dim]\n")
    )


def ask(
    question: str,
    *,
    default: str | None = None,
    choices: list[str] | None = None,
    show_default: bool = True,
) -> str:
    """Ask on stderr and read the answer from stdin.

    Rich prints the prompt to `console` and then reads with a bare `input()`,
    which is what keeps the question off stdout. Raises `EOFError` when
    there's nobody there to answer.
    """
    return Prompt.ask(
        question,
        console=console,
        default=default,
        choices=choices,
        show_choices=bool(choices),
        show_default=show_default,
    )


def confirm(question: str, *, default: bool = False) -> bool:
    return Confirm.ask(question, console=console, default=default)


def emit_template(text: str) -> None:
    """Write the template to stdout - highlighted for a terminal, raw for a pipe."""
    if payload.is_terminal:
        payload.print(Syntax(text, "yaml", background_color="default", word_wrap=False))
    else:
        payload.file.write(text)
        payload.file.flush()


def print_save_hint(default_path: str) -> None:
    """Tell the user what pressing Enter will do before they're asked."""
    console.print(
        _indented(
            "[dim]Enter a path to save the role template, or press "
            f"[/dim][bold]Enter[/bold][dim] for ./{default_path} in the "
            "directory you ran this from.[/dim]\n"
        )
    )


def print_saved(path: str, actions: Sequence[str]) -> None:
    console.print(
        Panel(
            Text.assemble(
                ("OK ", "bold green"),
                ("Saved the read-only role template\n", "bold"),
                (path, "bold cyan"),
                (f"  -  {len(actions)} read-only actions", "dim"),
            ),
            box=BOX,
            border_style="green",
            padding=(0, 2),
            expand=False,
        )
    )
    console.print()


def print_next_steps(path: str) -> None:
    console.print("  [bold]Next[/bold]")
    console.print(
        f"    [cyan]1.[/cyan] Read it. It's yours, and it's meant to be audited.\n"
        f"    [cyan]2.[/cyan] Deploy [bold]{path}[/bold] from the CloudFormation console, or:\n"
        f"       [dim]aws cloudformation deploy --template-file {path} \\\n"
        "         --stack-name preflight-role --capabilities CAPABILITY_NAMED_IAM \\\n"
        "         --parameter-overrides TrustedPrincipalArn=<the-arn-you-run-as>[/dim]\n"
        "    [cyan]3.[/cyan] Copy the [bold]RoleArn[/bold] output from the finished stack."
    )
    console.print(
        "    [cyan]4.[/cyan] Scan with it:\n"
        "       [bold]preflight scan --role-arn <the-RoleArn-output>[/bold]"
    )
    console.print(
        "\n  [dim]Nothing here has touched AWS yet. The scan is the first step that does, "
        "and it only reads.[/dim]"
    )


def print_error(message: str) -> None:
    console.print(f"[red]x[/red] {message}")


def print_hint(message: str) -> None:
    console.print(_indented(f"[dim]{escape(message)}[/dim]"))


# --- running a scan -------------------------------------------------------
#
# The scan half of the CLI has one job the generator half doesn't: it is
# about to read somebody's account, so it says what it's going to read
# before it does, and what it couldn't read afterwards.


def print_target(account: str, identity: str, source: str) -> None:
    """Whose account this is, and how we got in."""
    console.print(_indented(f"[bold]Account[/bold] [cyan]{account}[/cyan]"))
    console.print(_indented(f"[dim]as {identity}[/dim]"))
    console.print(_indented(f"[dim]via {source}[/dim]\n"))


def print_caution(warning: str, hint: str) -> None:
    console.print(_hanging("[yellow]![/yellow]", escape(warning), indent=0))
    print_hint(hint)
    console.print()


def print_plan(
    modules: Sequence[Module],
    checks: Sequence[Any],
    regions: Sequence[str],
    *,
    lookback_days: int,
    region_note: str | None = None,
) -> None:
    """Everything the scan is about to do, before it does any of it."""
    table = Table(box=None, pad_edge=False, padding=(0, 2, 0, 0), header_style="dim")
    table.add_column(" ", width=1)
    table.add_column("Check", style="bold", no_wrap=True)
    table.add_column("Looks for")
    for check in checks:
        table.add_row(Text("*", style="cyan"), Text(check.title), Text(check.looks_for))
    console.print(table)
    console.print()

    # Everything the scan will read, not just what the checks read: the
    # region list, last month's bill and the owner tags are calls too, and a
    # plan that leaves them out isn't the whole plan.
    support = sorted({action for module in modules for action in module.support_actions})
    actions = sorted({action for check in checks for action in check.actions} | set(support))
    services = sorted({action.split(":", 1)[0] for action in actions})
    names = ", ".join(module.name for module in modules)
    console.print(
        _indented(
            f"[dim]{names} - {len(checks)} checks - "
            f"{len(actions)} read-only actions across {len(services)} services[/dim]"
        )
    )
    console.print(
        _indented(
            f"[dim]{len(regions)} region{'' if len(regions) == 1 else 's'}: "
            f"{', '.join(regions)}[/dim]"
        )
    )
    console.print(_indented(f"[dim]Usage metrics over the last {lookback_days} days[/dim]"))
    if support:
        console.print(
            _indented(
                f"[dim]Plus {', '.join(support)} - for the region list, last "
                "month's bill and owner names[/dim]"
            )
        )
    console.print(
        _indented("[dim]Get, List and Describe only. Nothing is written, nothing is sent.[/dim]\n")
    )
    if region_note:
        print_hint(region_note + "\n")


#: Status glyphs for a finished check, picked so the shape of the line tells
#: you what happened before you've read the words.
_MARKS = {
    "clear": ("+", "green", "dim"),
    "found": ("!", "yellow", "bold"),
    "skipped": ("-", "yellow", "dim"),
    "failed": ("x", "red", "dim"),
}


def print_check_result(title: str, outcome: Any) -> None:
    """One line per finished check, as it finishes."""
    if outcome.status == "skipped":
        key, detail = "skipped", f"skipped - {outcome.reason}"
    elif outcome.status == "failed":
        key, detail = "failed", f"failed - {outcome.reason}"
    elif outcome.findings:
        key = "found"
        detail = f"{len(outcome.findings)} to look at, of {outcome.examined} checked"
    else:
        key = "clear"
        detail = f"nothing to flag, of {outcome.examined} checked"
    glyph, glyph_style, title_style = _MARKS[key]
    console.print(
        Text.assemble(
            ("  ", ""),
            (glyph, glyph_style),
            (" ", ""),
            (title, title_style),
            (f" - {detail}", "dim"),
        )
    )


def scanning(message: str = "Reading the account") -> Any:
    """A spinner for the long middle of a scan, on a terminal."""
    return console.status(f"[dim]{message}...[/dim]", spinner="dots")


def pause(seconds: float) -> None:
    """Wait, but only when there's somebody watching.

    A real scan arrives a line at a time because each check takes a moment
    to read the account. The demo has nothing to read, so it would otherwise
    dump nine lines in one frame - faster, and harder to follow. Down a pipe
    or under the test runner there's nobody watching, so nothing waits.
    """
    if console.is_terminal:
        time.sleep(seconds)


# --- the report -----------------------------------------------------------
#
# The report is the terminal. There is no file to open and no browser in the
# loop: everything a reader needs is printed here, in ASCII, and the JSON
# written alongside it is the same thing for a machine to read.
#
# On a real terminal it is read a section at a time, driven by the arrow
# keys, so the end of a scan is a page you can take in rather than a wall
# that scrolls past. Anywhere else - a pipe, CI, the test runner - the same
# sections are printed one after another, so nothing is hidden from a script.


@dataclass(frozen=True)
class Page:
    """One screen of the report: a name for it, and how to draw it."""

    title: str
    render: Callable[[], None]
    note: str | None = None


def print_intro(result: Any, *, json_path: str | None, paged: bool, sections: int) -> None:
    """The few lines before the report: what we found, and what happens next.

    Deliberately small. The scan has just finished and the reader wants one
    number, the name of the file we wrote, and to know the report is about
    to be shown to them rather than buried somewhere.
    """
    from preflight.core.report import money, plural

    console.print()
    if result.findings:
        count = len(result.findings)
        headline = (
            f"[bold]{count}[/bold] {plural(count, 'finding')}, "
            f"about [bold green]{money(result.monthly_usd)}/month[/bold green]."
        )
    else:
        headline = (
            f"[bold]Nothing worth flagging[/bold], from "
            f"{result.examined} {plural(result.examined, 'resource')}."
        )
    console.print(_indented(f"Done. {headline}"))
    if json_path:
        console.print(_indented(f"[dim]JSON saved to[/dim] [cyan]{json_path}[/cyan]"))
    console.print()
    if paged:
        console.print(
            _indented(
                f"[dim]The report is here in your terminal, in {sections} "
                f"{plural(sections, 'section')}.[/dim]"
            )
        )
        console.print(_indented(f"[dim]{PAGER_KEYS}[/dim]"))
        console.print()
        console.print(_indented("[dim]Press[/dim] [bold]Enter[/bold] [dim]to start.[/dim]"))
    else:
        console.print(_indented("[dim]The report follows.[/dim]"))
    console.print()


#: How to drive the pager, said the same way everywhere it's said.
PAGER_KEYS = "Arrows to move, Enter for the next section, 'a' for all of it, q to quit"


def show_report(result: Any, *, json_path: str | None = None, paged: bool | None = None) -> None:
    """Say what we found and where it went, then show the report itself."""
    if paged is None:
        paged = console.is_terminal and keys.supported()
    pages = report_pages(result, room=_room() if paged else None)
    print_intro(result, json_path=json_path, paged=paged, sections=len(pages))
    if not paged:
        _print_pages(pages)
        return
    if _wait_to_start():
        _run_pager(pages)


def _wait_to_start() -> bool:
    """Hold on the intro until there's a reason to move. False means skip it."""
    try:
        return keys.read_key() not in ("q", keys.ESCAPE)
    except (EOFError, KeyboardInterrupt):
        console.print()
        return False


def print_report(result: Any, *, paged: bool | None = None) -> None:
    """The whole report, with no preamble."""
    if paged is None:
        paged = console.is_terminal and keys.supported()
    pages = report_pages(result, room=_room() if paged else None)
    if paged:
        _run_pager(pages)
    else:
        _print_pages(pages)


def _print_pages(pages: Sequence[Page]) -> None:
    """Every section, one after another, each under its own heading."""
    for page in pages:
        print_heading(page.title, page.note)
        page.render()


def report_pages(result: Any, *, room: int | None = None) -> list[Page]:
    """The report, cut into sections at the places a reader would cut it.

    `room` is how many lines a section's body may take. Given one, the two
    sections that can run long - the index of findings, and a single check's
    findings in full - are cut again to fit it. Left out, each section is one
    page however long it is, which is what a pipe wants.
    """
    modules = ", ".join(module.name for module in result.modules)
    pages = [Page(modules or "Summary", partial(_summary_page, result))]
    if result.headline:
        pages.append(Page("Start here", partial(print_start_here, result)))

    numbered = _numbered_groups(result.groups())
    if numbered:
        rows = [item for _, items in numbered for item in items]
        pages.extend(_split("Everything we found", rows, _findings_index, room))
        for group, items in numbered:
            pages.extend(
                _split(
                    group["check"].title,
                    items,
                    partial(_group_page, group),
                    room,
                    cap=_FINDINGS_PER_PAGE,
                )
            )

    pages.append(Page("What was checked", partial(print_checked, result)))
    if result.skipped or result.failed or result.notes:
        pages.append(Page("What this scan couldn't see", partial(print_gaps, result)))
    pages.append(Page("How these numbers were worked out", partial(print_method, result)))
    return pages


def _split(
    title: str,
    items: Sequence[Any],
    render: Callable[[Sequence[Any]], None],
    room: int | None,
    *,
    cap: int | None = None,
) -> list[Page]:
    """Cut `items` into pages that fit, each saying which of them it is.

    A section taller than the window is worse than no section at all - you
    read the bottom of it and the top has already gone - so the pages are
    measured rather than guessed: how tall a table row or a finding comes
    out depends on how much wraps, which only rendering it can tell you.
    """
    chunks = _chunks(items, render, room, cap)
    return [
        Page(
            title,
            partial(render, chunk),
            note=f"page {position} of {len(chunks)}" if len(chunks) > 1 else None,
        )
        for position, chunk in enumerate(chunks, start=1)
    ]


def _chunks(
    items: Sequence[Any],
    render: Callable[[Sequence[Any]], None],
    room: int | None,
    cap: int | None,
) -> list[list[Any]]:
    """Greedily fill pages: take items until the next one wouldn't fit."""
    if room is None:
        return [list(items)]
    chunks: list[list[Any]] = []
    current: list[Any] = []
    for item in items:
        tall = current and _height(partial(render, [*current, item])) > room
        if len(current) == cap or tall:
            chunks.append(current)
            current = [item]
        else:
            current.append(item)
    if current:
        chunks.append(current)
    return chunks


def _height(render: Callable[[], None]) -> int:
    """How many lines something takes once it's drawn, wrapping included."""
    with console.capture() as captured:
        render()
    return len(captured.get().splitlines())


def _numbered_groups(groups: Sequence[Any]) -> list[tuple[Any, list[tuple[int, Any]]]]:
    """Findings numbered once, in reading order, so the index and the detail agree."""
    numbered: list[tuple[Any, list[tuple[int, Any]]]] = []
    number = 0
    for group in groups:
        items = []
        for finding in group["findings"]:
            number += 1
            items.append((number, finding))
        numbered.append((group, items))
    return numbered


#: What a page spends on its heading, the keys line, and the blank lines
#: around them, before any of the report gets a line.
_PAGE_CHROME = 5

#: However tall the window is, this many findings on one page is plenty to
#: read at once.
_FINDINGS_PER_PAGE = 4

#: Below this width, the index of findings drops its Check column rather
#: than folding resource names a character at a time.
_WIDE_ENOUGH_FOR_THE_CHECK = 100


def _room() -> int:
    """Lines a section's body has to work with."""
    return max(console.size.height - _PAGE_CHROME, 4)


def _summary_page(result: Any) -> None:
    print_report_header(result)
    print_headline(result)


def _run_pager(pages: Sequence[Page]) -> None:
    """Read the report a section at a time, driven by the arrow keys."""
    index = 0
    while True:
        _draw_page(pages, index)
        try:
            key = keys.read_key()
        except (EOFError, KeyboardInterrupt):
            console.print()
            return
        if key in ("q", keys.ESCAPE):
            _clear()
            return
        if key == "a":
            # Everything at once, so it's all in the scrollback to search.
            _clear()
            _print_pages(pages)
            return
        if key in (keys.LEFT, keys.UP, "p"):
            index = max(index - 1, 0)
        elif key in (keys.RIGHT, keys.DOWN, keys.ENTER, keys.SPACE, "n"):
            if index == len(pages) - 1:
                _clear()
                return
            index += 1


def _draw_page(pages: Sequence[Page], index: int) -> None:
    _clear()
    page = pages[index]
    console.print(
        _indented(
            f"[bold]{escape(page.title)}[/bold] [dim]- section {index + 1} of {len(pages)}[/dim]"
        )
    )
    page.render()
    console.print(_indented(f"[dim]{PAGER_KEYS}[/dim]"))


def _clear() -> None:
    if console.is_terminal:
        console.clear()


def print_report_header(result: Any) -> None:
    """What this report is of: the account, the regions, the window."""
    from preflight.core.report import plural

    regions = f"{len(result.regions)} {plural(len(result.regions), 'region')}"
    if len(result.regions) <= 6:
        regions += f" ({', '.join(result.regions)})"
    console.print(
        _indented(
            f"[dim]Account[/dim] [cyan]{result.account.id}[/cyan] [dim]- {regions} - "
            f"{result.lookback_days}-day usage window[/dim]"
        )
    )
    console.print(
        _indented(
            f"[dim]{result.finished_at.strftime('%d %B %Y at %H:%M UTC')} - "
            f"preflight {result.version}[/dim]"
        )
    )
    console.print()
    if result.demo:
        print_caution(
            "Sample data.",
            "This report came from a made-up account so you can see the shape "
            "of one. Nothing here was read from AWS.",
        )
    if result.redacted:
        print_hint(
            "Redacted: account and resource identifiers have been replaced with "
            "stable pseudonyms. The same resource keeps the same label throughout, "
            "and the arithmetic is unchanged.\n"
        )


def print_headline(result: Any) -> None:
    """The number, and what it's made of."""
    from preflight.core.report import money, percent, plural

    if not result.findings:
        console.print(
            Panel(
                Text.assemble(
                    ("OK ", "bold green"),
                    ("Nothing worth flagging\n", "bold"),
                    (
                        f"{result.examined} resources checked across "
                        f"{len(result.regions)} {plural(len(result.regions), 'region')}",
                        "dim",
                    ),
                ),
                box=BOX,
                border_style="green",
                padding=(0, 2),
                expand=False,
            )
        )
        console.print()
        return

    share = ""
    if result.share_of_spend is not None:
        share = f" - {percent(result.share_of_spend)} of last month's bill"
    console.print(
        Panel(
            Text.assemble(
                (f"{money(result.monthly_usd)}/month", "bold green"),
                (f"  -  {money(result.annual_usd)}/year{share}", "dim"),
            ),
            title="Estimated saving",
            title_align="left",
            box=BOX,
            border_style="green",
            padding=(0, 2),
            expand=False,
        )
    )
    console.print()

    counts = result.by_severity
    table = Table(box=BOX, header_style="dim", border_style="dim")
    for column in ("Findings", "High", "Medium", "Low", "Checks run", "Resources"):
        table.add_column(column, justify="right")
    table.add_row(
        Text(str(len(result.findings)), style="bold"),
        Text(str(counts["high"]), style="red" if counts["high"] else "dim"),
        Text(str(counts["medium"]), style="yellow" if counts["medium"] else "dim"),
        Text(str(counts["low"]), style="cyan" if counts["low"] else "dim"),
        Text(f"{len(result.ran)} of {len(result.outcomes)}"),
        Text(str(result.examined)),
    )
    console.print(Padding(table, (0, 0, 0, 2), expand=False))
    console.print()


def print_start_here(result: Any) -> None:
    """The first few things to fix, ahead of the full list."""
    from preflight.core.report import money

    if not result.headline:
        return
    console.print(
        _indented(f"[dim]The {len(result.headline)} worth doing first, by what they save.[/dim]")
    )
    console.print()
    for index, finding in enumerate(result.headline, start=1):
        console.print(
            _hanging(
                f"[cyan]{index}.[/cyan]",
                f"[bold]{escape(finding.title)}[/bold] "
                f"[dim]({money(finding.monthly_usd)}/month)[/dim]",
            )
        )
        console.print(
            _indented(
                f"[dim]{escape(finding.resource.label)} - {finding.resource.region}[/dim]",
                indent=7,
            )
        )
        console.print(_indented(escape(finding.recommendation), indent=7))
    console.print()


def _findings_index(rows: Sequence[tuple[int, Any]]) -> None:
    """A table of findings, in the order the sections that follow take them."""
    from preflight.core.report import money

    # Narrow windows don't have the room for both the check and the resource,
    # and the resource is the one you can't look up elsewhere - the check is
    # named at the top of the section that follows for every row here.
    with_check = console.width >= _WIDE_ENOUGH_FOR_THE_CHECK
    console.print()
    table = Table(box=BOX, header_style="dim", border_style="dim")
    table.add_column("#", justify="right", width=3)
    if with_check:
        table.add_column("Check", no_wrap=True)
    table.add_column("Resource", style="bold", overflow="fold")
    table.add_column("Region", no_wrap=True)
    table.add_column("Severity", no_wrap=True)
    table.add_column("$/month", justify="right", no_wrap=True)
    for number, finding in rows:
        cells = [Text(str(number), style="cyan")]
        if with_check:
            cells.append(Text(finding.check))
        cells += [
            Text(finding.resource.label),
            Text(finding.resource.region),
            _severity(finding),
            Text(money(finding.monthly_usd)),
        ]
        table.add_row(*cells)
    console.print(Padding(table, (0, 0, 0, 2), expand=False))
    console.print()


def _group_page(group: Any, chunk: Sequence[tuple[int, Any]]) -> None:
    """One check's findings, in full. Split across pages when there are many."""
    from preflight.core.report import money, plural

    count = len(group["findings"])
    console.print(
        _indented(
            f"[dim]{count} {plural(count, 'finding')} - "
            f"{money(group['monthly_usd'])}/month - "
            f"looked at {group['outcome'].examined}[/dim]"
        )
    )
    console.print(_indented(f"[dim]{escape(group['check'].looks_for)}[/dim]"))
    console.print()
    for number, finding in chunk:
        _print_finding(number, finding)


def _severity(finding: Any) -> Text:
    from preflight.core.report import SEVERITY_STYLE

    return Text(finding.level.label, style=SEVERITY_STYLE[finding.level.value])


def _print_finding(number: int, finding: Any) -> None:
    """One finding in full: what it is, the evidence, and what to do."""
    from preflight.core.report import money

    resource = finding.resource
    console.print(
        _hanging(
            f"[cyan]\\[{number}][/cyan]",
            f"[bold]{escape(finding.title)}[/bold] "
            f"[bold green]{money(finding.monthly_usd)}/month[/bold green]",
        )
    )
    meta = [
        finding.level.label + " severity",
        finding.confidence.label + " confidence",
        resource.id,
        resource.region,
    ]
    if resource.name:
        meta.append(f'"{resource.name}"')
    if resource.owner:
        meta.append(f"owner: {resource.owner}")
    console.print(_indented(f"[dim]{escape(' - '.join(meta))}[/dim]", indent=8))
    for line in finding.evidence:
        console.print(_hanging("[dim]*[/dim]", escape(line), indent=8))
    console.print(_indented(f"[bold]What to do:[/bold] {escape(finding.recommendation)}", indent=8))
    if finding.estimate:
        console.print(
            _indented(
                f"[dim]How the number was worked out: {escape(finding.estimate.basis)}[/dim]",
                indent=8,
            )
        )
    console.print()


def print_checked(result: Any) -> None:
    """Every check that ran, found nothing, or couldn't run."""
    from preflight.core.report import UNKNOWN

    if not result.outcomes:
        return
    console.print()
    table = Table(box=BOX, header_style="dim", border_style="dim")
    table.add_column("Check", style="bold", no_wrap=True)
    table.add_column("What it looks for", overflow="fold")
    table.add_column("Looked at", justify="right", no_wrap=True)
    table.add_column("Found", justify="right", no_wrap=True)
    table.add_column("Status", no_wrap=True)
    for outcome in result.outcomes:
        if outcome.clean:
            status = Text("clear", style="green")
        elif outcome.ran:
            status = Text(f"{len(outcome.findings)} to look at", style="yellow")
        elif outcome.status == "skipped":
            status = Text("skipped", style="yellow")
        else:
            status = Text("failed", style="red")
        table.add_row(
            Text(outcome.check.title),
            Text(outcome.check.looks_for),
            Text(str(outcome.examined) if outcome.status != "skipped" else UNKNOWN),
            Text(str(len(outcome.findings)) if outcome.ran else UNKNOWN),
            status,
        )
    console.print(Padding(table, (0, 0, 0, 2), expand=False))
    console.print()


def print_gaps(result: Any) -> None:
    """What the scan couldn't see, said out loud rather than left in the file."""
    if not (result.skipped or result.failed or result.notes):
        return
    console.print(_indented("[dim]So you can judge how complete the rest of it is.[/dim]"))
    console.print()
    for outcome in result.skipped:
        console.print(
            _hanging(
                "[yellow]-[/yellow]", f"[dim]{escape(outcome.check.title)}: {outcome.reason}[/dim]"
            )
        )
    for outcome in result.failed:
        console.print(
            _hanging("[red]x[/red]", f"[dim]{escape(outcome.check.title)}: {outcome.reason}[/dim]")
        )
    for note in result.notes:
        console.print(_hanging("[dim]*[/dim]", f"[dim]{escape(note)}[/dim]"))
    if result.missing_actions:
        console.print(
            f"\n  [dim]Missing: {', '.join(result.missing_actions)}[/dim]\n"
            "  [dim]Regenerate a role with everything the checks need:[/dim]\n"
            "    [bold]preflight scan --modules cost --save[/bold]"
        )
    console.print()


def print_method(result: Any) -> None:
    """The arithmetic, stated rather than implied.

    Printed with every report, because a number you can't check is a number
    you shouldn't trust.
    """
    notes = (
        "Every figure is a list price for us-east-1, the cheapest region for "
        f"everything priced here, reviewed {result.prices_reviewed}. In any "
        "other region the real saving is the same or larger.",
        "Nothing accounts for Savings Plans, Reserved Instances, credits or "
        "private pricing. If you have those, treat the figures as an upper "
        "bound on list and a lower bound on effort.",
        "Snapshots are billed incrementally, so they're costed at a third of "
        "their volume's size rather than all of it.",
        f"Usage-based checks look back {result.lookback_days} days and ignore "
        "anything that hasn't existed for that long. CPU is a proxy for "
        '"busy", not a measurement of it - check memory and disk before '
        "resizing anything.",
        "Resources tagged preflight:ignore are skipped everywhere, so you can "
        "silence a finding you've already decided about.",
        "Preflight only ever made Get, List and Describe calls to produce "
        "this. It cannot change anything in the account, by construction.",
    )
    for note in notes:
        console.print(_hanging("[dim]*[/dim]", f"[dim]{note}[/dim]"))
    console.print()


def print_scan_footer(seconds: float) -> None:
    console.print(
        f"  [dim]Read-only: every call was a Get, List or Describe. "
        f"Finished in {seconds:.1f}s.[/dim]"
    )
    console.print("  [dim]Want a hand fixing these? [/dim]https://jetonecloud.com/book")
