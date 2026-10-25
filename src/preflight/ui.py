"""Terminal presentation for the CLI.

Everything the user reads goes to stderr; the only thing on stdout is output
they might pipe somewhere, so `preflight scan -m cost --print > role.yaml`
produces a clean file.
"""

from __future__ import annotations

from collections.abc import Collection, Mapping, Sequence
from typing import Any

from rich.console import Console
from rich.padding import Padding
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text

from preflight import __version__
from preflight.modules import Module, ModuleStatus

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
        f"[dim] {TAGLINE} · v{__version__} · by[/dim] [cyan]Jet1[/cyan]\n",
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


def _indented(markup: str) -> Padding:
    """Markup indented so wrapped lines line up with the first one."""
    return Padding(Text.from_markup(markup), (0, 0, 0, 2))


def print_step(number: int, total: int, title: str) -> None:
    console.print(f"[cyan]┌──[/cyan] [bold]Step {number} of {total}[/bold] · {title}")
    console.print("[cyan]└──────────────────────────────────────[/cyan]\n")


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
    driving — `len(groups)` being the Continue row below the services. Left as
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
            f"[dim]{len(picked)} of {len(groups)} services · "
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
    """Write the template to stdout — highlighted for a terminal, raw for a pipe."""
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
                ("✓ ", "bold green"),
                ("Saved the read-only role template\n", "bold"),
                (path, "bold cyan"),
                (f"  ·  {len(actions)} read-only actions", "dim"),
            ),
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
    console.print(f"[red]✗[/red] {message}")


def print_hint(message: str) -> None:
    console.print(f"[dim]  {message}[/dim]")


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
    console.print(f"[yellow]![/yellow] {warning}")
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
        table.add_row(Text("·", style="cyan"), Text(check.title), Text(check.looks_for))
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
            f"[dim]{names} · {len(checks)} checks · "
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
                f"[dim]Plus {', '.join(support)} — for the region list, last "
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
    "clear": ("✓", "green", "dim"),
    "found": ("●", "yellow", "bold"),
    "skipped": ("-", "yellow", "dim"),
    "failed": ("✗", "red", "dim"),
}


def print_check_result(title: str, outcome: Any) -> None:
    """One line per finished check, as it finishes."""
    if outcome.status == "skipped":
        key, detail = "skipped", f"skipped — {outcome.reason}"
    elif outcome.status == "failed":
        key, detail = "failed", f"failed — {outcome.reason}"
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
            (f" — {detail}", "dim"),
        )
    )


def scanning(message: str = "Reading the account") -> Any:
    """A spinner for the long middle of a scan, on a terminal."""
    return console.status(f"[dim]{message}…[/dim]", spinner="dots")


def print_headline(result: Any) -> None:
    """The number, and the three things to do about it."""
    from preflight.core.report import money, percent, plural

    console.print()
    if not result.findings:
        console.print(
            Panel(
                Text.assemble(
                    ("✓ ", "bold green"),
                    ("Nothing worth flagging\n", "bold"),
                    (
                        f"{result.examined} resources checked across "
                        f"{len(result.regions)} {plural(len(result.regions), 'region')}",
                        "dim",
                    ),
                ),
                border_style="green",
                padding=(0, 2),
                expand=False,
            )
        )
        console.print()
        return

    share = ""
    if result.share_of_spend is not None:
        share = f" · {percent(result.share_of_spend)} of last month's bill"
    console.print(
        Panel(
            Text.assemble(
                (f"{money(result.monthly_usd)}/month", "bold green"),
                (f"  ·  {money(result.annual_usd)}/year{share}", "dim"),
            ),
            title="Estimated saving",
            title_align="left",
            border_style="green",
            padding=(0, 2),
            expand=False,
        )
    )
    console.print()
    counts = result.by_severity
    console.print(
        _indented(
            f"[bold]{len(result.findings)}[/bold] findings "
            f"[dim]({counts['high']} high, {counts['medium']} medium, "
            f"{counts['low']} low) from {result.examined} resources[/dim]\n"
        )
    )

    console.print("  [bold]Start here[/bold]")
    for index, finding in enumerate(result.headline, start=1):
        amount = money(finding.monthly_usd) if finding.monthly_usd is not None else "—"
        console.print(
            f"    [cyan]{index}.[/cyan] [bold]{finding.title}[/bold] [dim]({amount}/month)[/dim]"
        )
        console.print(f"       [dim]{finding.resource.label} · {finding.resource.region}[/dim]")
    console.print()


def print_gaps(result: Any) -> None:
    """What the scan couldn't see, said out loud rather than left in the file."""
    if not (result.skipped or result.failed or result.notes):
        return
    console.print("  [bold]What this scan couldn't see[/bold]")
    for outcome in result.skipped:
        console.print(f"    [yellow]-[/yellow] [dim]{outcome.check.title}: {outcome.reason}[/dim]")
    for outcome in result.failed:
        console.print(f"    [red]✗[/red] [dim]{outcome.check.title}: {outcome.reason}[/dim]")
    for note in result.notes:
        console.print(f"    [dim]· {note}[/dim]")
    if result.missing_actions:
        console.print(
            f"\n  [dim]Missing: {', '.join(result.missing_actions)}[/dim]\n"
            "  [dim]Regenerate a role with everything the checks need:[/dim]\n"
            "    [bold]preflight scan --modules cost --save[/bold]"
        )
    console.print()


def print_report_saved(paths: Mapping[str, Any]) -> None:
    if not paths:
        return
    lines = [Text.assemble(("✓ ", "bold green"), ("Report saved", "bold"))]
    for label, path in paths.items():
        lines.append(Text.assemble((f"{label.upper():5}", "dim"), (f" {path}", "cyan")))
    console.print(Panel(Text("\n").join(lines), border_style="green", padding=(0, 2), expand=False))
    console.print()


def print_scan_footer(seconds: float) -> None:
    console.print(
        f"  [dim]Read-only: every call was a Get, List or Describe. "
        f"Finished in {seconds:.1f}s.[/dim]"
    )
    console.print("  [dim]Want a hand fixing these? [/dim]https://jetonecloud.com/book")
