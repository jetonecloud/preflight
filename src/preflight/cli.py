from __future__ import annotations

import re
import sys
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any, NoReturn

import click
import typer

from preflight import __version__, keys, ui
from preflight.core.cfn import DEFAULT_FILENAME, render_role_template
from preflight.core.iam import collect_actions, selectable_services
from preflight.modules import (
    BASE_ACTIONS,
    REGISTRY,
    Module,
    ModuleError,
    ModuleNotAvailableError,
    UnknownModuleError,
    available_modules,
    resolve,
)

app = typer.Typer(
    name="preflight",
    no_args_is_help=True,
    add_completion=False,
    help="Free, read-only AWS audit CLI. Finds the first three things to fix "
    "in deploys, cost, and bus factor.",
)

TOTAL_STEPS = 3


def _show_version(value: bool) -> None:
    """`--version` on stdout, so a script can read it."""
    if value:
        typer.echo(f"preflight {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            "-V",
            callback=_show_version,
            is_eager=True,
            help="Show the version and exit.",
        ),
    ] = False,
) -> None:
    pass


def _tokens(raw: str) -> list[str]:
    """Split `cost, security` or `1 2` into tokens."""
    return [token for token in re.split(r"[,\s]+", raw.strip()) if token]


def _select(raw: str) -> tuple[Module, ...]:
    """Turn picker input - numbers, keys, or `all` - into modules."""
    options = available_modules()
    wanted: list[str] = []
    for token in _tokens(raw):
        if token.isdigit():
            index = int(token)
            if not 1 <= index <= len(options):
                raise ModuleError(f"There's no module {index} in the list.")
            wanted.append(options[index - 1].key)
        else:
            wanted.append(token)
    if not wanted:
        raise ModuleError("Nothing selected.")
    return resolve(wanted)


def _report_selection_error(exc: ModuleError) -> None:
    if isinstance(exc, UnknownModuleError):
        ui.print_error(f"Don't know {_quote(exc.keys)}.")
    elif isinstance(exc, ModuleNotAvailableError):
        ui.print_error(f"{_quote(exc.keys)} isn't available yet.")
    else:
        ui.print_error(str(exc))
    ui.print_hint(f"Available now: {_quote(tuple(m.key for m in available_modules()))}")


def _quote(keys: tuple[str, ...]) -> str:
    return ", ".join(f"'{key}'" for key in keys) if keys else "nothing"


def _abandoned() -> NoReturn:
    """Nobody answered - say so, and point at the non-interactive route."""
    ui.console.print()
    ui.print_error("No answer given, so nothing was written.")
    ui.print_hint("In a script, skip the questions: preflight scan --modules cost --save")
    raise typer.Exit(2)


def _ask(text: str, **kwargs: Any) -> str:
    """Ask a question, and fail helpfully when there's no one to answer."""
    try:
        return ui.ask(text, **kwargs)
    except (EOFError, KeyboardInterrupt, click.Abort):
        _abandoned()


def _interactive() -> bool:
    """Whether there's a person on the other end to answer a question."""
    return sys.stdin.isatty()


def _confirm(text: str, *, default: bool = False) -> bool:
    try:
        return ui.confirm(text, default=default)
    except (EOFError, KeyboardInterrupt, click.Abort):
        return default


def _fail(message: str, hint: str | None = None, code: int = 1) -> NoReturn:
    ui.print_error(message)
    if hint:
        ui.print_hint(hint)
    raise typer.Exit(code)


def _prompt_for_modules() -> tuple[Module, ...]:
    """Ask until the answer resolves to something we can run."""
    default = "1" if available_modules() else None
    while True:
        raw = _ask("Modules to check (number, name, or 'all')", default=default)
        try:
            return _select(raw)
        except ModuleError as exc:
            _report_selection_error(exc)
            ui.console.print()


#: Words the permission picker understands on top of numbers and service names.
SELECT_ALL = {"a", "all", "*"}
SELECT_NONE = {"n", "none", "clear"}
PICKER_DONE = {"", "d", "done", "ok", "go", "continue", "y", "yes"}


def _select_services(raw: str, groups: dict[str, tuple[str, ...]]) -> list[str]:
    """Turn `1 3 ec2` into service names, in picker order."""
    names = list(groups)
    chosen: list[str] = []
    for token in _tokens(raw):
        if token.isdigit():
            index = int(token)
            if not 1 <= index <= len(names):
                raise ModuleError(f"There's no permission {index} in the list.")
            chosen.append(names[index - 1])
        elif token.lower() in groups:
            chosen.append(token.lower())
        else:
            raise ModuleError(f"Don't know the service '{token}'.")
    # Deduplicated: a service named twice in one answer still toggles once.
    return list(dict.fromkeys(chosen))


def _requested_services(raw: str | None, groups: dict[str, tuple[str, ...]]) -> tuple[str, ...]:
    """Resolve `--services ec2,rds` against what the selected modules declare."""
    if raw is None:
        return tuple(groups)
    wanted = [token.lower() for token in _tokens(raw)]
    if "all" in wanted:
        return tuple(groups)
    unknown = tuple(dict.fromkeys(token for token in wanted if token not in groups))
    if unknown:
        ui.print_error(f"The modules you picked don't use {_quote(unknown)}.")
        ui.print_hint(f"Services they do use: {_quote(tuple(groups))}")
        raise typer.Exit(2)
    if not wanted:
        ui.print_error("No services selected, so there'd be no permissions to grant.")
        ui.print_hint(f"Pick from: {_quote(tuple(groups))}")
        raise typer.Exit(2)
    chosen = set(wanted)
    return tuple(service for service in groups if service in chosen)


ARROW_KEYS = "Up/Down to move, Enter to check or uncheck, 'a' for all, 'n' for none"
TYPED_KEYS = "Toggle by number or name, 'all', 'none', or Enter to continue"

NOTHING_PICKED = "Nothing selected, so there'd be no permissions to grant."


def _prompt_for_services(
    selected: tuple[Module, ...],
    groups: dict[str, tuple[str, ...]],
    start: Sequence[str],
) -> tuple[str, ...]:
    """Let the user switch off services they'd rather not grant.

    Everything starts checked unless `--services` narrowed it, so continuing
    straight away grants exactly what the modules asked for. Arrow keys when
    there's a terminal to read them from, typed answers otherwise, so the
    flow still works down a pipe.
    """
    picker = _arrow_picker if keys.supported() else _typed_picker
    return picker(selected, groups, set(start))


def _arrow_picker(
    selected: tuple[Module, ...],
    groups: dict[str, tuple[str, ...]],
    picked: set[str],
) -> tuple[str, ...]:
    """Up/Down to move, Enter to toggle, Enter on the last row to continue."""
    services = list(groups)
    cursor = 0
    error: str | None = None
    while True:
        _redraw_permissions(selected, groups, picked, error, cursor=cursor, hint=ARROW_KEYS)
        error = None
        try:
            key = keys.read_key()
        except (EOFError, KeyboardInterrupt):
            _abandoned()
        if key == keys.UP:
            cursor = (cursor - 1) % (len(services) + 1)
        elif key == keys.DOWN:
            cursor = (cursor + 1) % (len(services) + 1)
        elif key == "a":
            picked = set(groups)
        elif key == "n":
            picked = set()
        elif key in (keys.ENTER, keys.SPACE):
            # The row under the services is the one that leaves the picker.
            if cursor < len(services):
                picked.symmetric_difference_update({services[cursor]})
            elif picked:
                return tuple(service for service in groups if service in picked)
            else:
                error = NOTHING_PICKED


def _typed_picker(
    selected: tuple[Module, ...],
    groups: dict[str, tuple[str, ...]],
    picked: set[str],
) -> tuple[str, ...]:
    """The same picker for terminals we can't read a single keypress from."""
    error: str | None = None
    while True:
        _redraw_permissions(selected, groups, picked, error, hint=TYPED_KEYS)
        error = None
        raw = _ask("Toggle, 'all', 'none', or Enter to continue", default="", show_default=False)
        token = raw.strip().lower()
        if token in SELECT_ALL:
            picked = set(groups)
            continue
        if token in SELECT_NONE:
            picked = set()
            continue
        if token in PICKER_DONE:
            if picked:
                return tuple(service for service in groups if service in picked)
            error = NOTHING_PICKED
            continue
        try:
            picked.symmetric_difference_update(_select_services(raw, groups))
        except ModuleError as exc:
            error = str(exc)


def _redraw_permissions(
    selected: tuple[Module, ...],
    groups: dict[str, tuple[str, ...]],
    picked: set[str],
    error: str | None,
    *,
    cursor: int | None = None,
    hint: str | None = None,
) -> None:
    ui.clear_screen()
    ui.print_step(2, TOTAL_STEPS, "Choose the permissions")
    ui.print_checking(selected)
    ui.print_permissions(groups, picked, always=BASE_ACTIONS, cursor=cursor, keys=hint)
    if error:
        ui.print_error(error)
        ui.console.print()


def _resolve_target(out: Path | None, save: bool) -> Path | None:
    """Where the template should be written, if anywhere."""
    if out is None:
        return Path(DEFAULT_FILENAME) if save else None
    # A directory means "in here, under the usual name".
    return out / DEFAULT_FILENAME if out.is_dir() else out


def _write_template(path: Path, text: str, *, force: bool, interactive: bool) -> None:
    if path.exists():
        if not path.is_file():
            _fail(f"{path} isn't a file.")
        if not force and not (interactive and _confirm(f"{path} already exists. Overwrite it?")):
            _fail(
                f"{path} already exists, so nothing was written.",
                "Re-run with --force to overwrite it, or --out <path> to write elsewhere.",
            )
    try:
        path.write_text(text, encoding="utf-8")
    except OSError as exc:
        _fail(f"Couldn't write {path}: {exc.strerror or exc}")


DEFAULT_LOOKBACK_DAYS = 14


def _short(path: Path) -> str:
    """A path relative to where you ran the command, if it is one."""
    try:
        return f"./{path.resolve().relative_to(Path.cwd())}"
    except ValueError:
        return str(path)


def _deliver(result: Any, out: Path | None, *, save_json: bool = True) -> None:
    """Write the JSON copy, say what we found and where it went, then show it.

    The file is written before anything is printed, so the line that names
    it is a fact rather than an intention.
    """
    from preflight.core import report

    path = report.write(result, out or Path.cwd()) if save_json else None
    ui.show_report(result, json_path=_short(path) if path else None)
    ui.print_scan_footer(result.seconds)


#: How long the sample dwells on each check before printing its line. The
#: demo has no account to read, so the pacing is the only thing standing
#: between the reader and nine lines in a single frame.
DEMO_PACE = 0.4


@app.command()
def demo(
    out: Annotated[
        Path | None,
        typer.Option("--out", "-o", help="Directory to write the sample JSON export into."),
    ] = None,
    no_json: Annotated[
        bool,
        typer.Option("--no-json", help="Print the sample report without writing the JSON export."),
    ] = False,
) -> None:
    """Print a sample report, with no AWS account and no credentials.

    The sample is produced by running the real checks against a made-up
    account, so what you see is what the tool actually does - including the
    cases it deliberately stays quiet about.
    """
    ui.print_banner()

    from preflight import demo as sample
    from preflight.core.scan import ScanProgress

    ui.console.print(
        "  [dim]Sample data for a made-up account. No AWS calls, no credentials.[/dim]\n"
    )

    def starting(check: Any, status: Any) -> None:
        status.update(f"[dim]{check.title}...[/dim]")
        ui.pause(DEMO_PACE)

    try:
        with ui.scanning("Reading the sample account") as status:
            progress = ScanProgress(
                on_check_start=lambda check: starting(check, status),
                on_check_done=lambda outcome: ui.print_check_result(outcome.check.title, outcome),
            )
            result = sample.build(progress=progress)
            status.update("[dim]Looking up last month's bill...[/dim]")
            ui.pause(DEMO_PACE)
    except KeyboardInterrupt:
        ui.console.print()
        _fail("Stopped.", code=130)

    # A beat between the last check and the total, so the number lands on a
    # screen the reader has finished with rather than one still filling.
    ui.pause(DEMO_PACE * 2)
    _deliver(result, out, save_json=not no_json)


def _modules_for_scan(raw: str | None) -> tuple[Module, ...]:
    """Which modules a scan runs: everything available unless told otherwise."""
    if raw is None:
        return available_modules()
    try:
        return _select(raw)
    except ModuleError as exc:
        _report_selection_error(exc)
        raise typer.Exit(2) from None


def _list_checks(modules: str | None) -> None:
    for module in _modules_for_scan(modules):
        ui.print_checks(module)


def _checks_to_run(selected: tuple[Module, ...], only: str | None) -> tuple[str, ...] | None:
    """Resolve `--only`, or `None` for "all of them"."""
    if only is None:
        return None
    known = {check.key for module in selected for check in module.checks}
    wanted = tuple(dict.fromkeys(_tokens(only)))
    unknown = tuple(key for key in wanted if key not in known)
    if unknown:
        ui.print_error(f"Don't know the check {_quote(unknown)}.")
        ui.print_hint("List them with: preflight scan --list-checks")
        raise typer.Exit(2)
    if not wanted:
        _fail("No checks selected.", "List them with: preflight scan --list-checks", code=2)
    return wanted


def _command_line(
    *,
    modules: tuple[Module, ...],
    role_arn: str | None,
    profile: str | None,
    regions: str | None,
    days: int,
    only: str | None,
) -> str:
    """The command that reproduces this scan, for the report's header.

    Rebuilt from the resolved options rather than copied out of `sys.argv`,
    so nothing the user happened to type ends up in a file they might share.
    """
    parts = ["preflight scan", f"--modules {','.join(module.key for module in modules)}"]
    if role_arn:
        parts.append(f"--role-arn {role_arn}")
    if profile:
        parts.append(f"--profile {profile}")
    if regions:
        parts.append(f"--region {regions}")
    if only:
        parts.append(f"--only {only}")
    if days != DEFAULT_LOOKBACK_DAYS:
        parts.append(f"--days {days}")
    return " ".join(parts)


def _audit(
    *,
    modules: str | None,
    profile: str | None,
    role_arn: str | None,
    external_id: str | None,
    regions: str | None,
    days: int,
    only: str | None,
    out: Path | None,
    save_json: bool,
    redact: bool,
    yes: bool,
) -> None:
    """Read the account and report on it.

    Everything up to the confirmation is free: resolving credentials and
    asking AWS who we are costs one `GetCallerIdentity`, and we show what
    we're about to read before reading any of it.
    """
    from preflight.core import aws
    from preflight.core import spend as spend_reader
    from preflight.core.report import Account, ScanResult
    from preflight.core.scan import ScanContext, ScanProgress, run_module
    from preflight.core.session import identity_caution, open_session, resolve_regions

    if days < 1:
        _fail("--days has to be at least 1.", code=2)

    selected = _modules_for_scan(modules)
    wanted_checks = _checks_to_run(selected, only)
    requested_regions = tuple(_tokens(regions)) if regions else ()

    try:
        session = open_session(
            profile=profile,
            role_arn=role_arn,
            external_id=external_id,
            region=requested_regions[0] if requested_regions else None,
        )
        identity = session.identity
    except aws.AwsError as exc:
        _fail(exc.message, exc.hint)

    ui.print_target(identity.account_id, identity.arn, session.source)
    caution = identity_caution(identity)
    if caution:
        ui.print_caution(*caution)

    try:
        plan = resolve_regions(session, requested_regions)
    except aws.AwsError as exc:
        _fail(exc.message, exc.hint)

    checks = [
        check
        for module in selected
        for check in module.checks
        if wanted_checks is None or check.key in wanted_checks
    ]
    ui.print_plan(selected, checks, plan.regions, lookback_days=days, region_note=plan.note)

    if not yes:
        if not _interactive():
            # No one to ask. Say so rather than hanging or quietly assuming.
            ui.print_hint("Nothing to ask on, so going ahead. Use --yes to make that explicit.\n")
        elif not _confirm("Read the account now?", default=True):
            ui.print_error("Nothing was read.")
            raise typer.Exit(1)
    ui.console.print()

    started = datetime.now(UTC)
    ctx = ScanContext(session, regions=plan.regions, lookback_days=days)
    if plan.note:
        ctx.note(plan.note)

    outcomes = []
    try:
        with ui.scanning() as status:
            progress = ScanProgress(
                on_check_start=lambda check: status.update(f"[dim]{check.title}...[/dim]"),
                on_check_done=lambda outcome: ui.print_check_result(outcome.check.title, outcome),
            )
            for module in selected:
                outcomes.extend(run_module(ctx, module, progress=progress, only=wanted_checks))
            status.update("[dim]Looking up last month's bill...[/dim]")
            spend = _read_spend(session, selected, spend_reader)
    except aws.CredentialsError as exc:
        _fail(exc.message, exc.hint)
    except KeyboardInterrupt:
        ui.console.print()
        _fail("Stopped. Nothing was written.", code=130)

    result = ScanResult(
        account=Account.of(identity),
        regions=plan.regions,
        outcomes=tuple(outcomes),
        modules=selected,
        started_at=started,
        finished_at=datetime.now(UTC),
        lookback_days=days,
        credentials=session.source,
        command=_command_line(
            modules=selected,
            role_arn=role_arn,
            profile=profile,
            regions=regions,
            days=days,
            only=only,
        ),
        spend=spend,
        notes=tuple(ctx.notes),
    )
    if redact:
        result = result.redact()
    _deliver(result, out, save_json=save_json)


def _read_spend(session: Any, modules: tuple[Module, ...], reader: Any) -> Any:
    """Last month's bill, if any selected module asked for the permission."""
    declared = {action for module in modules for action in module.iam_actions}
    if reader.ACTION not in declared:
        return None
    return reader.read(session)


@app.command()
def scan(
    modules: Annotated[
        str | None,
        typer.Option(
            "--modules",
            "-m",
            metavar="KEYS",
            help="Modules to include, comma-separated (e.g. 'cost' or 'all'). Skips the questions.",
        ),
    ] = None,
    services: Annotated[
        str | None,
        typer.Option(
            "--services",
            "-s",
            metavar="SERVICES",
            help="Narrow the role to these AWS services, comma-separated (e.g. 'ec2,rds'). "
            "Defaults to everything the selected modules need.",
            show_default=False,
        ),
    ] = None,
    save: Annotated[
        bool,
        typer.Option("--save", help=f"Write the role template to ./{DEFAULT_FILENAME}."),
    ] = False,
    out: Annotated[
        Path | None,
        typer.Option(
            "--out",
            "-o",
            help="Where to write: the role template's path, or the directory "
            "the JSON export goes in when you're scanning.",
            show_default=False,
        ),
    ] = None,
    show: Annotated[
        bool, typer.Option("--print", help="Write the role template to stdout.")
    ] = False,
    force: Annotated[
        bool, typer.Option("--force", help="Overwrite the output file if it exists.")
    ] = False,
    list_modules: Annotated[
        bool, typer.Option("--list-modules", help="List the modules and exit.")
    ] = False,
    profile: Annotated[
        str | None,
        typer.Option(help="AWS profile to scan with. Implies a scan rather than a role."),
    ] = None,
    region: Annotated[
        str | None,
        typer.Option(
            metavar="REGIONS",
            help="Regions to scan, comma-separated. Defaults to every region the "
            "account has enabled.",
            show_default=False,
        ),
    ] = None,
    role_arn: Annotated[
        str | None,
        typer.Option(help="Read-only role to assume and scan with. The recommended way."),
    ] = None,
    external_id: Annotated[
        str | None,
        typer.Option(help="External ID, if the role's trust policy requires one."),
    ] = None,
    current: Annotated[
        bool,
        typer.Option(
            "--current",
            help="Scan with whatever credentials are already in the environment "
            "(CloudShell, env vars, an instance role).",
        ),
    ] = False,
    days: Annotated[
        int,
        typer.Option(
            "--days",
            metavar="N",
            help="How many days of usage metrics the idle checks look at.",
        ),
    ] = DEFAULT_LOOKBACK_DAYS,
    only: Annotated[
        str | None,
        typer.Option(
            "--only",
            metavar="CHECKS",
            help="Run only these checks, comma-separated. See --list-checks.",
            show_default=False,
        ),
    ] = None,
    list_checks: Annotated[
        bool, typer.Option("--list-checks", help="List the individual checks and exit.")
    ] = False,
    no_json: Annotated[
        bool,
        typer.Option("--no-json", help="Print the report without writing the JSON export."),
    ] = False,
    redact: Annotated[
        bool,
        typer.Option(
            "--redact",
            help="Replace account and resource identifiers with stable pseudonyms.",
        ),
    ] = False,
    yes: Annotated[
        bool, typer.Option("--yes", "-y", help="Don't ask before reading the account.")
    ] = False,
) -> None:
    """Generate the read-only IAM role, or scan an account with it.

    With no credentials given, this runs entirely offline and produces a
    CloudFormation template you can read before you deploy it, granting only
    the Get/List/Describe actions the modules you picked declare.

    Give it `--role-arn` (or `--profile`, or `--current`) and it runs the
    checks instead, and prints you a report.
    """
    ui.print_banner()

    if list_modules:
        ui.print_modules(REGISTRY)
        ui.console.print(
            "Generate the role for one: [bold]preflight scan --modules cost --save[/bold]"
        )
        raise typer.Exit()

    if list_checks:
        _list_checks(modules)
        raise typer.Exit()

    if role_arn or profile or current:
        # Flags that only mean something when generating a role. Say so
        # rather than ignoring them, so nobody thinks --save wrote a report.
        unused = [
            flag
            for flag, given in (
                ("--save", save),
                ("--print", show),
                ("--force", force),
                ("--services", services is not None),
            )
            if given
        ]
        if unused:
            ui.print_hint(
                f"{', '.join(unused)} only applies when generating a role, "
                "so it was ignored here.\n"
            )
        _audit(
            modules=modules,
            profile=profile,
            role_arn=role_arn,
            external_id=external_id,
            regions=region,
            days=days,
            only=only,
            out=out,
            save_json=not no_json,
            redact=redact,
            yes=yes,
        )
        return

    if region:
        ui.print_hint(
            "--region only applies to a scan. Add --role-arn (or --profile) to run one.\n"
        )

    interactive = modules is None

    ui.print_step(1, TOTAL_STEPS, "Choose what to check")
    if interactive:
        ui.print_modules(REGISTRY)
        selected = _prompt_for_modules()
    else:
        try:
            selected = _select(modules)
        except ModuleError as exc:
            _report_selection_error(exc)
            raise typer.Exit(2) from None

    # Step 2 gets a screen of its own: the picker is something you read and
    # change, not something you scroll back through.
    groups = selectable_services(selected)
    requested = _requested_services(services, groups)
    if interactive:
        chosen_services = _prompt_for_services(selected, groups, requested)
        ui.clear_screen()
    else:
        ui.print_step(2, TOTAL_STEPS, "Review the permissions")
        chosen_services = requested
        ui.print_checking(selected)
        ui.print_permissions(groups, set(chosen_services), always=BASE_ACTIONS)

    narrowed = tuple(chosen_services) if set(chosen_services) != set(groups) else None
    actions = collect_actions(selected, narrowed)
    template = render_role_template(selected, services=narrowed)

    ui.print_step(3, TOTAL_STEPS, "Save the template")
    ui.print_selection(selected, actions)
    target = _resolve_target(out, save)
    to_stdout = show

    if interactive and not to_stdout and target is None:
        ui.print_save_hint(DEFAULT_FILENAME)
        answer = _ask("Save to", default=DEFAULT_FILENAME)
        target = _resolve_target(Path(answer.strip() or DEFAULT_FILENAME), True)
    elif target is None and not to_stdout:
        # Non-interactive with no destination: stdout is the useful default.
        to_stdout = True

    if to_stdout:
        ui.emit_template(template)
    if target is not None:
        _write_template(target, template, force=force, interactive=interactive)
        ui.print_saved(str(target), actions)
        ui.print_next_steps(str(target))


@app.command()
def preview() -> None:
    """Show exactly what would be sent if you opt in to email delivery."""
    typer.echo("preview: not yet implemented")


if __name__ == "__main__":
    app()
