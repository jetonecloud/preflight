from __future__ import annotations

import re
from collections.abc import Sequence
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
    """Turn picker input — numbers, keys, or `all` — into modules."""
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
    """Nobody answered — say so, and point at the non-interactive route."""
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


def _confirm(text: str) -> bool:
    try:
        return ui.confirm(text)
    except (EOFError, KeyboardInterrupt, click.Abort):
        return False


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


@app.command()
def demo() -> None:
    """Render a sample report with no AWS access required."""
    typer.echo("demo: not yet implemented")


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
            help="Write the role template to this path instead.",
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
    profile: Annotated[str | None, typer.Option(help="AWS profile to use.")] = None,
    region: Annotated[str | None, typer.Option(help="AWS region to scan.")] = None,
    role_arn: Annotated[
        str | None, typer.Option(help="IAM role to assume before scanning.")
    ] = None,
) -> None:
    """Pick what to check and generate the read-only IAM role it needs.

    Runs entirely offline: no AWS calls, no credentials, nothing leaves your
    machine. You get a CloudFormation template you can read before you deploy
    it, granting only the Get/List/Describe actions the modules you picked
    declare.
    """
    ui.print_banner()

    if list_modules:
        ui.print_modules(REGISTRY)
        ui.console.print(
            "Generate the role for one: [bold]preflight scan --modules cost --save[/bold]"
        )
        raise typer.Exit()

    if profile or region or role_arn:
        ui.console.print(
            "[yellow]![/yellow] The checks themselves aren't wired up yet, so "
            "--profile/--region/--role-arn do nothing for now."
        )
        ui.print_hint("This release gets the read-only role in place first.\n")

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
