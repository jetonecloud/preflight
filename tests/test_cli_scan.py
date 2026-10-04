"""End-to-end tests for `preflight scan`.

The two properties worth protecting: stdout carries only the template, so it
can be piped; and nothing in this command touches the network.
"""

import os
import socket
import subprocess
import sys

import pytest
from typer.testing import CliRunner

from preflight import __version__, keys
from preflight.cli import app
from preflight.core.cfn import DEFAULT_FILENAME, render_role_template
from preflight.modules import by_key

# Wide enough that Rich doesn't wrap mid-phrase in the assertions below.
ENV = {"COLUMNS": "200", "TERM": "dumb", "NO_COLOR": "1"}

runner = CliRunner()


@pytest.fixture
def cost_template():
    return render_role_template([by_key("cost")])


@pytest.fixture
def workdir(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    return tmp_path


def invoke(*args, **kwargs):
    return runner.invoke(app, list(args), env=ENV, **kwargs)


# --- the app itself --------------------------------------------------------


def test_version_goes_to_stdout():
    """install.sh reads this to report what it installed."""
    result = invoke("--version")
    assert result.exit_code == 0
    assert result.stdout.strip() == f"preflight {__version__}"


# --- listing ---------------------------------------------------------------


def test_list_modules_shows_what_is_and_isnt_ready():
    result = invoke("scan", "--list-modules")
    assert result.exit_code == 0
    assert "Cost Check" in result.stderr
    assert "available" in result.stderr
    assert "coming soon" in result.stderr
    assert "Security & IAM" in result.stderr, "listed in the coming-soon note"
    assert result.stdout == "", "nothing to pipe when only listing"


def test_banner_is_shown():
    result = invoke("scan", "--list-modules")
    assert "|_|  |_|_\\" in result.stderr, "ASCII wordmark"
    assert "by" in result.stderr and "Jet1" in result.stderr


# --- non-interactive ------------------------------------------------------


def test_print_puts_only_the_template_on_stdout(cost_template):
    result = invoke("scan", "--modules", "cost", "--print")
    assert result.exit_code == 0
    assert result.stdout == cost_template
    assert "Step 1 of 3" in result.stderr, "chrome belongs on stderr"
    assert "Step" not in result.stdout


def test_modules_without_a_destination_prints(cost_template):
    result = invoke("scan", "-m", "cost")
    assert result.exit_code == 0
    assert result.stdout == cost_template


def test_save_writes_the_default_filename(workdir, cost_template):
    result = invoke("scan", "--modules", "cost", "--save")
    assert result.exit_code == 0
    saved = workdir / DEFAULT_FILENAME
    assert saved.read_text() == cost_template
    assert result.stdout == "", "--save shouldn't also print"
    assert DEFAULT_FILENAME in result.stderr


def test_save_reports_the_next_steps(workdir):
    result = invoke("scan", "--modules", "cost", "--save")
    assert "Next" in result.stderr
    assert "CloudFormation" in result.stderr
    assert "RoleArn" in result.stderr


def test_out_overrides_the_filename(workdir, cost_template):
    result = invoke("scan", "-m", "cost", "--out", "roles/preflight.yaml")
    assert result.exit_code == 1, "parent directory doesn't exist"
    (workdir / "roles").mkdir()
    result = invoke("scan", "-m", "cost", "--out", "roles/preflight.yaml")
    assert result.exit_code == 0
    assert (workdir / "roles" / "preflight.yaml").read_text() == cost_template


def test_out_accepts_a_directory(workdir, cost_template):
    (workdir / "infra").mkdir()
    result = invoke("scan", "-m", "cost", "-o", "infra")
    assert result.exit_code == 0
    assert (workdir / "infra" / DEFAULT_FILENAME).read_text() == cost_template


def test_print_and_save_together(workdir, cost_template):
    result = invoke("scan", "-m", "cost", "--save", "--print")
    assert result.exit_code == 0
    assert result.stdout == cost_template
    assert (workdir / DEFAULT_FILENAME).read_text() == cost_template


def test_all_selects_every_available_module(workdir, cost_template):
    result = invoke("scan", "-m", "all", "--save")
    assert result.exit_code == 0
    assert (workdir / DEFAULT_FILENAME).read_text() == cost_template


# --- overwrite protection -------------------------------------------------


def test_existing_file_is_not_overwritten(workdir):
    target = workdir / DEFAULT_FILENAME
    target.write_text("mine\n")
    result = invoke("scan", "-m", "cost", "--save")
    assert result.exit_code == 1
    assert target.read_text() == "mine\n"
    assert "--force" in result.stderr


def test_force_overwrites(workdir, cost_template):
    target = workdir / DEFAULT_FILENAME
    target.write_text("mine\n")
    result = invoke("scan", "-m", "cost", "--save", "--force")
    assert result.exit_code == 0
    assert target.read_text() == cost_template


def test_a_directory_in_the_way_is_reported(workdir):
    (workdir / "infra").mkdir()
    (workdir / "infra" / DEFAULT_FILENAME).mkdir()
    result = invoke("scan", "-m", "cost", "-o", "infra")
    assert result.exit_code == 1
    assert "isn't a file" in result.stderr


# --- bad input ------------------------------------------------------------


def test_unknown_module_is_rejected():
    result = invoke("scan", "--modules", "nope")
    assert result.exit_code == 2
    assert "nope" in result.stderr
    assert "cost" in result.stderr, "tells you what you can pick"
    assert result.stdout == ""


def test_coming_soon_module_is_rejected_with_a_clear_reason():
    result = invoke("scan", "--modules", "security")
    assert result.exit_code == 2
    assert "isn't available yet" in result.stderr


def test_empty_module_list_is_rejected():
    result = invoke("scan", "--modules", " ")
    assert result.exit_code == 2


def test_aws_options_are_acknowledged_as_inert(workdir):
    result = invoke(
        "scan",
        "-m",
        "cost",
        "--save",
        "--role-arn",
        "arn:aws:iam::123456789012:role/PreflightReadOnlyRole",
    )
    assert result.exit_code == 0
    assert "aren't wired up yet" in result.stderr


# --- interactive ----------------------------------------------------------


def test_accepting_every_default_saves_the_cost_role(workdir, cost_template):
    """Modules, then the permission picker, then the path: Enter three times."""
    result = invoke("scan", input="\n\n\n")
    assert result.exit_code == 0
    assert (workdir / DEFAULT_FILENAME).read_text() == cost_template


def test_picking_by_name_and_printing_with_the_flag(workdir, cost_template):
    result = invoke("scan", "--print", input="cost\n\n")
    assert result.exit_code == 0
    assert result.stdout == cost_template
    assert not (workdir / DEFAULT_FILENAME).exists(), "--print doesn't ask for a path"


def test_picking_by_number_and_naming_the_file(workdir, cost_template):
    result = invoke("scan", input="1\n\nrole.yaml\n")
    assert result.exit_code == 0
    assert (workdir / "role.yaml").read_text() == cost_template


def test_an_empty_path_saves_in_the_current_directory(workdir, cost_template):
    result = invoke("scan", input="cost\n\n   \n")
    assert result.exit_code == 0
    assert (workdir / DEFAULT_FILENAME).read_text() == cost_template


def test_a_directory_as_the_path_gets_the_default_filename(workdir, cost_template):
    (workdir / "infra").mkdir()
    result = invoke("scan", input="cost\n\ninfra\n")
    assert result.exit_code == 0
    assert (workdir / "infra" / DEFAULT_FILENAME).read_text() == cost_template


def test_saving_is_the_only_ending(workdir):
    """Step 3 asks for a path, not for a choice between printing and quitting."""
    result = invoke("scan", input="cost\n\n\n")
    assert result.exit_code == 0
    assert "Save to" in result.stderr
    assert "print" not in result.stderr.lower().split("Next")[0]
    assert "quit" not in result.stderr.lower()


def test_each_step_gets_its_own_screen(workdir):
    """The wordmark is reprinted per step; everything else is cleared."""
    result = invoke("scan", input="cost\n\n\n")
    assert result.exit_code == 0
    assert result.stderr.count("|_|  |_|_\\") >= 3, "banner stays on every screen"


def test_a_bad_answer_is_asked_again(workdir, cost_template):
    result = invoke("scan", "--print", input="telemetry\n7\ncost\n\n")
    assert result.exit_code == 0
    assert "Don't know 'telemetry'" in result.stderr
    assert "no module 7" in result.stderr
    assert result.stdout == cost_template


def test_a_coming_soon_answer_is_asked_again(workdir, cost_template):
    result = invoke("scan", "--print", input="reliability\ncost\n\n")
    assert result.exit_code == 0
    assert "isn't available yet" in result.stderr
    assert result.stdout == cost_template


def test_overwrite_is_confirmed_interactively(workdir, cost_template):
    target = workdir / DEFAULT_FILENAME
    target.write_text("mine\n")
    result = invoke("scan", input=f"cost\n\n{DEFAULT_FILENAME}\ny\n")
    assert result.exit_code == 0
    assert target.read_text() == cost_template


def test_declining_the_overwrite_keeps_the_file(workdir):
    target = workdir / DEFAULT_FILENAME
    target.write_text("mine\n")
    result = invoke("scan", input=f"cost\n\n{DEFAULT_FILENAME}\nn\n")
    assert result.exit_code == 1
    assert target.read_text() == "mine\n"


# --- the permission picker ------------------------------------------------


def test_permissions_start_selected(workdir, cost_template):
    """Enter at the picker grants exactly what the modules declared."""
    result = invoke("scan", input="cost\n\n\n")
    assert result.exit_code == 0
    assert (workdir / DEFAULT_FILENAME).read_text() == cost_template
    assert "[x]" in result.stderr
    assert "always included" in result.stderr.lower(), "sts isn't deselectable"


def test_toggling_a_service_off_removes_its_actions(workdir):
    result = invoke("scan", input="cost\nec2\n\n\n")
    assert result.exit_code == 0
    saved = (workdir / DEFAULT_FILENAME).read_text()
    assert "ec2:DescribeVolumes" not in saved
    assert "rds:DescribeDBInstances" in saved
    assert "sts:GetCallerIdentity" in saved, "base actions survive any narrowing"


def test_deselecting_all_then_picking_one_service(workdir):
    result = invoke("scan", input="cost\nnone\n1\n\n\n")
    assert result.exit_code == 0
    saved = (workdir / DEFAULT_FILENAME).read_text()
    assert "autoscaling:DescribeAutoScalingGroups" in saved, "service 1 in the list"
    assert "ec2:DescribeVolumes" not in saved


def test_selecting_none_and_continuing_is_refused(workdir, cost_template):
    result = invoke("scan", input="cost\nnone\n\nall\n\n\n")
    assert result.exit_code == 0
    assert "no permissions to grant" in result.stderr
    assert (workdir / DEFAULT_FILENAME).read_text() == cost_template


def test_toggling_by_number_is_reversible(workdir, cost_template):
    result = invoke("scan", input="cost\n2\n2\n\n\n")
    assert result.exit_code == 0
    assert (workdir / DEFAULT_FILENAME).read_text() == cost_template


def test_an_unknown_service_in_the_picker_is_asked_again(workdir, cost_template):
    result = invoke("scan", input="cost\nlambda\n\n\n")
    assert result.exit_code == 0
    assert "Don't know the service 'lambda'" in result.stderr
    assert (workdir / DEFAULT_FILENAME).read_text() == cost_template


def test_a_narrowed_template_records_the_command_that_reproduces_it(workdir):
    result = invoke("scan", "-m", "cost", "--services", "ec2,rds", "--save")
    assert result.exit_code == 0
    saved = (workdir / DEFAULT_FILENAME).read_text()
    assert "--services ec2,rds" in saved
    assert "ce:GetCostAndUsage" not in saved
    assert "ec2:DescribeVolumes" in saved


def test_services_flag_rejects_what_the_modules_do_not_use(workdir):
    result = invoke("scan", "-m", "cost", "--services", "lambda", "--save")
    assert result.exit_code == 2
    assert "'lambda'" in result.stderr
    assert "ec2" in result.stderr, "tells you what you can pick"
    assert list(workdir.iterdir()) == []


@pytest.fixture
def keyboard(monkeypatch):
    """Pretend there's a terminal, and script what gets typed at it."""

    def script(*pressed):
        remaining = iter(pressed)
        monkeypatch.setattr("preflight.keys.supported", lambda: True)
        monkeypatch.setattr("preflight.keys.read_key", lambda: next(remaining))

    return script


DOWN, ENTER = keys.DOWN, keys.ENTER
#: Enough Downs to land on the Continue row of an 8-service picker.
TO_CONTINUE = [DOWN] * 8


def test_arrow_keys_move_and_enter_toggles(workdir, keyboard):
    """Down to ec2 (4th), Enter to uncheck it, then on to Continue."""
    keyboard(DOWN, DOWN, DOWN, ENTER, *[DOWN] * 5, ENTER)
    result = invoke("scan", input="cost\n\n")
    assert result.exit_code == 0
    saved = (workdir / DEFAULT_FILENAME).read_text()
    assert "ec2:DescribeVolumes" not in saved
    assert "rds:DescribeDBInstances" in saved


def test_continuing_without_touching_anything_grants_the_module(workdir, keyboard, cost_template):
    keyboard(*TO_CONTINUE, ENTER)
    result = invoke("scan", input="cost\n\n")
    assert result.exit_code == 0
    assert (workdir / DEFAULT_FILENAME).read_text() == cost_template
    assert "Up/Down to move" in result.stderr
    assert "Continue" in result.stderr


def test_the_cursor_wraps_round_to_continue(workdir, keyboard, cost_template):
    keyboard(keys.UP, ENTER)
    result = invoke("scan", input="cost\n\n")
    assert result.exit_code == 0
    assert (workdir / DEFAULT_FILENAME).read_text() == cost_template


def test_a_and_n_select_everything_and_nothing(workdir, keyboard, cost_template):
    keyboard("n", "a", *TO_CONTINUE, ENTER)
    result = invoke("scan", input="cost\n\n")
    assert result.exit_code == 0
    assert (workdir / DEFAULT_FILENAME).read_text() == cost_template


def test_continuing_with_nothing_checked_is_refused(workdir, keyboard, cost_template):
    keyboard("n", *TO_CONTINUE, ENTER, "a", ENTER)
    result = invoke("scan", input="cost\n\n")
    assert result.exit_code == 0
    assert "no permissions to grant" in result.stderr
    assert (workdir / DEFAULT_FILENAME).read_text() == cost_template


def test_ctrl_c_in_the_picker_writes_nothing(workdir, monkeypatch):
    def interrupt():
        raise KeyboardInterrupt

    monkeypatch.setattr("preflight.keys.supported", lambda: True)
    monkeypatch.setattr("preflight.keys.read_key", interrupt)
    result = invoke("scan", input="cost\n")
    assert result.exit_code == 2
    assert "nothing was written" in result.stderr
    assert list(workdir.iterdir()) == []


def test_the_services_flag_seeds_the_interactive_picker(workdir):
    """--services with no --modules pre-checks the picker rather than skipping it."""
    result = invoke("scan", "--services", "ec2", input="cost\n\n\n")
    assert result.exit_code == 0
    saved = (workdir / DEFAULT_FILENAME).read_text()
    assert "ec2:DescribeVolumes" in saved
    assert "rds:DescribeDBInstances" not in saved
    assert "1 of 8 services" in result.stderr


def test_services_all_is_the_same_as_not_narrowing(workdir, cost_template):
    result = invoke("scan", "-m", "cost", "-s", "all", "--save")
    assert result.exit_code == 0
    assert (workdir / DEFAULT_FILENAME).read_text() == cost_template


def test_no_one_to_answer_points_at_the_flags(workdir):
    result = invoke("scan", input="")
    assert result.exit_code == 2
    assert "--modules cost --save" in result.stderr
    assert list(workdir.iterdir()) == []


# --- the no-AWS guarantee -------------------------------------------------


def test_scan_opens_no_sockets(workdir, monkeypatch):
    def refuse(*args, **kwargs):
        raise AssertionError("scan tried to open a socket")

    monkeypatch.setattr(socket, "socket", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    result = invoke("scan", "-m", "cost", "--save")
    assert result.exit_code == 0


def test_scan_does_not_import_an_aws_client():
    """A scan that generates a role must not even load boto3."""
    probe = (
        "import sys;"
        "from typer.testing import CliRunner;"
        "from preflight.cli import app;"
        "r = CliRunner().invoke(app, ['scan', '-m', 'cost', '--print']);"
        "assert r.exit_code == 0, r.output;"
        "print(any(m.split('.')[0] in {'boto3', 'botocore'} for m in sys.modules))"
    )
    env = dict(os.environ, PYTHONPATH=os.pathsep.join(sys.path))
    finished = subprocess.run(
        [sys.executable, "-c", probe], capture_output=True, text=True, env=env
    )
    assert finished.returncode == 0, finished.stderr
    assert finished.stdout.strip() == "False"
