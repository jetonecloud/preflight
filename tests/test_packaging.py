"""The Homebrew formula and the Dockerfile, checked against the release.

Neither ships inside the wheel, so nothing here imports Preflight. What's
worth protecting is the agreement between them and the rest of the release:
the formula names the four assets the build matrix actually produces, and a
formula that would 404 or fail its checksum is never printed.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
RENDER = ROOT / "packaging" / "homebrew" / "render-formula.sh"
DOCKERFILE = ROOT / "Dockerfile"

#: The release assets, named as `install.sh` and the build matrix name them.
#: Renaming one of these breaks every installed copy of the installer, so the
#: formula is held to the same list.
ASSETS = (
    "preflight-linux-x86_64",
    "preflight-linux-aarch64",
    "preflight-macos-x86_64",
    "preflight-macos-arm64",
)

pytestmark = pytest.mark.skipif(
    shutil.which("sh") is None, reason="needs a POSIX shell to run the renderer"
)


def digest(seed: str) -> str:
    """A plausible-looking sha256: 64 hex characters, distinct per asset."""
    return (seed * 64)[:64]


@pytest.fixture
def checksums(tmp_path):
    """A release's `checksums.txt`, in `sha256sum` output format."""
    path = tmp_path / "checksums.txt"
    path.write_text("".join(f"{digest(str(i))}  {name}\n" for i, name in enumerate(ASSETS)))
    return path


def render(*args) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["sh", str(RENDER), *[str(arg) for arg in args]],
        capture_output=True,
        text=True,
        check=False,
    )


def test_the_formula_names_every_asset_the_build_produces(checksums):
    formula = render("1.2.3", checksums).stdout
    for name in ASSETS:
        assert f"releases/download/v1.2.3/{name}" in formula


def test_every_checksum_comes_from_the_release(checksums):
    formula = render("1.2.3", checksums).stdout
    for index in range(len(ASSETS)):
        assert f'sha256 "{digest(str(index))}"' in formula


def test_the_formula_is_the_version_it_was_asked_for(checksums):
    formula = render("1.2.3", checksums).stdout
    assert 'version "1.2.3"' in formula
    assert "@VERSION@" not in formula


def test_a_tag_is_accepted_where_a_version_is(checksums):
    """`$GITHUB_REF_NAME` is `v1.2.3`, and passing it through should work."""
    assert render("v1.2.3", checksums).stdout == render("1.2.3", checksums).stdout


def test_nothing_is_left_unfilled(checksums):
    assert "@" not in render("1.2.3", checksums).stdout


def test_a_missing_checksum_stops_the_render(checksums, tmp_path):
    """Rather than a formula whose sha256 is empty, which installs for nobody."""
    partial = tmp_path / "partial.txt"
    partial.write_text(f"{digest('0')}  {ASSETS[0]}\n")
    done = render("1.2.3", partial)
    assert done.returncode == 1
    assert "no checksum for" in done.stderr
    assert done.stdout == ""


def test_something_that_is_not_a_version_is_refused(checksums):
    """Homebrew compares versions; a branch name would install and never upgrade."""
    done = render("main", checksums)
    assert done.returncode == 1
    assert "doesn't look like a version" in done.stderr


def test_a_checksum_that_is_not_a_digest_is_refused(tmp_path):
    bad = tmp_path / "checksums.txt"
    bad.write_text("".join(f"not-a-digest  {name}\n" for name in ASSETS))
    done = render("1.2.3", bad)
    assert done.returncode == 1
    assert "hex digest" in done.stderr


def test_the_renderer_says_how_to_call_it():
    assert "usage:" in render().stderr


def test_the_image_does_not_run_as_root():
    """It reads somebody's AWS credentials. It has no business being root."""
    assert "USER preflight" in DOCKERFILE.read_text()


def test_the_image_entrypoint_is_preflight_itself():
    """So `docker run <image> demo` reads the way the docs say it does."""
    assert 'ENTRYPOINT ["preflight"]' in DOCKERFILE.read_text()
