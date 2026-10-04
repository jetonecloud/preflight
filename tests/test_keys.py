"""Keypress reading.

The platform-specific part — putting a terminal in raw mode — isn't exercised
here; what's worth protecting is the translation from bytes to the names the
pickers branch on, and that `supported()` says no when there's no terminal.
"""

import pytest

from preflight import keys


@pytest.fixture
def pressed(monkeypatch):
    """Feed `read_key` a character as if it came from a terminal."""

    def press(char: str) -> str:
        for reader in ("_read_char_posix", "_read_char_windows"):
            monkeypatch.setattr(keys, reader, lambda _char=char: _char)
        return keys.read_key()

    return press


@pytest.mark.parametrize(
    ("char", "expected"),
    [
        ("\r", keys.ENTER),
        ("\n", keys.ENTER),
        (" ", keys.SPACE),
        ("\x1b", keys.ESCAPE),
        (keys.UP, keys.UP),
        (keys.DOWN, keys.DOWN),
        ("a", "a"),
        ("A", "a"),
        ("n", "n"),
    ],
)
def test_keys_are_named(pressed, char, expected):
    assert pressed(char) == expected


def test_ctrl_c_and_ctrl_d_behave_like_an_abandoned_prompt(pressed):
    with pytest.raises(KeyboardInterrupt):
        pressed("\x03")
    with pytest.raises(EOFError):
        pressed("\x04")


def test_unsupported_without_a_terminal():
    """pytest replaces stdin with something that isn't a tty."""
    assert keys.supported() is False
