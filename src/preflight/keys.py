"""Single keypresses, for the pickers that want arrow keys.

Only used when there's a real terminal on the other end. Anything else — a
pipe, a CI job, the test runner — gets `supported() is False` and the caller
falls back to asking a question and reading a line, so every flow stays
scriptable.
"""

from __future__ import annotations

import sys

UP = "up"
DOWN = "down"
ENTER = "enter"
SPACE = "space"
ESCAPE = "escape"

#: What a CSI sequence's final byte means to us.
_CSI: dict[str, str] = {"A": UP, "B": DOWN}


def supported() -> bool:
    """Whether we can read keypresses one at a time."""
    if not (sys.stdin.isatty() and sys.stdin.readable()):
        return False
    try:
        if sys.platform == "win32":
            import msvcrt  # noqa: F401
        else:
            import termios  # noqa: F401
            import tty  # noqa: F401
    except ImportError:  # pragma: no cover - platform without either
        return False
    return True


def read_key() -> str:
    """Block for one keypress and name it.

    Returns `UP`, `DOWN`, `ENTER`, `SPACE`, `ESCAPE`, or the character itself
    lowercased. Raises `KeyboardInterrupt` on Ctrl-C and `EOFError` on Ctrl-D,
    so callers can treat them the way they treat an abandoned prompt.
    """
    char = _read_char_windows() if sys.platform == "win32" else _read_char_posix()
    if char == "\x03":
        raise KeyboardInterrupt
    if char == "\x04":
        raise EOFError
    if char in ("\r", "\n"):
        return ENTER
    if char == " ":
        return SPACE
    if char == "\x1b":
        return ESCAPE
    return char.lower()


def _read_char_posix() -> str:
    """One keypress from a POSIX terminal, with escape sequences collapsed.

    Reads the file descriptor rather than `sys.stdin`: the text wrapper would
    pull a whole `ESC [ A` into its own buffer while answering `read(1)` with
    just the ESC, and then `select` — which only sees the descriptor — would
    report nothing left and we'd call it a bare Escape.
    """
    import os
    import select
    import termios
    import tty

    descriptor = sys.stdin.fileno()
    saved = termios.tcgetattr(descriptor)
    try:
        tty.setraw(descriptor)
        first = os.read(descriptor, 1)
        if first != b"\x1b":
            return first.decode("utf-8", "replace")
        # An arrow key arrives as ESC [ A. A bare Escape arrives alone, so
        # don't block waiting for the rest of a sequence that isn't coming.
        rest = b""
        while len(rest) < 2 and select.select([descriptor], [], [], 0.05)[0]:
            rest += os.read(descriptor, 8)
        if rest[:1] != b"[":
            return "\x1b"
        return _CSI.get(rest[1:2].decode("utf-8", "replace"), "\x1b")
    finally:
        termios.tcsetattr(descriptor, termios.TCSADRAIN, saved)


def _read_char_windows() -> str:  # pragma: no cover - exercised on Windows only
    """One keypress from a Windows console."""
    import msvcrt

    char = msvcrt.getwch()
    if char in ("\x00", "\xe0"):
        return {"H": UP, "P": DOWN}.get(msvcrt.getwch(), "\x1b")
    return char
