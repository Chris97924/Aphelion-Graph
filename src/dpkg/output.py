"""Human / machine output writer for the DPKG CLI.

Two orthogonal axes:

* ``json_mode``   - when True, success output is a single JSON line on stdout
  (``{"ok": true, "command": <name>, ...}``). When False, output is plain
  text with optional ANSI color.
* ``color``       - when True, human-mode output is wrapped in ANSI SGR
  sequences. Auto-detected (tty + ``NO_COLOR`` env respect) but can be forced
  off via the CLI flag or the env var.

The error path (``dpkg.errors.emit_error``) stays JSON-on-stderr regardless
of ``json_mode`` so scripts can parse failures without opting into
``--json``. ``json_mode`` only controls success output on stdout.
"""

from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import dataclass
from typing import IO, Any


ANSI_RESET = "\x1b[0m"
ANSI_BOLD = "\x1b[1m"
ANSI_DIM = "\x1b[2m"
ANSI_GREEN = "\x1b[32m"
ANSI_CYAN = "\x1b[36m"
ANSI_YELLOW = "\x1b[33m"

# Matches ANSI/VT control sequences (CSI + OSC + bare ESC + C0/C1 controls
# except \t and \n). Used to sanitize attacker-controlled strings (file paths,
# error messages) so they cannot inject color / clear-screen / cursor moves
# when rendered in a human terminal.
_ANSI_CONTROL_RE = re.compile(
    r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)"  # OSC ... BEL or ST
    r"|\x1b\[[\x30-\x3f]*[\x20-\x2f]*[\x40-\x7e]"  # CSI sequences
    r"|\x1b[@-_]"  # other 2-byte ESC sequences (incl. single-char C1 intros)
    r"|\x1b"  # any remaining lone ESC byte (belt-and-braces)
    r"|[\x00-\x08\x0b-\x1f\x7f]"  # bare C0 controls (keep \t=\x09 and \n=\x0a)
)


def _strip_ansi(text: str) -> str:
    """Remove ANSI / VT control sequences from ``text``.

    Applied to the caller-supplied ``summary`` / hint / heading strings before
    they are written in human mode, so an attacker who controls e.g. a file
    path cannot inject color resets or cursor moves into the operator's
    terminal. JSON mode is unaffected: ``json.dumps`` already escapes the
    ``\\x1b`` byte.
    """
    return _ANSI_CONTROL_RE.sub("", text)


def detect_color(stream: IO[str] | None = None) -> bool:
    """Decide whether ANSI color is safe for ``stream``.

    Rules (in order):
      1. ``NO_COLOR`` env var set (any value, per https://no-color.org) -> off.
      2. Stream is not a tty -> off (piped/redirected output stays clean).
      3. Otherwise on.
    """
    if "NO_COLOR" in os.environ:
        return False
    target = stream if stream is not None else sys.stdout
    isatty = getattr(target, "isatty", None)
    if not callable(isatty):
        return False
    try:
        return bool(isatty())
    except (ValueError, OSError):
        # Closed or detached stream.
        return False


@dataclass(frozen=True)
class Writer:
    """Bound output policy for a single CLI invocation.

    Instances are created once in :func:`dpkg.cli.main` after flag parsing
    and threaded through the subcommand handlers. Frozen so handlers can't
    accidentally mutate the mode mid-run.
    """

    json_mode: bool
    color: bool
    stdout: IO[str]

    def _color(self, code: str, text: str) -> str:
        if not self.color:
            return text
        return f"{code}{text}{ANSI_RESET}"

    def success(self, command: str, *, summary: str, data: dict[str, Any] | None = None) -> None:
        """Emit a one-line success result.

        In JSON mode: ``{"ok": true, "command": ..., "summary": ..., ...data}``
        In human mode: colored summary (green check) to stdout.
        """
        if self.json_mode:
            payload: dict[str, Any] = {"ok": True, "command": command, "summary": summary}
            if data is not None:
                payload.update(data)
            self.stdout.write(json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n")
        else:
            self.stdout.write(self._color(ANSI_GREEN, "[ok] ") + _strip_ansi(summary) + "\n")
        self.stdout.flush()

    def hint(self, line: str) -> None:
        """Extra human-only hint (e.g. ``Next steps:``).

        Suppressed entirely in JSON mode -- the caller should bundle any
        machine-relevant info into ``data`` on :meth:`success` instead.
        """
        if self.json_mode:
            return
        self.stdout.write(self._color(ANSI_DIM, _strip_ansi(line)) + "\n")
        self.stdout.flush()

    def heading(self, text: str) -> None:
        if self.json_mode:
            return
        self.stdout.write(self._color(ANSI_BOLD + ANSI_CYAN, _strip_ansi(text)) + "\n")
        self.stdout.flush()
