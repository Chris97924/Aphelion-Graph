"""Tests for the v0.2.2 CLI output layer (``--json`` / ``--no-color`` /
``--version`` dual display).

These exercise the :class:`dpkg.output.Writer` integration in
``dpkg.cli.main``. The existing ``test_cli.py`` covers error branches;
this file covers the success-path output contract.
"""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from dpkg import __version__, SPEC_VERSION, SCHEMA_VERSION_MAX
from dpkg.output import Writer, detect_color

from conftest import FakeTTY, run_cli as _run


# ---------- --version dual display ----------


def test_version_shows_package_spec_and_schema() -> None:
    # ``main`` catches argparse's SystemExit and returns the code, so the
    # version-action's exit code surfaces as the return value rather than an
    # exception. That is fine for scripts but means the test asserts on the
    # return value instead of ``pytest.raises``.
    code, out, err = _run(["--version"])
    assert code == 0
    line = (out + err).strip()
    # Three numbers must all appear so neither reader nor script has to guess.
    assert __version__ in line
    assert f"spec {SPEC_VERSION}" in line
    assert f"schema {SCHEMA_VERSION_MAX}" in line


# ---------- --json on success ----------


def test_init_json_mode_emits_single_json_line_on_stdout(tmp_path: Path) -> None:
    dest = tmp_path / "pkg"
    code, out, err = _run(["--json", "init", str(dest)])
    assert code == 0, err
    # In --json mode stdout must be exactly one JSON object (no human hints).
    non_blank = [ln for ln in out.splitlines() if ln.strip()]
    assert len(non_blank) == 1, f"expected 1 JSON line on stdout, got {non_blank!r}"
    payload = json.loads(non_blank[0])
    assert payload["ok"] is True
    assert payload["command"] == "init"
    assert payload["dest"] == str(dest)
    assert payload["spec_version"] == SPEC_VERSION


def test_validate_json_mode_reports_event_count(tmp_path: Path) -> None:
    dest = tmp_path / "pkg"
    code, _, err = _run(["init", str(dest)])
    assert code == 0, err
    code, out, err = _run(["--json", "validate", str(dest)])
    assert code == 0, err
    payload = json.loads(out.strip())
    assert payload == {
        "command": "validate",
        "event_count": 0,
        "mode": "strict",
        "ok": True,
        "source": str(dest),
        "summary": f"{dest}: syntax + schema OK (0 event(s))",
    }


def test_json_mode_suppresses_ansi_color(tmp_path: Path) -> None:
    dest = tmp_path / "pkg"
    code, out, _ = _run(["--json", "init", str(dest)])
    assert code == 0
    # ANSI SGR introducer must not appear in JSON mode regardless of tty.
    assert "\x1b[" not in out


# ---------- Human mode: NO_COLOR + --no-color ----------


def test_human_mode_stdout_is_plain_text(tmp_path: Path) -> None:
    dest = tmp_path / "pkg"
    code, out, err = _run(["init", str(dest)])
    assert code == 0, err
    # StringIO is not a tty -> color auto-off, output must be ANSI-free.
    assert "\x1b[" not in out
    assert "Initialized empty DPKG skeleton" in out
    assert "Next steps:" in out


def test_no_color_flag_suppresses_ansi_even_with_forced_color(tmp_path: Path) -> None:
    dest = tmp_path / "pkg"
    # --no-color must win over any tty-based auto-detection.
    code, out, _ = _run(["--no-color", "init", str(dest)])
    assert code == 0
    assert "\x1b[" not in out


def test_no_color_env_var_respected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NO_COLOR", "1")
    assert detect_color(FakeTTY()) is False


def test_detect_color_off_when_not_a_tty() -> None:
    # Plain StringIO is not a tty -> color off.
    assert detect_color(io.StringIO()) is False


def test_detect_color_on_when_tty_and_no_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NO_COLOR", raising=False)
    assert detect_color(FakeTTY()) is True


# ---------- Writer unit behavior ----------


def test_writer_success_json_payload_includes_data() -> None:
    buf = io.StringIO()
    w = Writer(json_mode=True, color=False, stdout=buf)
    w.success("pack", summary="x -> y", data={"bytes": 42})
    payload = json.loads(buf.getvalue().strip())
    assert payload == {
        "bytes": 42,
        "command": "pack",
        "ok": True,
        "summary": "x -> y",
    }


def test_writer_hint_suppressed_in_json_mode() -> None:
    buf = io.StringIO()
    w = Writer(json_mode=True, color=False, stdout=buf)
    w.hint("this should not appear")
    assert buf.getvalue() == ""


def test_writer_human_success_uses_color_when_enabled() -> None:
    buf = io.StringIO()
    w = Writer(json_mode=False, color=True, stdout=buf)
    w.success("init", summary="done")
    out = buf.getvalue()
    assert "\x1b[32m" in out  # green [ok] prefix
    assert "\x1b[0m" in out  # reset
    assert "done" in out


def test_writer_human_success_strips_color_when_disabled() -> None:
    buf = io.StringIO()
    w = Writer(json_mode=False, color=False, stdout=buf)
    w.success("init", summary="done")
    out = buf.getvalue()
    assert "\x1b[" not in out
    assert out.rstrip() == "[ok] done"


def test_writer_heading_and_hint_respect_color_flag() -> None:
    buf = io.StringIO()
    w = Writer(json_mode=False, color=True, stdout=buf)
    w.heading("HEAD")
    w.hint("tip")
    out = buf.getvalue()
    assert "\x1b[" in out
    assert "HEAD" in out
    assert "tip" in out


# ---------- ANSI injection sanitization ----------


def test_writer_human_success_strips_ansi_from_summary() -> None:
    """Attacker-controlled text in ``summary`` (e.g. a malicious file path)
    must not inject color / cursor / clear-screen sequences into the operator
    terminal. Sanitization happens on the human path; JSON mode is safe
    because ``json.dumps`` already escapes ``\\x1b``."""
    buf = io.StringIO()
    w = Writer(json_mode=False, color=False, stdout=buf)
    hostile = "pkg\x1b[2Jevicted\x1b[31m RED"
    w.success("init", summary=hostile)
    out = buf.getvalue()
    # The ESC byte (0x1b) must not appear anywhere on the human stream.
    assert "\x1b" not in out
    # The human-readable tail of the string must still survive.
    assert "pkgevicted RED" in out


def test_writer_hint_strips_ansi() -> None:
    buf = io.StringIO()
    w = Writer(json_mode=False, color=False, stdout=buf)
    w.hint("next step \x1b[1;31m!!!\x1b[0m end")
    out = buf.getvalue()
    assert "\x1b" not in out
    assert "next step !!! end" in out


def test_writer_strips_lone_trailing_esc_byte() -> None:
    """A bare trailing ``\\x1b`` with no follower must also be removed; the
    original regex matched only ESC + <param>, leaving a lone ESC intact."""
    buf = io.StringIO()
    w = Writer(json_mode=False, color=False, stdout=buf)
    w.success("init", summary="trailing\x1b")
    assert "\x1b" not in buf.getvalue()
    assert "trailing" in buf.getvalue()


def test_writer_heading_strips_ansi() -> None:
    buf = io.StringIO()
    w = Writer(json_mode=False, color=False, stdout=buf)
    w.heading("head\x1b[2Ker")
    out = buf.getvalue()
    assert "\x1b" not in out
    assert "header" in out


def test_writer_json_mode_preserves_raw_summary_because_json_escapes_esc() -> None:
    """In JSON mode the ESC byte is JSON-escaped by ``json.dumps`` (``\\u001b``),
    so we do not need to strip it — and stripping would destroy data the
    consumer may actually want. This test locks in that contract."""
    buf = io.StringIO()
    w = Writer(json_mode=True, color=False, stdout=buf)
    w.success("init", summary="pkg\x1b[2Jx")
    payload = json.loads(buf.getvalue().strip())
    # Round-tripping JSON gives us the raw character back, and it is NOT a
    # literal ESC byte in the serialized form.
    assert payload["summary"] == "pkg\x1b[2Jx"
    raw = buf.getvalue()
    assert "\x1b" not in raw  # JSON-escaped as  on the wire
    assert "\\u001b" in raw


# ---------- Full pipeline smoke in JSON mode ----------


def test_full_pipeline_init_validate_pack_unpack_verify_json(tmp_path: Path) -> None:
    """End-to-end smoke of the exact five-step flow the CI matrix runs,
    ensuring each command emits a parseable JSON success line."""
    pkg = tmp_path / "pkg"
    archive = tmp_path / "out.dpkg.tar"
    unpacked = tmp_path / "unpacked"

    for argv, expected_cmd in [
        (["--json", "init", str(pkg)], "init"),
        (["--json", "validate", str(pkg)], "validate"),
        (["--json", "pack", str(pkg), str(archive)], "pack"),
        (["--json", "unpack", str(archive), str(unpacked)], "unpack"),
        (["--json", "verify", str(unpacked)], "verify"),
    ]:
        code, out, err = _run(argv)
        assert code == 0, f"{argv} failed: {err}"
        payload = json.loads(out.strip())
        assert payload["ok"] is True
        assert payload["command"] == expected_cmd
