"""Shared pytest fixture helpers for Aphelion tests."""

from __future__ import annotations

import contextlib
import hashlib
import io
import sys
from pathlib import Path

# Ensure src/ is importable without requiring pip install in CI
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

import pytest  # noqa: E402


class FakeTTY(io.StringIO):
    """StringIO subclass that reports as a tty, for color-detection tests."""

    def isatty(self) -> bool:  # noqa: D401 -- simple override
        return True


def run_cli(argv: list[str]) -> tuple[int, str, str]:
    """Invoke ``aphelion.cli.main(argv)`` with stdout/stderr captured.

    Returns ``(exit_code, stdout, stderr)``. ``main`` converts argparse's
    ``SystemExit`` into a return code, but we still catch ``SystemExit`` as a
    safety net for the ``--version`` action path.
    """
    from aphelion.cli import main as cli_main

    out = io.StringIO()
    err = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = cli_main(argv)
        except SystemExit as exc:
            code = exc.code if isinstance(exc.code, int) else 2
    return code, out.getvalue(), err.getvalue()


FIXTURES = ROOT / "tests" / "fixtures"


# UUID v7 samples (valid by schema regex) used across fixtures
UUID_PKG = "0191aaaa-0000-7000-8000-000000000001"
UUID_CLAIM_A = "0191aaaa-0000-7000-8000-00000000aaaa"
UUID_CLAIM_B = "0191aaaa-0000-7000-8000-00000000bbbb"
UUID_INSTANCE_A = "0191aaaa-0000-7000-8000-aaaaaaaaaaaa"
UUID_INSTANCE_B = "0191aaaa-0000-7000-8000-bbbbbbbbbbbb"
UUID_EVENT_1 = "0191aaaa-0000-7000-8000-eeee00000001"
UUID_EVENT_2 = "0191aaaa-0000-7000-8000-eeee00000002"
UUID_EVENT_3 = "0191aaaa-0000-7000-8000-eeee00000003"


def _claim_md(title: str, body: str = "") -> bytes:
    header = (
        '---\n'
        f'"body_format": "markdown"\n'
        f'"claim_id": "{UUID_CLAIM_A}"\n'
        f'"title": "{title}"\n'
        '---\n'
    )
    return (header + body).encode("utf-8") + b"\n"


@pytest.fixture
def fixture_dir() -> Path:
    return FIXTURES


@pytest.fixture
def tmp_source(tmp_path: Path) -> Path:
    """A minimal valid source_dir with one claim."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "claims").mkdir()
    claim_path = f"claims/{UUID_CLAIM_A}.md"
    claim_bytes = _claim_md("Hello")
    (src / claim_path).write_bytes(claim_bytes)
    claim_hash = hashlib.sha256(claim_bytes).hexdigest()

    manifest = {
        "aphelion_spec_version": "0.4.0",
        "claims": [
            {
                "claim_id": UUID_CLAIM_A,
                "claim_instance_id": UUID_INSTANCE_A,
                "hash": claim_hash,
                "path": claim_path,
                "state": "active",
            }
        ],
        "created_at": "2026-04-21T00:00:00Z",
        "format_version": "2.0",
        "license": "Apache-2.0",
        "package_id": UUID_PKG,
        "producer": "aphelion-test",
        "provenance_path": "provenance.jsonl",
    }
    from aphelion.canonical_json import dumps, normalize

    (src / "manifest.json").write_bytes(dumps(normalize(manifest)))
    event = {
        "actor": "test",
        "claim_id": UUID_CLAIM_A,
        "claim_instance_id": UUID_INSTANCE_A,
        "event_id": UUID_EVENT_1,
        "event_type": "create",
        "timestamp": "2026-04-21T00:00:00Z",
    }
    (src / "provenance.jsonl").write_bytes(dumps(normalize(event)))
    return src
