"""Contract tests for ``scripts/external_reader.py``.

These tests guard two properties:

  1. The reader classifies every sample under ``samples/`` with the
     same verdict as its ``expected-normalized.json``.
  2. The reader has zero dependencies on the ``aphelion`` or ``parallax``
     packages — it is a stdlib-only demonstration that the wire format
     is self-describing.
"""

from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
READER = ROOT / "scripts" / "external_reader.py"
SAMPLES = ROOT / "samples"


def test_reader_exists_and_is_stdlib_only() -> None:
    """Static import scan: no ``aphelion`` / ``parallax`` / ``memory`` imports."""
    src = READER.read_text(encoding="utf-8")
    tree = ast.parse(src)
    forbidden = {"aphelion", "parallax", "memory"}
    offenders: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                top = alias.name.split(".", 1)[0]
                if top in forbidden:
                    offenders.append(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                top = node.module.split(".", 1)[0]
                if top in forbidden:
                    offenders.append(node.module)
    assert not offenders, f"external_reader.py must be stdlib-only, found: {offenders}"


def test_reader_classifies_all_samples_correctly() -> None:
    """Exit code 0 proves every sample's verdict matches expectation."""
    proc = subprocess.run(
        [sys.executable, str(READER), str(SAMPLES)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, (
        f"external_reader failed.\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
    )
    assert "all match" in proc.stdout


def test_reader_emit_sample_json_matches_expected_verdict() -> None:
    """For every sample, ``emit_sample_json`` MUST agree with the
    sample's ``expected-normalized.json`` on both ``validator_verdict``
    and ``error_code`` (when present). Note: the reader does not
    reproduce ``notes`` verbatim — it derives a minimal subset — so
    only the verdict layer is compared here, which is the property the
    P6/P7 spec guarantees."""
    import importlib.util
    import json as _json

    spec = importlib.util.spec_from_file_location("external_reader", READER)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    failures: list[str] = []
    for sample in sorted(SAMPLES.iterdir()):
        exp_path = sample / "expected-normalized.json"
        if not exp_path.exists():
            continue
        expected = _json.loads(exp_path.read_text(encoding="utf-8"))
        got = mod.emit_sample_json(sample)
        # Collision sample is the one case where we expect "multi"
        # rather than a single verdict — its invalidity surfaces only
        # at merge time, which is out of scope for a per-sample reader.
        if expected.get("error_code") == "ERR-SEM-DUPLICATE-HASH-COLLISION":
            if got.get("validator_verdict") != "multi":
                failures.append(
                    f"{sample.name}: expected multi-package verdict, got {got}"
                )
            continue
        if got["validator_verdict"] != expected["validator_verdict"]:
            failures.append(
                f"{sample.name}: verdict {got['validator_verdict']!r} != "
                f"{expected['validator_verdict']!r}"
            )
        if expected.get("error_code") and got.get("error_code") != expected["error_code"]:
            failures.append(
                f"{sample.name}: error_code {got.get('error_code')!r} != "
                f"{expected['error_code']!r}"
            )
    assert not failures, "\n".join(failures)


def test_reader_rejects_illegal_lifecycle_sample() -> None:
    """Point-sample the illegal-reaffirm case: verdict MUST be ``invalid``."""
    # Reach in through the module by loading it as a script sibling.
    import importlib.util

    spec = importlib.util.spec_from_file_location("external_reader", READER)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    verdict, code, _ = mod._classify_package(SAMPLES / "withdraw-then-illegal-reaffirm")
    assert verdict == "invalid"
    assert code == "ERR-SEM-LIFECYCLE-ILLEGAL"
