"""Exercise `aphelion validate` against every samples/*/ package.

For each sample with ``validator_verdict == "valid"``, the CLI must exit 0.
For each sample with ``validator_verdict == "invalid"``, the CLI must exit
non-zero and emit the error code declared in ``expected-normalized.json``.

The ``duplicate-reaffirm-collision`` sample is a merge-time verdict only:
each of its ``package-a`` / ``package-b`` sub-packages is individually
valid, so we treat it as a special case and verify both sub-packages
validate cleanly.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.conftest import run_cli


ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "samples"


def _samples_with_top_level_manifest() -> list[str]:
    out: list[str] = []
    for child in sorted(SAMPLES.iterdir()):
        if not child.is_dir():
            continue
        if (child / "manifest.json").is_file():
            out.append(child.name)
    return out


_EXPECTED = "expected-normalized.json"

SAMPLE_NAMES = _samples_with_top_level_manifest()


def _load_expected(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _code_from_stderr(stderr: str) -> str | None:
    """Pull the ``code`` field out of the CLI's JSON error line."""
    for line in stderr.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        if isinstance(obj, dict) and "code" in obj:
            return obj["code"]
    return None


# Mapping from semantic alias (in expected-normalized.json) to PX code
# emitted by the validator. The registry is normative in
# spec/error-codes.md; mirror only the codes used by samples here.
_ALIAS_TO_PX: dict[str, str] = {
    "ERR-SEM-LIFECYCLE-ILLEGAL": "PX_E_5101",
    "ERR-SEM-REAFFIRM-MISSING-TARGET": "PX_E_5102",
    "ERR-SEM-DUPLICATE-HASH-COLLISION": "PX_E_5103",
    "ERR-SYN-VERSION-UNKNOWN-MAJOR": "PX_E_3003",
    "ERR-SYN-VERSION-NOT-SEMVER": "PX_E_3004",
    "ERR-SYN-TIMESTAMP-NS": "PX_E_3005",
}


@pytest.mark.parametrize("name", SAMPLE_NAMES)
def test_per_package_validate(name: str) -> None:
    sample_dir = SAMPLES / name
    expected = _load_expected(sample_dir / _EXPECTED)
    code, _, err = run_cli(["validate", str(sample_dir)])
    if expected["validator_verdict"] == "valid":
        assert code == 0, f"{name}: expected exit 0, got {code}; stderr={err!r}"
        return
    assert code != 0, f"{name}: expected non-zero exit for invalid sample; stderr={err!r}"
    alias = expected["error_code"]
    got_px = _code_from_stderr(err)
    expected_px = _ALIAS_TO_PX.get(alias)
    assert expected_px is not None, f"{name}: unmapped semantic alias {alias!r}"
    assert got_px == expected_px, (
        f"{name}: expected {alias}={expected_px}, got {got_px!r}; stderr={err!r}"
    )


def test_duplicate_collision_sub_packages_individually_valid() -> None:
    """Collision sample is merge-time only; each sub-package is valid alone."""
    collision_root = SAMPLES / "duplicate-reaffirm-collision"
    # The top-level has no manifest.json — just two subdirs.
    assert not (collision_root / "manifest.json").exists()
    for sub in ("package-a", "package-b"):
        sub_dir = collision_root / sub
        assert (sub_dir / "manifest.json").is_file(), f"{sub_dir}: missing manifest.json"
        code, _, err = run_cli(["validate", str(sub_dir)])
        assert code == 0, f"{sub}: expected exit 0 alone; stderr={err!r}"


def test_sample_inventory_has_eight_entries() -> None:
    """Sanity-check: PRD mandates exactly the 8 samples listed in P1-SAMPLES."""
    mandated = {
        "architecture-claim",
        "contradictory-claim",
        "revise-withdraw-flow",
        "minimal-empty",
        "unicode-normalization",
        "multi-source-claim",
        "duplicate-reaffirm-collision",
        "withdraw-then-illegal-reaffirm",
    }
    actual = {p.name for p in SAMPLES.iterdir() if p.is_dir()}
    assert actual == mandated, f"samples/ inventory drift: {actual ^ mandated}"
