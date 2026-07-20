"""M5 — round-trip agreement with the independent Aphelion reader (skeleton).

M5 asks whether an *independent* reader reproduces the reference verdict for an
Aphelion package. This module is the **verdict-level** wrapper over the current
``scripts/external_reader.py``: for each sample it compares the reader's
``validator_verdict`` (valid / invalid) against the sample's committed
``expected-normalized.json``.

The full M5 gate pinned in ``preregister.json`` is stronger — option (a) W-M5:
a second, fully independent canonical reader with **byte-for-byte** equality of
the normalized output (100/100). That two-implementation byte-equality reader is
scheduled for the EXECUTION drive (Chris 2026-07-19) and is deliberately NOT
built here; this skeleton establishes only the callable contract and the
verdict-level agreement check the execution drive will harden.

The comparison mirrors ``external_reader.run``'s own semantics, including its one
special case: a duplicate-hash-collision fixture nests two sub-packages that are
each individually valid (the collision is only illegal at merge time, out of the
minimal reader's scope), so agreement there means "every sub-package is valid".

Pure stdlib. Imports the reader by file path (it is a script, not a package) and
makes no model or network calls.
"""

from __future__ import annotations

import importlib.util
import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from types import ModuleType

# benchmarks/longmemeval/metrics/m5_roundtrip.py -> repo root is three parents up.
_REPO_ROOT = Path(__file__).resolve().parents[3]
_READER_PATH = _REPO_ROOT / "scripts" / "external_reader.py"

_COLLISION_ERROR_CODE = "ERR-SEM-DUPLICATE-HASH-COLLISION"
_EXPECTED_FILENAME = "expected-normalized.json"


@lru_cache(maxsize=1)
def _reader() -> ModuleType:
    """Load ``scripts/external_reader.py`` as a module, by path.

    The reader is a standalone script (not importable as a package), so it is
    loaded from its file location under a private module name. Its module body has
    no side effects — the import guard and CLI only run under ``__main__`` — so
    importing it here is safe.
    """
    spec = importlib.util.spec_from_file_location("_lme_external_reader", _READER_PATH)
    if spec is None or spec.loader is None:  # pragma: no cover - defensive
        raise ImportError(f"cannot load external_reader from {_READER_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@dataclass(frozen=True)
class VerdictAgreement:
    """Round-trip verdict agreement over a set of sample directories."""

    total: int
    agreements: int
    disagreements: tuple[str, ...]

    @property
    def rate(self) -> float:
        """Fraction of scored samples whose reader verdict matched expected."""
        return self.agreements / self.total if self.total else 0.0

    @property
    def all_agree(self) -> bool:
        return self.total > 0 and not self.disagreements


def reader_normalized(sample: Path) -> dict:
    """The independent reader's normalized output for one sample directory."""
    return _reader().emit_sample_json(sample)


def expected_normalized(sample: Path) -> dict:
    """The committed ``expected-normalized.json`` for one sample directory."""
    return json.loads((sample / _EXPECTED_FILENAME).read_text(encoding="utf-8"))


def verdict_agrees(sample: Path) -> bool:
    """True iff the reader's verdict matches the sample's expected verdict.

    Mirrors ``external_reader.run``: for a duplicate-hash-collision fixture the
    reader reports ``multi`` (nested sub-packages) and agreement means each
    sub-package is individually valid; otherwise the single top-level
    ``validator_verdict`` must equal the expected one.
    """
    expected = expected_normalized(sample)
    got = reader_normalized(sample)

    if expected.get("error_code") == _COLLISION_ERROR_CODE:
        sub_packages = got.get("sub_packages") or []
        return bool(sub_packages) and all(
            sub["validator_verdict"] == "valid" for sub in sub_packages
        )
    return got.get("validator_verdict") == expected["validator_verdict"]


def _scored_samples(samples_root: Path) -> list[Path]:
    """Sample subdirectories that carry an ``expected-normalized.json``."""
    return [
        sample
        for sample in sorted(samples_root.iterdir())
        if sample.is_dir() and (sample / _EXPECTED_FILENAME).exists()
    ]


def roundtrip_agreement(samples_root: Path) -> VerdictAgreement:
    """Verdict-level M5 over every expected-annotated sample under ``samples_root``.

    Returns the agreement count and the names of any disagreeing samples. The full
    byte-equality M5 (W-M5) that supersedes this is an execution-drive deliverable.
    """
    disagreements: list[str] = []
    total = 0
    for sample in _scored_samples(samples_root):
        total += 1
        if not verdict_agrees(sample):
            disagreements.append(sample.name)
    return VerdictAgreement(
        total=total,
        agreements=total - len(disagreements),
        disagreements=tuple(disagreements),
    )
