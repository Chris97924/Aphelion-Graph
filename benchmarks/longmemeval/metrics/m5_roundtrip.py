"""M5 — cross-tool round-trip determinism for Aphelion packages.

M5 asks whether an Aphelion package survives a round trip byte-for-byte. This
module provides the two checks that are buildable today, and refuses to let the
pinned gate be reported from either of them alone:

1. :func:`roundtrip_agreement` — **verdict level, genuinely cross-tool.** Wraps
   ``scripts/external_reader.py``, a stdlib-only reader that never imports
   ``aphelion``, and compares its ``validator_verdict`` against each sample's
   committed ``expected-normalized.json``.
2. :func:`byte_equality` — **byte level, reference implementation only.** Drives
   the ``aphelion`` package's own public API (``packer.pack`` → ``unpacker.unpack``
   → ``packer.pack``) and SHA-256-compares the two archives. Everything goes
   through the installed package; nothing here re-implements canonical
   serialization, so a serialization bug cannot be masked by a second copy of the
   same mistake.

**The pinned M5 gate is NOT satisfied by either.** ``preregister.json`` pins
option (a) ``W-M5``: a *second, fully independent* canonical reader whose bytes
are compared against the reference (design doc §7.4). Check 1 is cross-tool but
only verdict-deep; check 2 is byte-deep but single-implementation. Together they
are design-doc option **(b)**, which §7.4 records as explicitly *not* pinned —
"M5 is blocked, not waived and not silently downgraded to (b)". Landing W-M5
means expanding ``scripts/external_reader.py`` into a full canonical reader.
:func:`gate_status` exists so a runner reports that blockage instead of quietly
publishing an option-(b) number as if it were the gate.

Pure stdlib plus the ``aphelion`` package itself. No model or network calls.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import tempfile
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


# ---------------------------------------------------------------------------
# Byte-level round trip, through the aphelion package's own public API
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ByteEquality:
    """Byte-level round-trip outcome over a set of sample directories.

    ``unpackable`` records the samples that could not be packed at all, with the
    Aphelion error code that rejected them. Those are the deliberately-invalid
    fixtures (an illegal lifecycle stream, a nested multi-package collision
    fixture); they are reported rather than silently skipped so the denominator
    stays auditable.
    """

    total: int
    identical: int
    mismatches: tuple[str, ...]
    unpackable: tuple[tuple[str, str], ...]

    @property
    def rate(self) -> float:
        """Fraction of packable samples that round-tripped byte-identically."""
        return self.identical / self.total if self.total else 0.0

    @property
    def all_identical(self) -> bool:
        return self.total > 0 and not self.mismatches


def package_digest(archive: Path) -> str:
    """SHA-256 of an archive's bytes, as lowercase hex."""
    return hashlib.sha256(archive.read_bytes()).hexdigest()


def roundtrip_digests(sample: Path, workdir: Path) -> tuple[str, str]:
    """Pack → unpack → re-pack one sample; return both archives' SHA-256s.

    Every step runs through the installed ``aphelion`` package's public API, so
    this measures the reference implementation's own canonical determinism (a
    prerequisite for M5, not the two-implementation gate itself — see the module
    docstring).
    """
    from aphelion.packer import pack
    from aphelion.unpacker import unpack

    workdir.mkdir(parents=True, exist_ok=True)
    first = Path(pack(sample, workdir / "first.aphelion.tar"))
    unpacked = unpack(first, workdir / "unpacked")
    second = Path(pack(unpacked, workdir / "second.aphelion.tar"))
    return package_digest(first), package_digest(second)


def roundtrip_is_byte_identical(sample: Path, workdir: Path) -> bool:
    """True iff packing, unpacking and re-packing ``sample`` reproduces its bytes."""
    first, second = roundtrip_digests(sample, workdir)
    return first == second


def independent_verdict(sample: Path, workdir: Path) -> str:
    """``"valid"`` / the Aphelion error code, via ``aphelion.verifier.verify_package``.

    Uses the package's own end-to-end verifier rather than a local re-check, so
    the verdict is the one the shipped tool would give.
    """
    from aphelion.errors import AphelionError
    from aphelion.packer import pack
    from aphelion.verifier import verify_package

    workdir.mkdir(parents=True, exist_ok=True)
    try:
        archive = Path(pack(sample, workdir / "verify.aphelion.tar"))
        verify_package(archive)
    except AphelionError as exc:
        return str(exc.code.value if hasattr(exc.code, "value") else exc.code)
    return "valid"


def byte_equality(samples_root: Path, workdir: Path | None = None) -> ByteEquality:
    """Byte-level round-trip over every sample that packs.

    ``workdir`` defaults to a temporary directory that is removed on return, so
    the check leaves nothing behind and never writes into ``samples/``.
    """
    if workdir is None:
        with tempfile.TemporaryDirectory() as tmp:
            return byte_equality(samples_root, Path(tmp))

    from aphelion.errors import AphelionError

    identical = 0
    mismatches: list[str] = []
    unpackable: list[tuple[str, str]] = []
    for index, sample in enumerate(_scored_samples(samples_root)):
        try:
            ok = roundtrip_is_byte_identical(sample, workdir / f"s{index:03d}")
        except AphelionError as exc:
            code = exc.code.value if hasattr(exc.code, "value") else exc.code
            unpackable.append((sample.name, str(code)))
            continue
        if ok:
            identical += 1
        else:
            mismatches.append(sample.name)

    return ByteEquality(
        total=identical + len(mismatches),
        identical=identical,
        mismatches=tuple(mismatches),
        unpackable=tuple(unpackable),
    )


# ---------------------------------------------------------------------------
# Gate status — the pinned M5 gate cannot be reported from this module
# ---------------------------------------------------------------------------

#: Why the pinned M5 gate cannot run yet. ``preregister.json`` pins option (a):
#: a second, fully independent canonical reader (``W-M5``). Until that lands in
#: ``scripts/external_reader.py``, the byte-level check here covers only the
#: reference implementation, so the gate is blocked — design doc §7.4 forbids
#: silently downgrading it to option (b).
GATE_BLOCKER = (
    "W-M5 not landed: scripts/external_reader.py reproduces the validator "
    "verdict only, not canonical bytes, so no second implementation exists to "
    "byte-compare against. preregister.json M5 pins option (a); design doc §7.4 "
    "records that M5 is blocked, not waived and not downgraded to option (b)."
)


@dataclass(frozen=True)
class GateStatus:
    """Whether the pinned M5 gate is runnable, and the evidence gathered so far."""

    runnable: bool
    blocker: str
    verdict_agreement: VerdictAgreement
    byte_equality: ByteEquality


def gate_status(samples_root: Path, workdir: Path | None = None) -> GateStatus:
    """Collect both M5 checks and report the pinned gate as **not** runnable.

    Returning a status object rather than a bare pass/fail keeps a runner from
    publishing the option-(b) numbers as if they were the pinned option-(a) gate.
    """
    return GateStatus(
        runnable=False,
        blocker=GATE_BLOCKER,
        verdict_agreement=roundtrip_agreement(samples_root),
        byte_equality=byte_equality(samples_root, workdir),
    )
