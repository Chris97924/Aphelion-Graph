"""M4 — storage / latency sanity, with a non-gating 10× tripwire.

``preregister.json`` pins M4 as ``gate: none (sanity-only)`` with a soft
``tripwire: 10x Arm A``, and design doc §4 says why: "Aphelion trades
storage/compute for correctness; this benchmark judges correctness, so M4 is
context, not a gate. Report p50/p95 query latency and on-disk bytes/claim, and
flag only pathological >10× A regressions."

So this module **reports and flags; it never fails a run.** :meth:`M4Report.flags`
returns what breached the tripwire and nothing raises on a breach. The one thing
it *does* refuse is a drifted pin: :func:`pinned_tripwire` re-reads
``preregister.json`` every call and raises
:class:`~benchmarks.longmemeval.pipeline.GatePinError` if M4 ever stops declaring
"none" as its gate, so a newly-pinned gate cannot be silently ignored by code
written when there wasn't one.

**Determinism and the clock.** Wall-clock latency is not reproducible, and this
harness's results files are required to be byte-identical across runs. The clock
is therefore an injection point exactly like the model stages are:
:func:`measure_arm` takes ``clock=``, defaulting to :func:`time.perf_counter` for
a real run, and :class:`CountingClock` gives an offline smoke a deterministic
stand-in whose numbers are plumbing evidence rather than a measurement.

**Storage.** ``bytes/claim`` is measured through an injectable ``sizer``. The
default, :func:`canonical_claim_bytes`, is the canonical-JSON size of a retained
claim — arm-fair (identical claims measure identically, so the difference between
arms is retention policy, which is what M4 is asking about) and available offline.
A run that has actually packaged its claims to disk should pass a sizer that
measures the package instead.

Pure stdlib. No model or network calls.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol, Sequence, runtime_checkable

from benchmarks.longmemeval.metrics._stats import percentile
from benchmarks.longmemeval.pipeline import (
    PREREGISTER_PATH,
    Claim,
    GatePinError,
    MissingArmError,
    preregistered_metric,
)

__all__ = [
    "ArmPerf",
    "CountingClock",
    "GatePinError",
    "M4Report",
    "M4Tripwire",
    "MissingArmError",
    "TripwireFlag",
    "canonical_claim_bytes",
    "measure_arm",
    "measure_arms",
    "percentile",
    "pinned_tripwire",
]

# The two reported measures the tripwire is evaluated over: the latency tail and
# the storage cost. p50 is reported for context but not tripped on — a median
# regression that leaves the tail alone is not the pathological case §4 names.
TRIPWIRE_MEASURES: tuple[str, ...] = ("p95_ms", "bytes_per_claim")

# ``10x Arm A`` — the soft tripwire's factor and the arm it is relative to.
_TRIPWIRE_RE = re.compile(r"(\d+(?:\.\d+)?)\s*[x×]\s*Arm\s+([A-Z])", re.IGNORECASE)

# M4's pinned gate must keep declaring that it has none.
_NO_GATE_RE = re.compile(r"^\s*none\b", re.IGNORECASE)


class CountingClock:
    """A deterministic stand-in for :func:`time.perf_counter`.

    Each call advances by a fixed step, so a measured interval is exactly
    ``step_seconds`` and a run built on it is byte-identical across executions.
    It measures nothing real — that is the point: it keeps an offline smoke's
    output reproducible while making the absence of a real measurement obvious
    in the caveat that travels with the numbers.
    """

    def __init__(self, step_seconds: float = 1.0) -> None:
        self.step_seconds = step_seconds
        self._ticks = 0

    def __call__(self) -> float:
        now = self._ticks * self.step_seconds
        self._ticks += 1
        return now


@runtime_checkable
class RetrievingStore(Protocol):
    """A memory store M4 can time and size."""

    @property
    def claims(self) -> list[Claim]: ...

    def retrieve(self, question: str) -> Sequence[Claim]: ...


@dataclass(frozen=True)
class M4Tripwire:
    """M4's pinned soft tripwire: ``factor`` × the reference arm.

    ``gating`` is always ``False`` while the pre-registration keeps M4 at
    "sanity-only"; it is carried explicitly so a results row states the metric's
    standing rather than leaving a reader to remember it.
    """

    factor: float
    reference_arm: str
    gating: bool
    source: str

    def breaches(self, value: float, reference_value: float) -> bool:
        """True when ``value`` exceeds ``factor`` × the reference arm's value."""
        return value > self.factor * reference_value


def pinned_tripwire(path: Path = PREREGISTER_PATH) -> M4Tripwire:
    """Parse M4's pinned gate and tripwire out of the pre-registration."""
    record = preregistered_metric("M4", path)

    gate_text = str(record.get("gate", ""))
    if not _NO_GATE_RE.match(gate_text):
        raise GatePinError(
            f"{path}: pinned M4 gate is {gate_text!r}, but this metric implements "
            "M4 as sanity-only ('none') per design doc §4 and reports rather than "
            "fails. A real gate has been pinned since — enforce it deliberately "
            "instead of letting this module report a breach as advisory."
        )

    tripwire_text = str(record.get("tripwire", ""))
    match = _TRIPWIRE_RE.search(tripwire_text)
    if match is None:
        raise GatePinError(
            f"{path}: pinned M4 tripwire {tripwire_text!r} is not of the form "
            "'<factor>x Arm <arm>'. This metric will not guess a factor or a "
            "reference arm."
        )

    factor, reference = match.groups()
    return M4Tripwire(
        factor=float(factor),
        reference_arm=reference.upper(),
        gating=False,
        source=tripwire_text,
    )


@dataclass(frozen=True)
class ArmPerf:
    """One arm's latency and storage profile."""

    arm: str
    p50_ms: float
    p95_ms: float
    num_queries: int
    num_claims: int
    storage_bytes: int
    bytes_per_claim: float

    def measure(self, name: str) -> float:
        if name not in TRIPWIRE_MEASURES:
            raise ValueError(
                f"unknown tripwire measure {name!r}; expected one of "
                f"{TRIPWIRE_MEASURES}"
            )
        return float(getattr(self, name))

    def as_record(self) -> dict[str, Any]:
        return {
            "p50_ms": self.p50_ms,
            "p95_ms": self.p95_ms,
            "num_queries": self.num_queries,
            "num_claims": self.num_claims,
            "storage_bytes": self.storage_bytes,
            "bytes_per_claim": self.bytes_per_claim,
        }


@dataclass(frozen=True)
class TripwireFlag:
    """One measure on one arm that exceeded the tripwire. Advisory only."""

    arm: str
    measure: str
    value: float
    reference_value: float
    factor: float

    def as_record(self) -> dict[str, Any]:
        return {
            "arm": self.arm,
            "measure": self.measure,
            "value": self.value,
            "reference_value": self.reference_value,
            "factor": self.factor,
        }


def canonical_claim_bytes(claim: Claim) -> int:
    """The canonical-JSON byte size of one retained claim.

    Sorted keys and UTF-8, so the same claim measures the same everywhere and
    two arms differ only where their *retention* differs — which is what M4 is
    asking about. This is the offline stand-in for "on-disk bytes/claim"; a run
    that has packaged its claims should inject a sizer that measures the package.
    """
    payload = {"id": claim.id, "text": claim.text, "metadata": claim.metadata}
    return len(
        json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")
    )


def measure_arm(
    arm: str,
    store: RetrievingStore,
    questions: Mapping[str, str],
    *,
    top_k: int,
    clock: Callable[[], float] = time.perf_counter,
    sizer: Callable[[Claim], int] = canonical_claim_bytes,
) -> ArmPerf:
    """Time one arm's retrievals and size its retained claims.

    The timed span is ``store.retrieve(question)[:top_k]`` — the same slice the
    answering model would be handed, so the latency reported is the latency the
    pipeline actually pays. Questions are visited in sorted id order so the
    measurement is order-stable.
    """
    latencies_ms: list[float] = []
    for qid in sorted(questions):
        start = clock()
        # The slice is the measured work, not a value this function needs: M4
        # times what the pipeline pays to produce the answering context.
        _ = store.retrieve(questions[qid])[:top_k]
        latencies_ms.append((clock() - start) * 1000.0)

    claims = list(store.claims)
    storage_bytes = sum(sizer(claim) for claim in claims)
    return ArmPerf(
        arm=arm,
        p50_ms=percentile(latencies_ms, 0.50) if latencies_ms else 0.0,
        p95_ms=percentile(latencies_ms, 0.95) if latencies_ms else 0.0,
        num_queries=len(latencies_ms),
        num_claims=len(claims),
        storage_bytes=storage_bytes,
        bytes_per_claim=storage_bytes / len(claims) if claims else 0.0,
    )


@dataclass(frozen=True)
class M4Report:
    """Every arm's profile, plus whatever breached the advisory tripwire."""

    tripwire: M4Tripwire
    arms: dict[str, ArmPerf]

    @property
    def flags(self) -> tuple[TripwireFlag, ...]:
        """Advisory breaches, sorted by ``(arm, measure)``. Never raises on one."""
        reference = self.arms.get(self.tripwire.reference_arm)
        if reference is None:
            raise MissingArmError(
                f"M4's pinned tripwire is relative to arm "
                f"{self.tripwire.reference_arm!r}, which is absent from "
                f"{sorted(self.arms)}. A ratio against a missing baseline is not a "
                "sanity check."
            )

        breaches = [
            TripwireFlag(
                arm=arm,
                measure=measure,
                value=perf.measure(measure),
                reference_value=reference.measure(measure),
                factor=self.tripwire.factor,
            )
            for arm, perf in sorted(self.arms.items())
            if arm != self.tripwire.reference_arm
            for measure in TRIPWIRE_MEASURES
            if self.tripwire.breaches(perf.measure(measure), reference.measure(measure))
        ]
        return tuple(breaches)

    def as_record(self) -> dict[str, Any]:
        """The report as a results-row fragment."""
        by_arm = sorted(self.arms.items())
        return {
            "tripwire": self.tripwire.source,
            "tripwire_factor": self.tripwire.factor,
            "tripwire_reference_arm": self.tripwire.reference_arm,
            "gating": self.tripwire.gating,
            "p50_ms": {arm: perf.p50_ms for arm, perf in by_arm},
            "p95_ms": {arm: perf.p95_ms for arm, perf in by_arm},
            "bytes_per_claim": {arm: perf.bytes_per_claim for arm, perf in by_arm},
            "num_claims": {arm: perf.num_claims for arm, perf in by_arm},
            "tripwire_flags": [flag.as_record() for flag in self.flags],
        }


def measure_arms(
    stores: Mapping[str, RetrievingStore],
    questions: Mapping[str, str],
    *,
    top_k: int,
    clock_factory: Callable[[], Callable[[], float]] | None = None,
    sizer: Callable[[Claim], int] = canonical_claim_bytes,
    path: Path = PREREGISTER_PATH,
) -> M4Report:
    """Profile every arm over one shared question set.

    ``clock_factory`` builds a **fresh** clock per arm, so one arm's timings
    cannot leak into the next through a shared counter; it defaults to handing
    every arm :func:`time.perf_counter`.
    """
    make_clock = clock_factory or (lambda: time.perf_counter)
    return M4Report(
        tripwire=pinned_tripwire(path),
        arms={
            arm: measure_arm(
                arm,
                store,
                questions,
                top_k=top_k,
                clock=make_clock(),
                sizer=sizer,
            )
            for arm, store in stores.items()
        },
    )
