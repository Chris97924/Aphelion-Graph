"""M1 — QA accuracy on knowledge-update, and the pre-registered ``C − B`` gate.

M1 is the metric the whole G2 kill-gate points at: does the claim-semantics
machinery convert into *answers*? ``preregister.json`` pins it as
``C − B >= +3pp on knowledge-update`` at ``N = 78``, reported "directional,
bootstrapped CI, C-A secondary".

**This module runs no model.** The answering and judge models are pinned
(design doc §5.2) but reaching them is the operator's job, exactly as everywhere
else in this harness: :func:`run_m1` scores through
:func:`~benchmarks.longmemeval.pipeline.score_blind`, so an unpinned judge
raises :class:`~benchmarks.longmemeval.pipeline.UnpinnedStageError` naming the
stage to bind, while an injected offline judge makes the whole path runnable
without a socket. :func:`score_m1` goes further and takes verdicts that have
*already* been produced, so the arithmetic can be checked with no stage at all.

**Nothing here re-declares a threshold.** ``+3pp``, the two arms of the primary
contrast, the secondary contrast, and ``N = 78`` are parsed out of
``preregister.json`` by :func:`pinned_gate`; a pin this parser cannot read
raises :class:`~benchmarks.longmemeval.pipeline.GatePinError` rather than
falling back to a constant, because a constant in this file would let the frozen
gate and the code enforcing it drift apart (design doc §6.1 guard 3).

**Underpowered by design, and it says so.** Design doc §3.3 is blunt: at
``N = 78`` a +3pp difference is ≈ 2.3 questions and M1 must be "reported with a
bootstrapped confidence interval and read as *directional*". So
:meth:`M1Report.gate_verdict` refuses outright at any other ``N`` — a five-question
smoke must not be able to emit a pass/fail against a gate pinned at 78 — and the
report always carries the CI alongside the point estimate.

Pure stdlib. No model or network calls.
"""

from __future__ import annotations

import random
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from benchmarks.longmemeval.metrics._stats import percentile
from benchmarks.longmemeval.pipeline import (
    PREREGISTER_PATH,
    ArmResult,
    GatePinError,
    Judge,
    MissingArmError,
    PipelineConfig,
    QAItem,
    pinned_seed,
    preregistered_metric,
    score_blind,
)

__all__ = [
    "BOOTSTRAP_RESAMPLES",
    "CI_LEVEL",
    "ArmAccuracy",
    "ArmContrast",
    "ConfidenceInterval",
    "GatePinError",
    "M1Gate",
    "M1Report",
    "MissingArmError",
    "UnderpoweredSampleError",
    "bootstrap_delta_ci",
    "pinned_gate",
    "run_m1",
    "score_m1",
]

# Design doc §3.3 names a 95% interval ("a Wilson 95% CI at N = 78 is roughly
# ±11pp") and §4 requires a *bootstrapped* one; 95% is therefore the doc's own
# level, not a knob invented here.
CI_LEVEL = 0.95

# Resample count. Unlike the gate threshold this is a reporting knob, not a
# pinned value: it trades interval jitter for runtime and cannot move a verdict,
# only the width of the interval reported beside it. 10,000 is the conventional
# default at which percentile-bootstrap bounds are stable to well under a
# tenth of a percentage point.
BOOTSTRAP_RESAMPLES = 10_000

# ``C-B >= +3pp on knowledge-update`` — arms, direction, threshold.
_GATE_RE = re.compile(
    r"^\s*([A-Z])\s*-\s*([A-Z])\s*>=\s*\+?\s*(\d+(?:\.\d+)?)\s*pp\b",
    re.IGNORECASE,
)

# ``directional, bootstrapped CI, C-A secondary`` — the secondary contrast.
_SECONDARY_RE = re.compile(r"([A-Z])\s*-\s*([A-Z])\s+secondary", re.IGNORECASE)


class UnderpoweredSampleError(ValueError):
    """A gate verdict was read at an ``N`` the pre-registration does not pin.

    Design doc §3.3 fixes M1's denominator at the full 78-question
    knowledge-update pool and §8 gives that branch a deliberate two-round rule
    *because* the metric is underpowered even at 78. A verdict computed over a
    smaller slice — a smoke, a debugging subset — is not the pinned gate, and
    emitting one anyway is how a plumbing number ends up quoted as a result.
    """


@dataclass(frozen=True)
class M1Gate:
    """The pinned M1 gate, as read from ``preregister.json``."""

    treatment_arm: str
    control_arm: str
    threshold_pp: float
    n: int
    secondary_control_arm: str | None
    source: str

    def passes(self, delta_pp: float) -> bool:
        """``C − B >= +3pp``, evaluated against the pinned threshold."""
        return delta_pp >= self.threshold_pp


def pinned_gate(path: Path = PREREGISTER_PATH) -> M1Gate:
    """Parse M1's frozen gate out of the pre-registration.

    Raises :class:`~benchmarks.longmemeval.pipeline.GatePinError` when the pinned
    text is not the shape this metric knows how to enforce — the pin may have
    been amended, and enforcing a stale reading of it would be worse than
    stopping.
    """
    record = preregistered_metric("M1", path)
    gate_text = str(record.get("gate", ""))
    match = _GATE_RE.match(gate_text)
    if match is None:
        raise GatePinError(
            f"{path}: pinned M1 gate {gate_text!r} is not of the form "
            "'<treatment>-<control> >= +<N>pp ...'. This metric enforces that "
            "shape and will not guess a threshold; re-read the pin (design doc "
            "§4) and update the parser deliberately."
        )

    n = record.get("N")
    if isinstance(n, bool) or not isinstance(n, int):
        raise GatePinError(
            f"{path}: pinned M1 'N' must be an int, got {n!r}. M1's denominator "
            "is the knowledge-update pool size (design doc §3.3)."
        )

    secondary = _SECONDARY_RE.search(str(record.get("reporting", "")))
    treatment, control, threshold = match.groups()
    return M1Gate(
        treatment_arm=treatment.upper(),
        control_arm=control.upper(),
        threshold_pp=float(threshold),
        n=n,
        secondary_control_arm=secondary.group(2).upper() if secondary else None,
        source=gate_text,
    )


@dataclass(frozen=True)
class ArmAccuracy:
    """One arm's QA accuracy over the scored subset."""

    arm: str
    correct: int
    total: int

    @property
    def accuracy(self) -> float:
        return self.correct / self.total if self.total else 0.0

    def as_record(self) -> dict[str, Any]:
        return {"correct": self.correct, "total": self.total, "accuracy": self.accuracy}


@dataclass(frozen=True)
class ConfidenceInterval:
    """A percentile-bootstrap interval on a difference, in percentage points."""

    low: float
    high: float
    level: float
    resamples: int

    def as_record(self) -> dict[str, Any]:
        return {
            "low": self.low,
            "high": self.high,
            "level": self.level,
            "resamples": self.resamples,
        }


@dataclass(frozen=True)
class ArmContrast:
    """A treatment-minus-control accuracy difference, with its interval."""

    treatment_arm: str
    control_arm: str
    delta_pp: float
    ci: ConfidenceInterval

    def as_record(self) -> dict[str, Any]:
        return {
            "treatment": self.treatment_arm,
            "control": self.control_arm,
            "delta_pp": self.delta_pp,
            "ci": self.ci.as_record(),
        }


def bootstrap_delta_ci(
    treatment: Sequence[bool],
    control: Sequence[bool],
    *,
    seed: int,
    resamples: int = BOOTSTRAP_RESAMPLES,
    level: float = CI_LEVEL,
) -> ConfidenceInterval:
    """Percentile-bootstrap CI on ``treatment − control`` accuracy, in pp.

    The resample is **paired**: one set of question indices is drawn per replicate
    and applied to both arms. That is the correct design here because every arm
    answers the same questions under the same retriever and models — the only
    difference is the memory layer — so an unpaired bootstrap would inflate the
    interval with between-question variance the comparison already controls for.

    Deterministic under ``seed``: the same verdicts and seed reproduce the same
    bounds, so a published interval can be recomputed from the results file.
    """
    if len(treatment) != len(control):
        raise ValueError(
            f"paired bootstrap needs equal-length arms; got {len(treatment)} and "
            f"{len(control)}"
        )
    if resamples < 1:
        raise ValueError(f"resamples must be positive, got {resamples}")

    n = len(treatment)
    if n == 0:
        return ConfidenceInterval(low=0.0, high=0.0, level=level, resamples=resamples)

    rng = random.Random(seed)
    indices = range(n)
    deltas: list[float] = []
    for _ in range(resamples):
        drawn = [rng.choice(indices) for _ in range(n)]
        hits = sum(treatment[i] for i in drawn) - sum(control[i] for i in drawn)
        deltas.append(100.0 * hits / n)

    tail = (1.0 - level) / 2.0
    return ConfidenceInterval(
        low=percentile(deltas, tail),
        high=percentile(deltas, 1.0 - tail),
        level=level,
        resamples=resamples,
    )


@dataclass(frozen=True)
class M1Report:
    """M1's accuracies, contrasts and gate standing over one scored subset."""

    gate: M1Gate
    accuracies: dict[str, ArmAccuracy]
    primary: ArmContrast
    secondary: ArmContrast | None
    n: int

    @property
    def n_matches_pin(self) -> bool:
        """True only at the pinned denominator — the gate's precondition."""
        return self.n == self.gate.n

    def gate_verdict(self) -> bool:
        """The pinned ``C − B >= +3pp`` verdict. Refuses at any other ``N``."""
        if not self.n_matches_pin:
            raise UnderpoweredSampleError(
                f"M1's gate is pinned at N={self.gate.n} (the full knowledge-update "
                f"pool, design doc §3.3) but this report covers N={self.n}. A "
                "verdict from a different denominator is not the pre-registered "
                "gate; report the accuracies and the CI instead."
            )
        return self.gate.passes(self.primary.delta_pp)

    def as_record(self) -> dict[str, Any]:
        """The report as a results-row fragment.

        ``gate_verdict`` is ``None`` rather than absent when the denominator is
        not the pinned one, so a reader can tell "no verdict, underpowered" from
        a row where the field was simply never written.
        """
        return {
            "gate": self.gate.source,
            "n": self.n,
            "n_matches_pin": self.n_matches_pin,
            "accuracy": {
                arm: score.accuracy for arm, score in sorted(self.accuracies.items())
            },
            "correct": {
                arm: score.correct for arm, score in sorted(self.accuracies.items())
            },
            "primary": self.primary.as_record(),
            "secondary": self.secondary.as_record() if self.secondary else None,
            "gate_verdict": self.gate_verdict() if self.n_matches_pin else None,
        }


def _verdicts(
    scored: Mapping[str, ArmResult], arm: str, subset: Sequence[int] | None
) -> list[bool]:
    if arm not in scored:
        raise MissingArmError(
            f"M1's pinned gate names arm {arm!r}, which is absent from the scored "
            f"results {sorted(scored)}. Every §4 gate is a comparison; scoring one "
            "without an arm it names would contrast against nothing."
        )
    marks = scored[arm].verdicts
    if subset is None:
        return list(marks)
    return [marks[index] for index in subset]


def score_m1(
    scored: Mapping[str, ArmResult],
    *,
    subset: Sequence[int] | None = None,
    seed: int | None = None,
    resamples: int = BOOTSTRAP_RESAMPLES,
    level: float = CI_LEVEL,
    path: Path = PREREGISTER_PATH,
) -> M1Report:
    """Score M1 from verdicts the blind phase has already produced.

    ``subset`` selects the question indices M1 is defined over — the
    knowledge-update slice — because a run may answer a wider set (multi-session,
    adversarial) that M1's pinned denominator excludes. ``seed`` defaults to the
    pre-registered seed, so the bootstrap is reproducible against the pin rather
    than against a constant in this file.
    """
    gate = pinned_gate(path)
    resolved_seed = pinned_seed(path) if seed is None else seed

    arms = [gate.treatment_arm, gate.control_arm]
    if gate.secondary_control_arm is not None:
        arms.append(gate.secondary_control_arm)

    marks = {arm: _verdicts(scored, arm, subset) for arm in dict.fromkeys(arms)}
    treatment = marks[gate.treatment_arm]

    def contrast(control_arm: str) -> ArmContrast:
        control = marks[control_arm]
        n = len(treatment)
        delta = 100.0 * (sum(treatment) - sum(control)) / n if n else 0.0
        return ArmContrast(
            treatment_arm=gate.treatment_arm,
            control_arm=control_arm,
            delta_pp=delta,
            ci=bootstrap_delta_ci(
                treatment,
                control,
                seed=resolved_seed,
                resamples=resamples,
                level=level,
            ),
        )

    return M1Report(
        gate=gate,
        accuracies={
            arm: ArmAccuracy(arm=arm, correct=sum(row), total=len(row))
            for arm, row in sorted(marks.items())
        },
        primary=contrast(gate.control_arm),
        secondary=(
            contrast(gate.secondary_control_arm)
            if gate.secondary_control_arm is not None
            else None
        ),
        n=len(treatment),
    )


def run_m1(
    results: Mapping[str, ArmResult],
    questions: Sequence[QAItem],
    *,
    config: PipelineConfig,
    judge: Judge | None = None,
    seed: int | None = None,
    subset: Sequence[int] | None = None,
    resamples: int = BOOTSTRAP_RESAMPLES,
    level: float = CI_LEVEL,
    path: Path = PREREGISTER_PATH,
) -> M1Report:
    """Judge every arm in one blind batch, then score M1 over the result.

    This is the whole M1 execution layer: it owns no model and no prompt. The
    judge is reached through ``config`` — so an unpinned judge stage raises
    :class:`~benchmarks.longmemeval.pipeline.UnpinnedStageError` naming exactly
    what to bind — and ``judge=`` overrides only the callable, for a
    deterministic offline stage.
    """
    return score_m1(
        score_blind(results, questions, config=config, judge=judge, seed=seed),
        subset=subset,
        seed=seed,
        resamples=resamples,
        level=level,
        path=path,
    )
