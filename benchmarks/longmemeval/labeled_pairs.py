"""M2's labeled duplicate ground truth, partitioned by lineage.

Design doc §4 defines M2 as **exact-duplicate detection**, scored as pairwise
F1 over a labeled duplicate set "drawn from exact restatements across *both*
subsets" (§3.3). The doc fixes *what* a labeled duplicate is — an exact
restatement — but not the mechanical derivation, so this module pins one:

**Derivation (chosen here, conservative and deterministic).** Two claims are a
labeled duplicate pair iff their bodies are byte-equal after the trivial
whitespace normalisation of design doc §2.2 — strip the ends, collapse internal
runs to a single space (:func:`~benchmarks.longmemeval.arms.naive_dedup.normalize_body`).
Nothing else: no case folding, no Unicode normalisation, no punctuation
stripping, no similarity threshold, and no seeded sampling — the rule is total
over the corpus, so there is no sample to seed and re-running it on the same
claims reproduces the same set exactly. Anything looser would need a
near-duplicate judgement the pre-registration does not license, and would score
Arm C's lineage-gated coalescing against a ground truth built from a *different*
notion of identity than the one under test.

**The tautology, stated rather than hidden.** This is by construction the rule
Arm B implements, so Arm B scores F1 = 1.0 on it. That is not an accident and
not a flaw: design doc §2.2 defines Arm B *as* exact-string dedup and §4's M2
gate is written knowing it — the gate asks whether C clears A by 0.10 and does
not regress below B by more than ε, i.e. whether the machinery at least matches
the three-line control. A ground truth that let C beat B on exact duplicates
would have to be a *semantic* duplicate set, which is a different metric than
the one pinned.

**Why the lineage partition exists.** M2's 2026-07-19 annotation is explicit:
under the §2.3 lineage-gated coalescing rule, cross-lineage byte-identical
duplicates that Arm B collapses will **not** coalesce in Arm C, so a
``C.F1 < B.F1 − ε`` deficit is no longer automatically an identity-projection
bug. The §8 M2-fail diagnosis *MUST* first check whether the deficit is entirely
attributable to those pairs — a linker lineage-fragmentation artifact — before
concluding the projection is at fault. That check is
:func:`cross_lineage_attribution`, and it needs the ground truth to carry the
within/cross-lineage split, which is why it is computed here rather than
recovered afterwards from arm outputs that no longer know the lineages.

Pure stdlib. No model or network calls.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from benchmarks.longmemeval.arms.naive_dedup import normalize_body
from benchmarks.longmemeval.metrics.m2_dedup import cluster_pairs
from benchmarks.longmemeval.pipeline import Claim

# Recorded on every derived set so a results file documents the rule it was
# scored under, instead of leaving it to be reconstructed from this docstring.
DERIVATION = (
    "exact restatement: claim bodies byte-equal after leading/trailing strip and "
    "internal whitespace-run collapse (design doc §2.2 normalisation); total over "
    "the claim set, no sampling, no similarity threshold"
)


@dataclass(frozen=True)
class LabeledPairSet:
    """M2's ground truth ``T``, split by whether a pair shares a lineage.

    ``pairs`` is what M2's F1 is scored against. ``within_lineage`` is the part
    Arm C's lineage-gated rule *can* coalesce; ``cross_lineage`` is the part it
    structurally cannot, and the two partition ``pairs`` exactly.
    """

    pairs: frozenset[frozenset]
    within_lineage: frozenset[frozenset]
    cross_lineage: frozenset[frozenset]
    derivation: str = DERIVATION

    def as_record(self) -> dict[str, int]:
        """Pair counts as a results-row fragment."""
        return {
            "total": len(self.pairs),
            "within_lineage": len(self.within_lineage),
            "cross_lineage": len(self.cross_lineage),
        }


def _lineage_of(claim: Claim) -> str:
    value = claim.metadata.get("claim_id")
    if not isinstance(value, str) or not value:
        raise ValueError(
            f"labeled-pair derivation needs a lineage: claim {claim.id!r} carries "
            f"claim_id {value!r}. The within/cross-lineage partition is what makes "
            "the §8 M2-fail diagnosis possible, so an unlineaged claim is refused "
            "rather than silently counted as its own lineage."
        )
    return value


def labeled_pairs_from_claims(claims: Iterable[Claim]) -> LabeledPairSet:
    """Derive M2's labeled duplicate set from linked claims.

    Groups claim *record ids* by normalised body (the derivation above), expands
    each group to its unordered pairs, and splits those pairs on whether both
    members carry the same ``claim_id``.
    """
    ids_by_body: dict[str, list[str]] = {}
    lineage_by_id: dict[str, str] = {}
    for claim in claims:
        lineage_by_id[claim.id] = _lineage_of(claim)
        ids_by_body.setdefault(normalize_body(claim.text), []).append(claim.id)

    pairs = cluster_pairs(ids_by_body.values())
    within = frozenset(
        pair for pair in pairs if len({lineage_by_id[member] for member in pair}) == 1
    )
    return LabeledPairSet(
        pairs=frozenset(pairs),
        within_lineage=within,
        cross_lineage=frozenset(pairs) - within,
    )


@dataclass(frozen=True)
class LineageAttribution:
    """Whether an M2 deficit is a fragmentation artifact or a projection bug.

    ``missed`` is what the control caught and the treatment arm did not.
    ``fully_attributable`` is the §8 first check: true only when there *is* a
    deficit and every missed pair is cross-lineage, i.e. the annotation's
    "linker lineage-fragmentation artifact" fully explains it. An empty deficit
    is deliberately **not** attributable — there is nothing to excuse, and a flag
    that read as "excused" on a passing arm would be worse than no flag.
    """

    missed: frozenset[frozenset]
    within_lineage_missed: frozenset[frozenset]
    cross_lineage_missed: frozenset[frozenset]
    fully_attributable: bool

    def as_record(self) -> dict[str, object]:
        """The attribution as a results-row fragment."""
        return {
            "missed": len(self.missed),
            "within_lineage_missed": len(self.within_lineage_missed),
            "cross_lineage_missed": len(self.cross_lineage_missed),
            "fully_attributable": self.fully_attributable,
        }


def cross_lineage_attribution(
    labeled: LabeledPairSet,
    *,
    control_pairs: Iterable[Iterable[object]],
    treatment_pairs: Iterable[Iterable[object]],
) -> LineageAttribution:
    """Run M2's §8 first check on a treatment-vs-control deficit.

    ``control_pairs`` are the duplicate pairs the control arm (B) predicted and
    ``treatment_pairs`` those the treatment arm (C) predicted. Only *labeled*
    pairs count: a pair neither arm should have merged is a precision question,
    not a deficit.

    A ``fully_attributable`` result means the annotation's escape hatch applies —
    the deficit is lineage fragmentation upstream in the linker, not an identity
    projection that over- or under-merges — and the §8 projection recheck should
    **not** be the first move. Anything else leaves the §8 diagnosis standing.
    """
    control = {frozenset(pair) for pair in control_pairs} & labeled.pairs
    treatment = {frozenset(pair) for pair in treatment_pairs} & labeled.pairs
    missed = control - treatment
    within_missed = missed & labeled.within_lineage
    return LineageAttribution(
        missed=frozenset(missed),
        within_lineage_missed=frozenset(within_missed),
        cross_lineage_missed=frozenset(missed & labeled.cross_lineage),
        fully_attributable=bool(missed) and not within_missed,
    )
