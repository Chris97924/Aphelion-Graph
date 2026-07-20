"""M3 — knowledge-update contamination rate.

A knowledge-update question has a value that changed over time: an *old*
(superseded) value and a *current* one. A memory layer is "contaminated" for a
question when the context it retrieves still surfaces the old value — the failure
mode a good memory layer is supposed to prevent by superseding stale claims.

The metric is a rate over questions::

    contamination_rate = (# questions whose retrieved context shows an old value)
                         / (# questions)

A question counts as contaminated when *any* of its retrieved context strings
contains *any* of that question's labeled old values, by case-sensitive substring
match. Substring matching is deliberately simple and mechanical for this skeleton;
token-boundary / normalization refinements are left to the execution drive. The
denominator is the knowledge-update set the caller passes in (``preregister.json``
M3 pins N=78 with the knowledge-update denominator); this module scores exactly
the questions it is given.

The gate that consumes this (M3) is ``C <= 0.5 * A``. This module only computes
the rate; the gate comparison lives with the execution drive.

Pure stdlib. No model or network calls.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Mapping, Sequence


@dataclass(frozen=True)
class ContaminationScore:
    """Contamination outcome over a question set.

    ``contaminated_ids`` lists the offending question ids (sorted) so a caller can
    inspect *which* questions leaked an old value, not just how many.
    """

    rate: float
    contaminated: int
    total: int
    contaminated_ids: tuple[str, ...]


def context_is_contaminated(
    contexts: Iterable[str], old_values: Iterable[str]
) -> bool:
    """True iff any context string contains any (non-empty) old value.

    Case-sensitive substring match. Empty old-value strings are ignored so a
    blank label can never mark every question contaminated.
    """
    olds = [value for value in old_values if value]
    if not olds:
        return False
    return any(any(old in context for old in olds) for context in contexts)


def contamination_rate(
    retrieved_contexts: Mapping[str, Sequence[str]],
    old_value_labels: Mapping[str, Sequence[str]],
) -> ContaminationScore:
    """Fraction of questions whose retrieved context surfaces an old value.

    ``retrieved_contexts`` maps ``question_id`` → the retrieved context strings;
    it defines the denominator (one entry per scored question). ``old_value_labels``
    maps ``question_id`` → the superseded values for that question; a question with
    no entry (or an empty list) can never be contaminated. Questions are visited in
    sorted id order so ``contaminated_ids`` is deterministic.
    """
    contaminated_ids: list[str] = []
    for qid in sorted(retrieved_contexts):
        contexts = retrieved_contexts[qid]
        olds = old_value_labels.get(qid, ())
        if context_is_contaminated(contexts, olds):
            contaminated_ids.append(qid)

    total = len(retrieved_contexts)
    contaminated = len(contaminated_ids)
    rate = contaminated / total if total else 0.0
    return ContaminationScore(
        rate=rate,
        contaminated=contaminated,
        total=total,
        contaminated_ids=tuple(contaminated_ids),
    )
