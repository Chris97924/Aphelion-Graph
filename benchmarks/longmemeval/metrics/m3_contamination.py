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
from typing import Iterable, Mapping, Protocol, Sequence, runtime_checkable


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


# ---------------------------------------------------------------------------
# Store bridge — building the retrieved contexts an arm actually surfaces
# ---------------------------------------------------------------------------


@runtime_checkable
class TextRecord(Protocol):
    """Anything with a ``text`` body — the harness ``Claim`` satisfies this."""

    text: str


@runtime_checkable
class RetrievingStore(Protocol):
    """A memory store that can answer a question with ranked claims."""

    def retrieve(self, question: str) -> Sequence[TextRecord]: ...


def contexts_from_store(
    store: RetrievingStore,
    questions: Mapping[str, str],
    *,
    top_k: int,
) -> dict[str, list[str]]:
    """Retrieve each question's top-``k`` context strings from one arm's store.

    ``questions`` maps ``question_id`` → question text; the result is keyed the
    same way and feeds straight into :func:`contamination_rate`. The ``top_k``
    slice is the *same* context the answering model would see, which is what M3
    is defined over — the metric asks whether a stale value reaches the model,
    not whether it merely survives in the store.
    """
    return {
        qid: [record.text for record in store.retrieve(question)[:top_k]]
        for qid, question in questions.items()
    }


def score_stores(
    questions: Mapping[str, str],
    old_value_labels: Mapping[str, Sequence[str]],
    stores: Mapping[str, RetrievingStore],
    *,
    top_k: int,
) -> dict[str, ContaminationScore]:
    """Contamination score per arm over one shared question set.

    Returns ``{arm label: ContaminationScore}``. Every arm is retrieved with the
    same questions, labels and ``top_k``, so the M3 gate's ``C <= 0.5 * A``
    comparison comes from a like-for-like measurement.
    """
    return {
        arm: contamination_rate(
            contexts_from_store(store, questions, top_k=top_k), old_value_labels
        )
        for arm, store in stores.items()
    }
