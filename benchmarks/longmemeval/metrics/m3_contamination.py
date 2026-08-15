r"""M3 — knowledge-update contamination rate.

A knowledge-update question has a value that changed over time: an *old*
(superseded) value and a *current* one. A memory layer is "contaminated" for a
question when the context it retrieves still surfaces the old value — the failure
mode a good memory layer is supposed to prevent by superseding stale claims.

The metric is a rate over questions::

    contamination_rate = (# questions whose retrieved context shows an old value)
                         / (# questions)

A question counts as contaminated when *any* of its retrieved context strings
contains *any* of that question's labeled old values, matched at **token
boundaries** and **case-sensitively** — the rule pinned on 2026-08-15
(``preregister.json`` ``metrics.M3.matching``)::

    (?<!\w) re.escape(value) (?!\w)

Raw substring matching was the skeleton's rule and is now pinned out, because it
is not conservative — it is *systematically wrong* on this label set. 23 of the
70 labels are four characters or shorter ("4", "20", "two"), so a raw substring
test fires on "42", "2024" and "14:30". That inflates both arms roughly equally,
and M3's gate is the **ratio** ``C <= 0.5 * A``: adding the same false-positive
mass to both numerator and denominator of the comparison pushes the ratio toward
1 and therefore biases the pinned gate toward FAIL. A token-boundary test is the
narrowest rule that removes it without normalising the corpus text.

The denominator is the question set the caller passes in; this module scores
exactly the questions it is given (``preregister.json`` pins N=66 — the
knowledge-update pool minus the 6 abstention variants and the 6 questions whose
evidence carries no old->new update at all).

The gate that consumes this (M3) is ``C <= 0.5 * A``. This module only computes
the rate; the gate comparison lives with the execution drive.

Pure stdlib. No model or network calls.
"""

from __future__ import annotations

import re
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


def old_value_pattern(value: str) -> re.Pattern[str]:
    """The pinned token-boundary matcher for one labeled old value.

    ``(?<!\\w) ... (?!\\w)``, case-sensitive, over the value escaped literally.
    Lookarounds rather than ``\\b`` because many labels begin or end with a
    non-word character — ``"$350"``, ``"3-2"``, ``"7:00 pm"`` — and ``\\b`` is
    defined between a word and a non-word character, so it would silently fail to
    anchor exactly the values most in need of anchoring.
    """
    return re.compile(rf"(?<!\w){re.escape(value)}(?!\w)")


def context_is_contaminated(
    contexts: Iterable[str], old_values: Iterable[str]
) -> bool:
    """True iff any context surfaces any (non-empty) old value at token boundaries.

    Case-sensitive, per the pinned rule (see the module docstring). Empty
    old-value strings are ignored so a blank label can never mark every question
    contaminated — the labels file deliberately keeps a key for every question,
    including the ones with no old value at all.
    """
    patterns = [old_value_pattern(value) for value in old_values if value]
    if not patterns:
        return False
    return any(
        pattern.search(context) is not None
        for context in contexts
        for pattern in patterns
    )


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
