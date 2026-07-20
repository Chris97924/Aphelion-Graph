"""M2 — deduplication quality (precision / recall / F1).

Deduplication is scored as a *pairwise* classification problem, the standard
framing for entity/record dedup evaluation:

* The ground truth is a set of **labeled duplicate pairs** — unordered pairs of
  claim ids that are genuinely the same fact.
* An arm's memory layer induces a **clustering** of the ingested claims: every
  retained claim stands for the group of original claim ids it merged (Arm A
  keeps everything, so each cluster is a singleton and it predicts *no*
  duplicates; Arm B merges whitespace-identical bodies; Arm C merges by lineage
  + content hash). The pairs an arm predicts to be duplicates are exactly the
  unordered pairs that fall inside the same cluster.

Given the true pairs ``T`` and the predicted pairs ``P``::

    precision = |T ∩ P| / |P|      (of the merges we made, how many were right)
    recall    = |T ∩ P| / |T|      (of the true duplicates, how many we caught)
    F1        = 2·P·R / (P + R)

The gate that consumes this (see ``preregister.json`` M2) compares arms:
``C.F1 > A.F1 + 0.10 AND C.F1 >= B.F1 - epsilon``. This module only *computes*
the score; gate arithmetic lives with the execution drive.

Pure stdlib. No model or network calls.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Hashable, Iterable

# An unordered pair of claim ids. ``frozenset`` makes {a, b} == {b, a} and keys
# cleanly into sets, so pair arithmetic is order-independent by construction.
Pair = frozenset


@dataclass(frozen=True)
class DedupScore:
    """The pairwise dedup score for one arm.

    Counts are exposed alongside the rates so callers can aggregate across
    question sets (micro-average) without re-deriving them.
    """

    precision: float
    recall: float
    f1: float
    true_positives: int
    false_positives: int
    false_negatives: int


def _normalize_pairs(pairs: Iterable[Iterable[Hashable]]) -> set[frozenset]:
    """Coerce an iterable of id-pairs into a set of 2-element ``frozenset``\\ s.

    Rejects degenerate pairs (a claim paired with itself) rather than silently
    dropping them, so a malformed label set surfaces instead of skewing recall.
    """
    out: set[frozenset] = set()
    for pair in pairs:
        members = frozenset(pair)
        if len(members) != 2:
            raise ValueError(f"duplicate pair must have two distinct ids: {pair!r}")
        out.add(members)
    return out


def cluster_pairs(clusters: Iterable[Iterable[Hashable]]) -> set[frozenset]:
    """Return every unordered intra-cluster id pair — an arm's *predicted* dups.

    Each cluster is the set of original claim ids an arm merged into one retained
    claim. Singleton clusters contribute no pairs (the arm predicts that claim is
    unique). Duplicate ids inside a cluster are collapsed first.
    """
    pairs: set[frozenset] = set()
    for cluster in clusters:
        ids = sorted(set(cluster))
        for i in range(len(ids)):
            for j in range(i + 1, len(ids)):
                pairs.add(frozenset((ids[i], ids[j])))
    return pairs


def dedup_prf(
    labeled_pairs: Iterable[Iterable[Hashable]],
    predicted_pairs: Iterable[Iterable[Hashable]],
) -> DedupScore:
    """Precision/recall/F1 of ``predicted_pairs`` against ``labeled_pairs``.

    Both arguments are iterables of unordered id-pairs. Precision is 0.0 when no
    pairs are predicted and recall is 0.0 when none are labeled (F1 is 0.0 when
    ``precision + recall`` is 0); these conventions keep an arm that dedups
    nothing from scoring as perfect.
    """
    labeled = _normalize_pairs(labeled_pairs)
    predicted = _normalize_pairs(predicted_pairs)

    tp = len(labeled & predicted)
    fp = len(predicted - labeled)
    fn = len(labeled - predicted)

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0

    return DedupScore(
        precision=precision,
        recall=recall,
        f1=f1,
        true_positives=tp,
        false_positives=fp,
        false_negatives=fn,
    )


def score_arm(
    labeled_pairs: Iterable[Iterable[Hashable]],
    arm_clusters: Iterable[Iterable[Hashable]],
) -> DedupScore:
    """Score one arm: (labeled duplicate pairs + the arm's merge clusters) → PRF.

    This is the headline callable — ``arm_clusters`` is the arm's per-retained-claim
    grouping of original ids (its "claim sets"); the predicted duplicate pairs are
    derived from it via :func:`cluster_pairs`.
    """
    return dedup_prf(labeled_pairs, cluster_pairs(arm_clusters))
