"""Deterministic, pure-stdlib BM25 retriever shared by every benchmark arm.

Implements Okapi BM25 (Robertson / Sparck-Jones) with the standard defaults
``k1 = 1.5`` and ``b = 0.75``. A single instance ranks each arm's claim corpus,
so ranking is held constant while the memory layer varies.

Determinism guarantees:

* Tokenisation is fixed — lower-case, then ``\\w+`` word runs (no stemming,
  stop-words, or locale rules).
* IDF uses the non-negative BM25 form
  ``ln(1 + (N - df + 0.5) / (df + 0.5))``, so a term's contribution is never
  negative.
* Ties (equal scores, including byte-identical claim bodies) break on the claim
  ``id`` in ascending lexicographic order, giving a total order that is stable
  across runs and independent of insertion order.

Corpus statistics (document frequencies, average length) are recomputed from the
claims passed to :meth:`BM25Retriever.rank` on each call, so the retriever is
stateless and the same instance/parameters serve every arm.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from typing import Any, Sequence

from benchmarks.longmemeval.pipeline import Claim


_TOKEN_RE = re.compile(r"\w+")


def tokenize(text: str) -> list[str]:
    """Split ``text`` into lower-cased ``\\w+`` tokens (deterministic)."""
    return _TOKEN_RE.findall(text.lower())


class BM25Retriever:
    """Okapi BM25 over claim text. Deterministic, with a stable ``id`` tiebreak."""

    def __init__(self, k1: float = 1.5, b: float = 0.75) -> None:
        self.k1 = k1
        self.b = b

    @property
    def params(self) -> dict[str, Any]:
        """Ranking parameters — recorded per run to document arm-invariance."""
        return {"algorithm": "BM25Okapi", "k1": self.k1, "b": self.b}

    def rank_with_scores(
        self, query: str, claims: Sequence[Claim]
    ) -> list[tuple[Claim, float]]:
        """Return ``(claim, score)`` pairs, best first, ``id``-stable on ties."""
        claim_list = list(claims)
        if not claim_list:
            return []

        doc_counts = [Counter(tokenize(c.text)) for c in claim_list]
        doc_lengths = [sum(counts.values()) for counts in doc_counts]
        num_docs = len(claim_list)
        avg_length = sum(doc_lengths) / num_docs

        # Document frequency of every term across the corpus.
        doc_freq: Counter[str] = Counter()
        for counts in doc_counts:
            doc_freq.update(counts.keys())

        query_terms = tokenize(query)
        # IDF once per distinct query term that actually occurs in the corpus;
        # terms absent from the corpus contribute nothing (tf is 0 everywhere).
        idf: dict[str, float] = {}
        for term in query_terms:
            if term in idf or term not in doc_freq:
                continue
            df = doc_freq[term]
            idf[term] = math.log(1.0 + (num_docs - df + 0.5) / (df + 0.5))

        scored: list[tuple[Claim, float]] = []
        for claim, counts, length in zip(
            claim_list, doc_counts, doc_lengths, strict=True
        ):
            # avg_length is 0 only when every document is empty (then length is
            # 0 too and no term matches), so guarding the ratio is sufficient.
            length_ratio = length / avg_length if avg_length else 0.0
            length_norm = self.k1 * (1.0 - self.b + self.b * length_ratio)
            score = 0.0
            for term in query_terms:
                weight = idf.get(term)
                if weight is None:
                    continue
                tf = counts.get(term, 0)
                if not tf:
                    continue
                score += weight * (tf * (self.k1 + 1.0)) / (tf + length_norm)
            scored.append((claim, score))

        scored.sort(key=lambda pair: (-pair[1], pair[0].id))
        return scored

    def rank(self, query: str, claims: Sequence[Claim]) -> list[Claim]:
        """Return claims ranked best-first (see :meth:`rank_with_scores`)."""
        return [claim for claim, _ in self.rank_with_scores(query, claims)]
