"""The shared, arm-independent extract + link stage (design doc §7.3).

One linker instance serves arms A, B and C over a single question scope, so all
three see **byte-identical** claims. That is the fairness constraint that makes
the memory layer the only independent variable: A and B simply ignore the
lineage and update edges the linker writes, while Arm C's ``content_hash``
coalescing and R4 resolution consume them.

What the linker assigns
-----------------------

* ``subject`` — the topic an update is detected *against*. R4 is subject-scoped
  (``spec/v0.3-claim-semantics.md``), so this is the grouping key.
* ``claim_id`` — one lineage node per distinct value standing on a subject. Two
  exact restatements of the value currently standing share a lineage, which is
  precisely the pair Arm C coalesces (design doc §2.3: same ``claim_id`` **and**
  byte-equal ``content_hash``). A body that returns *after* the subject moved on
  (``A -> B -> A``) is a **revert**, not a restatement, and mints a fresh node
  superseding the head — see :meth:`SharedLinker._revert_lineage` for why reusing
  the original lineage would make Arm C surface the stale value as current.
* ``supersedes`` — the update edge. When a subject that already carries a value
  receives a *different* body, the new lineage supersedes the subject's current
  head, so R4 resolves the group to the newest value and Arm C stops surfacing
  the stale one.
* ``valid_from`` — the instant the superseding claim became true, taken from the
  session's own recorded timestamp. Never invented: a session with no recorded
  instant yields no ``valid_from`` at all, which leaves R2 valid-time filtering
  unbound rather than fabricating a bound.

What the linker deliberately does **not** do
--------------------------------------------

It does not flip a superseded claim's ``state``. Superseding is resolved
*reader-side* from the ``supersedes`` graph
(``spec/v0.3-claim-semantics.md``); the ``state`` field belongs to the event
state machine's write path. Mutating an already-emitted claim's ``state`` would
also change its ``content_hash`` (``state`` is in the identity projection), which
``spec/lifecycle-state-machine.md`` §5.1 makes a hard
``ERR-SEM-DUPLICATE-HASH-COLLISION`` for a lineage that has already been stored.

The recall ceiling, stated up front
-----------------------------------

Design doc §7.3 names the central validity risk: *"the linker's recall bounds
Arm C's ceiling"* — if updates are not detected, Arm C degenerates to Arm B and
M1/M3 cannot move. Update detection therefore lives behind an injectable
:data:`SubjectPolicy` rather than being welded in, and every run reports its
:class:`LinkerStats` so the ceiling is visible in the results instead of being
inferred from a disappointing metric.

:func:`default_subject_policy` is deliberately **conservative** (high precision,
low recall): it detects an update only when a claim body ends in a value-like
token, and treats the preceding words as the subject. Ordinary conversational
prose yields no subject at all, so no update edge is invented from text the
policy cannot actually read. Building a looser semantic linker to raise Arm C's
score is exactly the bias design doc §6 exists to prevent — a benchmark whose
author tunes the shared stage until the arm under test wins.

Pure stdlib. No model or network calls.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Callable, Iterable, Mapping, Sequence

from benchmarks.longmemeval.arms.naive_dedup import normalize_body
from benchmarks.longmemeval.pipeline import Claim, Session

# A subject policy reads a normalised claim body and returns the subject an
# update would be detected against, or ``None`` when it can read no subject from
# the text. ``None`` is the honest answer, not a failure: it means this claim
# participates in no update chain.
SubjectPolicy = Callable[[str], "str | None"]

# Session metadata key carrying the instant a session occurred, already in the
# 20-char ``YYYY-MM-DDTHH:MM:SSZ`` form R2 compares against.
OCCURRED_AT_KEY = "occurred_at"

# Frontmatter constants for every linked claim. ``state`` is always ``active``:
# suppression of a superseded value is R4's reader-side verdict here, not a
# write-path state transition (see the module docstring).
CLAIM_STATE = "active"
CLAIM_PREDICATE = "states"
CLAIM_TYPE = "conversation_turn"

# A value-like token begins with a digit (after an optional sign or currency
# mark) and carries only digits, value punctuation, and a short unit tail. Times
# ("22:00"), dates ("2023/05/25"), counts ("12"), amounts ("$40.50") and units
# ("5km", "80%") match; ordinary words do not.
_VALUE_TOKEN_RE = re.compile(r"^[+-]?[$€£¥]?\d[\d.,:/\-]*[a-z%°]{0,4}[.!?]?$")


# Session metadata key carrying the extractor's structured claims: a mapping from
# the exact claim line to ``{"subject": ..., "value": ...}``. Absent for the
# mechanical stub extractor, which is why the offline smokes are unaffected.
STRUCTURED_KEY = "structured_claims"


def normalize_subject(subject: str) -> str:
    """The lineage key a provided subject collapses to.

    Case and surrounding whitespace are not part of a subject's identity, and a
    model asked for a stable slug will still vary on both. Nothing else is
    touched: two subjects that differ in their words are different subjects, and
    guessing otherwise is how a linker starts merging unrelated facts.
    """
    return " ".join(subject.split()).strip().lower()


def default_subject_policy(text: str) -> str | None:
    """The conservative default: a trailing value token makes the rest a subject.

    ``"user: my 5K personal best is 22:00"`` yields
    ``"user: my 5k personal best is"`` — so a later ``"... is 24:30"`` lands on
    the same subject and is detected as an update. Text that does not end in a
    value-like token yields ``None`` (no update is detectable), and so does a
    bare value with no surrounding topic, because a subject of ``""`` would
    group every stray number in the corpus into one conflict set.

    High precision, low recall, by design: see the module docstring on why the
    shared stage must not be tuned until the arm under test wins.
    """
    tokens = normalize_body(text).lower().split(" ")
    if len(tokens) < 2 or not _VALUE_TOKEN_RE.match(tokens[-1]):
        return None
    return " ".join(tokens[:-1])


@dataclass(frozen=True)
class LinkerStats:
    """What the linker managed to link — the ceiling it puts on Arm C.

    ``supersedes_edges`` and ``updated_subjects`` are the recall numbers design
    doc §7.3 makes load-bearing: both at zero means Arm C has no update to
    resolve and *cannot* separate itself from Arm B on M1 or M3, whatever the
    claim-semantics machinery does.
    """

    records: int = 0
    lineages: int = 0
    subjects: int = 0
    supersedes_edges: int = 0
    updated_subjects: int = 0
    restatement_groups: int = 0

    def __add__(self, other: LinkerStats) -> LinkerStats:
        return LinkerStats(
            records=self.records + other.records,
            lineages=self.lineages + other.lineages,
            subjects=self.subjects + other.subjects,
            supersedes_edges=self.supersedes_edges + other.supersedes_edges,
            updated_subjects=self.updated_subjects + other.updated_subjects,
            restatement_groups=self.restatement_groups + other.restatement_groups,
        )

    @classmethod
    def total(cls, parts: Iterable[LinkerStats]) -> LinkerStats:
        """Sum stats across scopes — one linker runs per question."""
        result = cls()
        for part in parts:
            result = result + part
        return result

    def as_record(self) -> dict[str, int]:
        """The stats as a results-row fragment."""
        return {
            "records": self.records,
            "lineages": self.lineages,
            "subjects": self.subjects,
            "supersedes_edges": self.supersedes_edges,
            "updated_subjects": self.updated_subjects,
            "restatement_groups": self.restatement_groups,
        }


class SharedLinker:
    """Extract claims from a session and link them into lineages.

    One instance per scope (a question), shared by every arm. Calling the
    instance is the :data:`~benchmarks.longmemeval.pipeline.Extractor` contract,
    so it drops straight into any store's ``extractor=`` slot.

    A body already seen in this scope re-emits its **cached metadata verbatim**.
    That is not an optimisation: two records of one lineage that disagree on any
    R4 field make Arm C raise ``CoalesceConflictError``, because the surviving
    record would otherwise be decided by ingest order
    (``spec/lifecycle-state-machine.md`` §5.3). Re-emitting byte-identical
    frontmatter is how the linker keeps that promise.
    """

    def __init__(
        self,
        scope: str,
        *,
        subject_policy: SubjectPolicy = default_subject_policy,
        occurred_at_key: str = OCCURRED_AT_KEY,
    ) -> None:
        self._scope = scope
        self._subject_policy = subject_policy
        self._occurred_at_key = occurred_at_key
        # Normalised body -> the frontmatter every record of that body carries.
        self._meta_by_body: dict[str, dict[str, Any]] = {}
        # Normalised body -> the record ids that restated it, in arrival order.
        self._ids_by_body: dict[str, list[str]] = {}
        # Subject -> the claim_id currently at the head of its update chain.
        self._head_by_subject: dict[str, str] = {}
        self._subjects: list[str] = []
        # Subject -> the frontmatter of the claim currently at its head. Only the
        # structured path needs it: deciding update-vs-restatement requires the
        # standing VALUE, which the head's claim_id alone does not carry.
        self._head_meta_by_subject: dict[str, dict[str, Any]] = {}
        self._lineage_seq = 0
        self._supersedes_edges = 0
        self._updated_subjects: set[str] = set()
        # Record id -> the claim emitted for it, in first-emission order. A dict
        # rather than a list because one linker is *re-run per arm* over the same
        # sessions (that is what makes the three arms see byte-identical claims),
        # so a record can be linked more than once and an appending list would
        # report three times the corpus it actually saw.
        self._claims: dict[str, Claim] = {}

    # -- extractor contract -------------------------------------------------

    def __call__(self, session: Session) -> list[Claim]:
        """One claim per non-blank line of the session, linked into lineages.

        Idempotent per record: re-linking a session already seen returns the
        same claims and leaves the stats untouched, because every arm calls the
        one shared linker over the same sessions.
        """
        occurred_at = session.metadata.get(self._occurred_at_key)
        # Absent is a legitimate state (the mechanical stub extractor supplies
        # nothing and must keep taking the free-text path); present-but-unusable
        # is not. Testing membership rather than truthiness is what keeps the two
        # apart: ``or {}`` turned a malformed ``[]`` into "absent" and slid the
        # run back onto the policy that produced 243 lineages and no edges.
        structured: Any = {}
        if STRUCTURED_KEY in session.metadata:
            structured = session.metadata[STRUCTURED_KEY]
        if not isinstance(structured, Mapping):
            # Raised rather than ignored. Falling back to the free-text policy
            # would silently restore the very behaviour structured extraction
            # replaced — 243 records resolving to 243 lineages with no update
            # edges — and a run would look like it had linked nothing to link.
            raise TypeError(
                f"session {session.id!r} carries {STRUCTURED_KEY!r} as "
                f"{type(structured).__name__}; it must be a mapping from claim "
                "text to {'subject': ..., 'value': ...}."
            )
        claims: list[Claim] = []
        for line_no, line in enumerate(session.text.split("\n")):
            if not line.strip():
                continue
            record_id = f"{session.id}#L{line_no:03d}"
            # A record's lineage is decided once, on first sight; re-linking is a
            # pure replay. The decision depends on what stood at the head of the
            # subject *at that moment*, so re-deriving it on a later pass would
            # read a head that has since moved and mint a spurious revert.
            settled = self._claims.get(record_id)
            if settled is None:
                settled = self._link(
                    record_id, line, occurred_at, structured.get(line)
                )
                self._claims[record_id] = settled
            claims.append(settled)
        return claims

    # -- linking ------------------------------------------------------------

    def _mint_claim_id(self) -> str:
        """Allocate the next lineage id in this scope.

        Counted separately from the body table because a lineage and a distinct
        body are no longer one-to-one: a revert mints a second lineage for a body
        already seen (see :meth:`_revert_lineage`).
        """
        claim_id = f"{self._scope}#C{self._lineage_seq:05d}"
        self._lineage_seq += 1
        return claim_id

    def _link(
        self,
        record_id: str,
        line: str,
        occurred_at: object,
        structured: Mapping[str, Any] | None = None,
    ) -> Claim:
        body = normalize_body(line)
        restatements = self._ids_by_body.setdefault(body, [])
        if record_id not in restatements:
            restatements.append(record_id)

        known = self._meta_by_body.get(body)
        if known is None:
            meta = self._new_lineage(body, occurred_at, structured)
        elif self._head_by_subject.get(known["subject"]) == known["claim_id"]:
            # The value this body carries is still the one standing on its
            # subject, so this is a plain restatement: re-emit verbatim.
            meta = known
        else:
            meta = self._revert_lineage(known, occurred_at)

        self._meta_by_body[body] = meta
        return Claim(id=record_id, text=line, metadata=dict(meta))

    def _set_head(self, subject: str, meta: dict[str, Any]) -> None:
        """Advance a subject's head — both maps, always together.

        ``_head_by_subject`` answers "which lineage stands here" and
        ``_head_meta_by_subject`` answers "at what value". They are two views of
        one fact, and a transition that moved only the first left the second
        describing a lineage that had already been superseded: the next
        differently-worded claim at that stale value would then read as a
        restatement of it, mint no edge, and leave Arm C surfacing a value the
        corpus had already moved past. Every transition goes through here so the
        two cannot drift.
        """
        self._head_by_subject[subject] = meta["claim_id"]
        self._head_meta_by_subject[subject] = meta

    def _revert_lineage(
        self, prior: dict[str, Any], occurred_at: object
    ) -> dict[str, Any]:
        """Mint a fresh update node for a value that was current, then was not.

        The ``A -> B -> A`` case. The third claim restates a body this scope has
        already seen, but the subject moved on in between: ``B`` now stands at the
        head. Re-using ``A``'s original lineage would put back a claim that ``B``
        supersedes, so R4 resolves the subject to ``B`` and Arm C surfaces the
        **stale** value as current even though the latest session reverted to
        ``A`` — the exact contamination Arm C exists to prevent. A revert is an
        update like any other, so it gets its own lineage superseding the head.

        The new node's ``content_hash`` equals the original ``A`` node's — same
        ``subject``/``predicate``/``object``/``state``/``type`` — while carrying a
        different ``claim_id``. That is precisely the cross-lineage,
        same-``content_hash`` pair design doc §2.3's amendment requires to reach
        R4 intact rather than coalesce, and Arm C's lineage gate keeps them apart
        by construction.
        """
        subject = str(prior["subject"])
        meta = dict(prior)
        meta["claim_id"] = self._mint_claim_id()
        meta["supersedes"] = [self._head_by_subject[subject]]
        # Drop any valid_from inherited from when this body was itself an update;
        # this node became true at *this* session's instant, or at none at all.
        meta.pop("valid_from", None)
        if isinstance(occurred_at, str) and occurred_at:
            meta["valid_from"] = occurred_at

        self._supersedes_edges += 1
        self._updated_subjects.add(subject)
        self._set_head(subject, meta)
        return meta

    def _new_lineage(
        self,
        body: str,
        occurred_at: object,
        structured: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Mint the frontmatter for a body this scope has not seen before.

        When the extractor supplied a ``subject``/``value`` for this claim, the
        subject is the lineage key and the **value** is what decides update from
        restatement. That distinction is the whole point of structured
        extraction: two sessions phrase the same fact differently, so a
        body-keyed linker sees two unrelated claims, while a subject-keyed one
        sees one fact whose value did — or did not — move.
        """
        provided_subject = str((structured or {}).get("subject") or "").strip()
        if provided_subject:
            return self._structured_lineage(provided_subject, structured, occurred_at)

        subject = self._subject_policy(body)
        claim_id = self._mint_claim_id()

        if subject is None:
            # No detectable topic: give the claim a subject of its own so R4
            # groups it with nothing. Dropping ``subject`` entirely is not an
            # option — Arm C's R4 pass needs one for any claim that might later
            # carry an update field (``spec/v0.3-claim-semantics.md`` §6.5).
            subject = f"{self._scope}#S{len(self._subjects):05d}"

        if subject not in self._head_by_subject:
            self._subjects.append(subject)

        meta: dict[str, Any] = {
            "claim_id": claim_id,
            "subject": subject,
            "predicate": CLAIM_PREDICATE,
            "object": body,
            "state": CLAIM_STATE,
            "type": CLAIM_TYPE,
            "question_id": self._scope,
        }

        head = self._head_by_subject.get(subject)
        if head is not None:
            meta["supersedes"] = [head]
            if isinstance(occurred_at, str) and occurred_at:
                meta["valid_from"] = occurred_at
            self._supersedes_edges += 1
            self._updated_subjects.add(subject)
        self._set_head(subject, meta)
        return meta

    def _structured_lineage(
        self,
        provided_subject: str,
        structured: Mapping[str, Any] | None,
        occurred_at: object,
    ) -> dict[str, Any]:
        """Link a claim whose subject and value the extractor supplied.

        Three outcomes, decided by what already stands on the subject:

        * nothing stands there yet — a new lineage, no edge;
        * the standing value equals this one — a **restatement** in different
          words, which re-uses the standing lineage verbatim so Arm C coalesces
          the pair instead of treating a rephrasing as an update;
        * the standing value differs — an **update**, which mints a new lineage
          superseding the head and is the edge design doc §7.3 makes Arm C's
          ceiling.

        Comparing values rather than bodies is what makes the middle case
        possible at all. Under the free-text policy the two probe phrasings of
        one score ("The user's highest score in Ticket to Ride is 124 points" /
        "The user reported achieving their highest score in Ticket to Ride, which
        was 132 points") are simply two unrelated claims; here they are one
        subject whose value moved.
        """
        subject = normalize_subject(provided_subject)
        value = str((structured or {}).get("value") or "").strip()

        head_meta = self._head_meta_by_subject.get(subject)
        if head_meta is not None and str(head_meta.get("object", "")) == value:
            # Same fact, same value, different wording: not an update.
            return head_meta

        claim_id = self._mint_claim_id()
        if subject not in self._head_by_subject:
            self._subjects.append(subject)

        meta: dict[str, Any] = {
            "claim_id": claim_id,
            "subject": subject,
            "predicate": CLAIM_PREDICATE,
            # The value carries the identity, not the sentence: two phrasings of
            # one value must project to one content_hash for Arm C to coalesce.
            "object": value,
            "state": CLAIM_STATE,
            "type": CLAIM_TYPE,
            "question_id": self._scope,
        }

        head = self._head_by_subject.get(subject)
        if head is not None:
            meta["supersedes"] = [head]
            if isinstance(occurred_at, str) and occurred_at:
                meta["valid_from"] = occurred_at
            self._supersedes_edges += 1
            self._updated_subjects.add(subject)

        self._set_head(subject, meta)
        return meta

    # -- reporting ----------------------------------------------------------

    @property
    def claims(self) -> list[Claim]:
        """Every distinct claim this linker has emitted, in first-emission order."""
        return list(self._claims.values())

    @property
    def stats(self) -> LinkerStats:
        """The recall numbers that bound Arm C (design doc §7.3)."""
        return LinkerStats(
            records=len(self._claims),
            lineages=self._lineage_seq,
            subjects=len(self._subjects),
            supersedes_edges=self._supersedes_edges,
            updated_subjects=len(self._updated_subjects),
            restatement_groups=sum(
                1 for ids in self._ids_by_body.values() if len(ids) > 1
            ),
        )

    def duplicate_groups(self) -> list[list[str]]:
        """Exact-restatement groups of record ids, within this scope."""
        return [list(ids) for ids in self._ids_by_body.values()]


# ---------------------------------------------------------------------------
# Corpus timestamps
# ---------------------------------------------------------------------------

# LongMemEval records session instants as ``2023/05/25 (Thu) 20:21`` — the
# weekday is redundant with the date, so it is matched and discarded.
_CORPUS_INSTANT_RE = re.compile(
    r"^\s*(\d{4})/(\d{2})/(\d{2})\s*(?:\([^)]*\))?\s*(\d{2}):(\d{2})\s*$"
)


def parse_corpus_instant(raw: object) -> str | None:
    """Convert a LongMemEval session date to the 20-char R2 comparison form.

    Returns ``None`` for anything that does not parse, so an unreadable date
    leaves ``valid_from`` unset rather than pinning a claim to a guessed instant.
    R2 treats an absent ``valid_from`` as unbounded, which is the correct reading
    of "we do not know when this became true".
    """
    if not isinstance(raw, str):
        return None
    match = _CORPUS_INSTANT_RE.match(raw)
    if match is None:
        return None
    year, month, day, hour, minute = match.groups()
    return f"{year}-{month}-{day}T{hour}:{minute}:00Z"


def link_sessions(scope: str, sessions: Sequence[Session]) -> SharedLinker:
    """Run one linker over every session of a scope and return it.

    The linker is returned rather than its claims because its
    :attr:`~SharedLinker.stats` and :meth:`~SharedLinker.duplicate_groups` are
    the parts M2 and the recall report consume.
    """
    link = SharedLinker(scope)
    for session in sessions:
        link(session)
    return link
