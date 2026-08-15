# M3 Stale-Value Labels — Methodology

**Status:** Pre-run labeling record — produced 2026-08-15, before any arm has run
**Labels:** `benchmarks/longmemeval/m3_labels.json`
**Pinned by:** `benchmarks/longmemeval/preregister.json` → `metrics.M3` (amendment dated 2026-08-15)
**Scope:** the 78-question knowledge-update pool, minus the 6 abstention (`_abs`) variants = 72 labeled questions

---

## 1. Why this document exists

M3 measures the rate at which a retrieved context still surfaces a **superseded**
value. The LongMemEval corpus ships no old-value annotation, so the metric had an
unmet precondition: without labels there is no M3, and with the *wrong* labels
there is a number that looks like M3 and is not.

The obvious automatic derivation — reading the old value off the harness's own
shared linker `supersedes` edges — was **rejected**. Those are precisely the edges
Arm C acts on, so labeling M3 with them would score Arm C against its own
mechanism and drive its contamination toward zero by construction. The labels
below are produced independently of the harness, before any arm run, by a model
that is not the pinned answering or extractor model.

## 2. Labeling model (deliberately NOT a pinned benchmark model)

| | |
|---|---|
| Model | `qwen3.6:latest` |
| Endpoint | GB10 ollama, `http://192.168.1.134:11434/api/chat` |
| Knobs | `temperature=0`, `num_ctx=32768`, `stream=false`, sequential calls only |
| Calls | 72 extraction calls (one per question), plus repair calls only on a failed verbatim check |

This model is **not** the pinned answering/extractor model (`gpt-oss:120b`) and is
never invoked by `benchmarks/longmemeval` itself. It does not participate in the
benchmark; it only produced candidate labels, every one of which was then
mechanically verified against the corpus (§5). Nothing it emitted is trusted on
the model's word alone.

## 3. Target set derivation

`question_type == "knowledge-update"` (checked against `corpus.KU_TYPE`), excluding
question_ids ending in `_abs`. This yields exactly **72** ids, and the 6 excluded
abstention ids match `preregister.json`'s `metrics.M3.denominator_amendment` list
exactly: `031748ae_abs`, `0ddfec37_abs`, `2133c1b5_abs`, `2698e78f_abs`,
`6aeb4375_abs`, `f685340e_abs`.

## 4. Evidence sessions

For all 72 questions, `haystack_session_ids` as a set is identical to
`answer_session_ids` (72/72), and `haystack_dates` is already chronological
(0/72 out of order). Evidence sessions are therefore all of a question's
`haystack_sessions` in existing order. Every one of the 72 questions has exactly
two evidence sessions: the old-value session, then the new/gold-value session.

## 5. Extraction prompt (verbatim)

`{question}` / `{answer}` / `{sessions_text}` are per-question substitutions.

```
You are a careful fact-checking assistant analyzing conversation transcripts for a memory benchmark.

TASK: The user asked a question whose factual answer changed over time across the evidence sessions below. You are given the question, the CURRENT (gold, most recent) answer, and the full text of the evidence sessions in chronological order.

Find every EARLIER (superseded, now-outdated) value of the same fact, exactly as it was stated in the sessions, before it changed to the gold answer. For each earlier value:
- old_value: the earlier value, written EXACTLY as it appears in the transcript (verbatim substring, not paraphrased, not reformatted, not unit-converted)
- quote: the exact sentence or clause from the transcript containing that old value (verbatim substring copy, not paraphrased)
- session_id: which session id the quote came from

Rules:
- Only report values superseded by the gold answer, never the gold answer itself.
- If a value differs from the gold answer only by formatting/wording (e.g. "25 minutes 50 seconds" vs "25:50") it is the SAME value, not an old value - do not report it.
- old_value and quote must be copied VERBATIM from the transcript text below. Do not paraphrase, fix typos, or normalize units/case.
- If there is truly no earlier value of this fact anywhere in the transcript, return an empty list.
- There may be more than one earlier value if the fact changed multiple times - report all of them.

Output ONLY a JSON object, no other text, in this exact schema:
{"old_values": [{"old_value": "...", "quote": "...", "session_id": "..."}]}

QUESTION: {question}
GOLD (current, latest) ANSWER: {answer}
{sessions_text}
```

A **repair prompt** is issued at most once per candidate, only when the verbatim
check below fails, asking the model to locate the exact substring it had
paraphrased:

```
You previously claimed this earlier/superseded value appeared in the transcript below: "{claimed_value}"

I could not find that exact text in the transcript. Find the EXACT verbatim substring in the transcript that expresses this same fact/value. Copy it character-for-character from the transcript, including exact spelling, punctuation, and number formatting.

Output ONLY a JSON object, no other text:
{"old_value": "<exact verbatim substring from transcript, or null if you cannot find it verbatim>", "quote": "<exact verbatim sentence/clause containing it, or null>", "session_id": "<session id it came from, or null>"}

QUESTION: {question}
GOLD (current, latest) ANSWER: {answer}
{sessions_text}
```

## 6. Mechanical validation (script-enforced, never model-trusted)

1. **Verbatim check.** `old_value` must appear as a substring of the raw evidence
   session text (the session turns' `content` fields, not the model's rendering).
   Exact substring first; a whitespace-flexible token-sequence regex is tried only
   as a *search* fallback, and the value stored is always the literal text
   recovered from the source at the matched span — never the model's candidate
   string. Anything accepted is therefore a genuine corpus substring. A failure
   triggers one repair call; a second failure drops the candidate and flags the
   question `NO_VERBATIM`.
2. **Not-same-as-gold check.** `old_value`, normalized (casefold +
   whitespace-collapse), must differ from the gold answer normalized the same way.
   Equal → dropped, flagged `SAME_AS_GOLD`.
3. **No-old-value check.** A question ending with zero accepted candidates is
   flagged `NO_OLD_VALUE`. **No value is ever invented to fill one.**
4. **Quote-contains-value check.** Every stored `quote` verbatim-contains its
   stored `old_value`. Where the model's own quote did not verbatim-match in the
   same session, a fallback quote is derived mechanically by expanding from the
   value's matched span to the nearest sentence/newline boundary in the raw
   session text, so every quote is itself a corpus substring.

Flagged questions keep their `question_id` key in the labels file with an empty
list — honesty over coverage.

## 7. Coverage

| | |
|---|---|
| Questions labeled | 72 |
| Questions with ≥1 old value | 66 |
| Total old values | 70 |
| Verbatim check | 70/70 pass |
| Quote-contains-value | 70/70 pass |
| `NO_VERBATIM` | 0 |
| `SAME_AS_GOLD` | 0 |
| `NO_OLD_VALUE` | 6 |
| Multi-update questions (>1 old value) | 3 — `830ce83f`, `0f05491a`, `5831f84d` |

Driver spot-check: 8/8 sampled labels semantically correct.

## 8. The 6 questions with no old→new update

These are **empirically** — not structurally — outside M3's substrate: the
labeling pass read each full transcript and found no superseded value of the
asked fact. Four of the six ask *for* the earlier value, so the gold answer **is**
the historical fact and nothing supersedes it; two state their value once and
never revise it.

| question_id | Question (abridged) | Gold | Why no old value exists |
|---|---|---|---|
| `0977f2af` | Which gadget did I invest in **before** getting the Air Fryer? | Instant Pot | Asks for the earlier item; the gold is itself the prior fact, so nothing supersedes it. |
| `10e09553` | How many bass did I catch on the **earlier** trip, before the 7/22 trip? | 7 | Asks for the earlier trip's count; that count is the gold and is never revised. |
| `9bbe84a2` | What was my **previous** goal before I updated it? | level 100 | The gold *is* the superseded value; there is no older one behind it to leak. |
| `dfde3500` | What day did I meet my **previous** tutor Juan? | Wednesday | Describes the prior arrangement; no earlier value of that day is stated. |
| `22d2cb42` | Where did I get my guitar serviced? | The music shop on Main St. | A single servicing location, stated once and never revised. |
| `5c40ec5b` | How many times have I met up with Alex from Germany? | We've met up twice. | The count is stated once as the current total; no earlier total is stated as superseded. |

Per the pinned M3 justification — old→new value labels exist "only where an update
actually exists" — these 6 carry no stale value **any** arm could surface, so they
are structurally uncontaminable and identical across A/B/C. Leaving them in the
denominator would deflate every arm's rate by the same 6 questions and bias the
pinned `C ≤ 0.5 × A` ratio toward FAIL. The pre-registration therefore corrects
the denominator 72 → **66**; the ratio itself is untouched (a common denominator
cancels).

## 9. Post-hoc corrections

One question (`0f05491a`) had a duplicate accepted entry — "300 stars" listed
twice with identical value / quote / session_id, the model repeating itself within
a single JSON response. Fixed by deduping on `(old_value, session_id)` across all
72 rows; a full scan confirmed only that question was affected, and the extraction
script was patched to dedupe in-loop for any future run. This was a pure
post-process over already-verified data — **no additional model calls were made.**

## 10. Known property of the pinned matching rule

Matching is token-boundary and case-sensitive (`(?<!\w)value(?!\w)`), pinned
2026-08-15. One consequence worth recording: a comma is not a word character, so
a label of `$350` would also match inside `$350,000`. The only two questions
carrying those values are different questions (`7e974930` labels `$350`;
`852ce960` labels `$350,000`), contamination is scored per question, and
`7e974930`'s own evidence contains no `$350,000` — so no label in this set is
affected. Recorded here because it is a property of the pinned rule, not an
accident of the current labels.
