# Structured Extraction & Subject-Keyed Linking

**Status:** Pre-run mechanism record — 2026-08-15, before any arm has run
**Pins:** `benchmarks/longmemeval/preregister.json` → `answering_model`, `extractor_model`, amendment dated 2026-08-15
**Design doc:** `docs/benchmark/longmemeval-3arm-design.md` §5.2 (pins), §7.3 (shared linker)

---

## 1. What the probe found

An **extraction-only** diagnostic was run on 2026-08-15 over 10 real
knowledge-update questions using the newly re-pinned extractor. No arm was run,
no benchmark metric was computed, and no gate outcome was knowable from it —
which is why acting on it stays inside the §6.3 amendment window.

Two findings, pointing in opposite directions:

**The claims were good.** Atomic, faithful, self-contained, and they captured
both values of a fact that changed — a Ticket to Ride high score recorded once at
124 points and later at 132. This is the quality gate the model re-pin needed.

**The linker linked nothing.** 243 extracted records resolved to **243 unique
lineages, 0 `supersedes` edges, 0 restatement groups.** Design doc §7.3 names
this exact failure in its own words — *"the linker's recall bounds Arm C's
ceiling"* — and it had been realised: with no update edges, Arm C's R4
resolution has nothing to resolve, it degenerates to Arm B, and M1/M3 cannot
move in either direction.

## 2. Why it happened — mechanism, not model deficiency

`default_subject_policy` derives a subject only when a claim body **ends in a
value-like token**, treating the preceding words as the subject. That works on
the smoke's mechanical `"role: text"` lines. It does not survive contact with
real claim sentences. Both probe phrasings of the score end in the word
`points.`:

| Session | Claim sentence | Subject derived |
|---|---|---|
| 1 | The user's highest score in Ticket to Ride is 124 points. | *(none)* |
| 2 | The user reported achieving their highest score in Ticket to Ride, which was 132 points. | *(none)* |

Neither yields a subject, so the two phrasings of one fact never meet, and no
update can be detected between them. Loosening the text policy was rejected: a
looser semantic matcher tuned until Arm C wins is precisely the bias design doc
§6 exists to prevent.

## 3. The fix — the extractor states the fact, the linker keys on it

The extractor now emits one JSON object per claim with three fields:

| Field | Purpose |
|---|---|
| `text` | The self-contained claim sentence. **Unchanged in role** — this is what BM25 ranks and what the answering model reads. |
| `subject` | A stable slug naming the *fact* (`user/ticket-to-ride/highest-score`). Identical whenever two claims are about the same fact, however differently worded. |
| `value` | The value that fact currently holds (`132 points`). |

`SharedLinker` keys lineages on the normalised `subject` and decides
update-versus-restatement on the `value`:

- subject unseen → new lineage, no edge;
- subject standing at the **same** value → a rephrasing, which re-uses the
  standing lineage so Arm C coalesces the pair rather than treating new wording
  as new information;
- subject standing at a **different** value → an update, minting a new lineage
  that supersedes the head. This is the edge Arm C's whole mechanism consumes.

Claims carrying no subject fall back to `default_subject_policy` unchanged, which
is what keeps the offline smokes byte-identical.

## 4. Why this is not tuning the benchmark toward a result

Three properties are preserved deliberately:

1. **The arms still see the same context.** The claim *sentence* is what feeds
   retrieval and answering; `subject`/`value` are metadata that Arms A and B
   ignore, exactly as they already ignore the lineage fields.
2. **The linker is still one shared, arm-independent stage.** Arm C is handed
   nothing Arms A and B are not also handed.
3. **A ceiling of zero is not a neutral baseline.** With 0 edges the benchmark
   could not produce a result in *either* direction — Arm C could not win and
   could not lose on its own mechanism. Raising the ceiling makes the kill-gate
   able to fire at all; it does not decide which way.

The fix was recorded before any arm ran, on evidence that contained no metric.

## 5. Serving configuration (recorded for reproducibility)

The pinned endpoint speaks the chat-completions dialect and is served on GB10.
The container is not always up, so the reference launch is recorded here and in
the pin:

```
vllm serve Qwen/Qwen3.8-27B-FP8 \
  --served-model-name qwen3.8 \
  --host 0.0.0.0 --port 8000 \
  --max-model-len 131072 \
  --gpu-memory-utilization 0.5 \
  --max-num-seqs 1 \
  --enable-chunked-prefill --enable-prefix-caching
```

**Every request must carry `chat_template_kwargs {"enable_thinking": false}`.**
This is part of the pin, not a client detail: with thinking on, the model's chat
template emits a reasoning preamble that consumes the whole completion budget and
the response arrives with `content: null` — not a worse answer, *no* answer. The
client raises a typed error naming this cause rather than substituting an empty
string, and `--preflight` checks the pinned served name appears in the endpoint's
model inventory without generating anything.

Observed timing during the probe: ~30 s for a long evidence session, sub-second
for small prompts.

## 6. Failure policy: fail loud, never salvage

A malformed extraction line raises `ExtractionFormatError` and fails the session
rather than being skipped. Skipping is not the conservative option here:
extraction is **memoised durably**, so a dropped claim is written to disk once
and every arm then answers from the same reduced memory for the rest of the run —
invisibly, because a smaller claim set is indistinguishable from a session that
had less to say. Failing leaves the operator a retry; salvaging leaves them a
benchmark quietly measured over inputs it does not describe.

Blank lines and bare code-fence delimiters are skipped, because they carry no
claim: a model that wraps correct output in a fence has still answered correctly.


---

## 7. Vocabulary priming (amendment #4, 2026-08-16)

### What the second probe found

Structured extraction worked, and the numbers say so: **11 `supersedes` edges
across 4 of 10 knowledge-update questions**, where the free-text policy produced
zero on all of them. But **6 questions still produced none**, and inspecting them
showed no missing facts — only missing agreement about names:

| Question | Earlier session | Later session |
|---|---|---|
| `01493427` | `user/postcard-collection/new-acquisitions-count` = 17 | `user/collection/postcards/new-additions-since-restart` = 25 |
| `0ddfec37` | `user/autographed-baseball-collection/count` = 15 | `user/collection/autographed-baseballs/recent-additions` = 20 |

Both pairs are the same fact with a moved value — exactly the update M1 and M3
ride on — and both went unlinked because the two sessions named the fact
differently.

### Why the rubric could not fix it

Each session is extracted in its **own call**. The model is not being
inconsistent *within* a call; it is being asked, twice and in isolation, to name
the same thing, with no memory of its earlier answer. Strengthening the
instruction cannot close a gap that exists between calls rather than inside one.

### The mechanism

Sessions already run in pinned occurrence order within a question. After each
session's extraction the question's subject vocabulary is accumulated — slug plus
the most recent value seen for it, in first-minted order — and every
**subsequent** session's prompt carries it:

```
Facts in this conversation were already given subject slugs in EARLIER sessions.
<<<KNOWN_SUBJECTS
user/postcard-collection/new-acquisitions-count = 17
KNOWN_SUBJECTS>>>

When a claim you extract is about the SAME fact as one of these, REUSE that exact
slug, character for character. ... Mint a new slug only for a fact that is
genuinely not listed above. The value may of course differ: that is what makes it
an update rather than a repetition.
```

The block is fenced like every other untrusted value — the slugs are model output
derived from corpus text, so they are data the model is shown, never instructions
it follows. The first session of a question is unprimed; there is nothing yet to
be consistent with.

### Properties preserved

- **Per question.** Nothing leaks between questions.
- **Order-derived, not accumulated.** The vocabulary for a session comes from the
  sessions *preceding* it in pinned order, never from "everything seen so far".
  Every arm replays the same sessions through the one shared extractor, so an
  accumulating vocabulary would prime a session differently on the second pass
  than on the first — and the memoised claims would then no longer correspond to
  the prompt this code would send.
- **Resume-equivalent.** A resumed run rebuilds the vocabulary from the cached
  claims in the same order, so a session extracted after an interruption is
  primed exactly as it would have been had the run never stopped.
- **Shared.** One primed extraction feeds all three arms; Arm C receives nothing
  Arms A and B do not.

### Cache versioning

Extraction is cached per **(question, session)**, because a primed prompt depends
on the question it sits in. The durable cache carries a format version and
**refuses** rows written before priming: those claims came from unprimed prompts,
and replaying them beside newly-primed sessions would mix two extraction
protocols inside one question, leaving linkage that belongs to neither. A
pre-priming cache is discarded, never migrated.

Cost: session reuse across questions is negligible — 10,417 (question, session)
pairs against 9,454 unique sessions, 1.1x — so per-question scoping costs roughly
10% more extraction calls than session-only caching would. Priced and accepted.

---

## 8. Extraction width (`--extract-workers`, 2026-08-24)

Extraction is one model call per session and the calls are slow — §5 records ~30
s for a long evidence session — but the dependency that makes them *sequential*
exists only inside a question. §7's priming makes session *k*'s prompt a function
of the sessions before it in the same question, so those can never overlap; two
different questions share nothing but the durable cache. `--extract-workers N`
takes exactly that asymmetry and nothing else: **sessions inside a question stay
strictly serial, whole questions run concurrently, up to N at a time.** What N
may change is the schedule and the wall clock; what it may not change is the
measurement, so the rows the cache ends up holding are the same set at any N,
each produced by the prompt the serial pass would have sent. Row *order within
the file* is deliberately not part of the contract — rows are appended the moment
they are durable, which is what makes an interrupted pass resumable, and nothing
reads the file positionally: the cache keys on `(question, session)` and the
priming vocabulary is derived from the session walk. The value a run used is
recorded in its manifest as `extract_workers`, and it is **not** a resume key in
either mode: it appears in neither `_IDENTITY_FIELDS`, the projection a graded
`--real` resume must match, nor `extraction_identity`, the one that guards the
cache. So a pass that ran four questions wide may be resumed one question wide
and the reverse, because neither produced a row the other would not have. Do not
read that across to the fields recorded beside it. `top_k` and `limit` are
likewise absent from `extraction_identity` — which is what lets a narrow pilot
extraction be topped up by a wider pass rather than thrown away — but both *are*
in `_IDENTITY_FIELDS`, so changing either between graded `--real` passes over one
`--out-dir` is refused with `RunManifestMismatchError`. `--real` takes the width
flag too; above 1 it warms the cache before the graded phase, which then finds
every session cached and replays it exactly as a resumed run always has. At the
default of 1 no pool is built at all and both modes are the strictly serial pass
they have always been.

**Merging this widening does, however, retire every extraction cache written
before it — the mechanism working rather than a regression.** Adding the flag
edits `real_run.py` and `run.py`, both inside `_EXTRACTION_HARNESS_ROOTS`
(`benchmarks/longmemeval/` itself), so `extraction_harness_sha256` moves, and
that digest is a field of `extraction_identity`; the wide `harness_sha256` spans
the same directory, so `_IDENTITY_FIELDS` shifts with it. An `--out-dir` filled
by pre-merge code is therefore refused at whichever gate it reaches first:
`check_manifest` raises `RunManifestMismatchError` against the manifest an
earlier pass left, and `reconcile_extraction_identity` raises
`ExtractionIdentityMismatchError` against rows whose identity record disagrees —
the refusal §7's pre-priming caches get, through the same record. No flag waives
either check, and the ways forward are the ones those errors themselves name: run
against a **new `--out-dir`**, which always works and leaves the paid rows where
they are, replayable by the revision that wrote them; or **re-run with the
recorded settings**, which for a harness digest means the revision of
`benchmarks/longmemeval/` that record was written under. Deleting
`extractions.jsonl` is admitted too — with no rows left there is nothing to
misattribute, so a disagreeing identity record is replaced rather than enforced —
but it does not clear the manifest gate by itself, and it re-pays every
extraction call. No path carries a pre-merge cache across at half price.

**This buys nothing against a server that will not serve it.** The reference
launch recorded in §5 carries `--max-num-seqs 1`, which admits one sequence at a
time: against that configuration N concurrent questions simply queue at the
endpoint and the pass takes as long as it always did. Raising N is worth doing
only together with a serving configuration that admits concurrent sequences —
and either way, the width that actually ran is on the record.

---

## 9. Stopping: the operator's Ctrl-C, and an endpoint that has gone dark (2026-08-31)

§8 left three things open, and they are the same thing seen from three sides: a
pass that is stopping has to stop at a place a resume can pick up from, and it
has to be able to say what it did not get to.

### Ctrl-C stops at a question boundary, at every width

A question is either **walked to its end or not started** — §6's failure policy
in one line, and what makes a resume cheap. A part-extracted question is not
lost, because rows are durable the moment they are appended, but it *is* replayed
from its first session on the next pass (§7: the priming vocabulary for a pending
session is derived from the sessions before it), so every session dropped part
way through a question is a session walked again next time.

Above one worker the interrupt already landed at that boundary for free: it
arrives in the main thread while it is draining the pool, the queued questions
are dropped, and the running ones are allowed to finish before the exception
leaves. At the default of one worker there is no pool and no such boundary — the
question is being walked on the very thread the interrupt lands on, so it was
abandoned mid-question, which is the one shape the policy says never happens.

So SIGINT is now deferred around the serial path: the handler sets the same halt
a failure sets, submission stops immediately, the question in flight is walked to
its end, and `KeyboardInterrupt` is raised once the pass has drained. A **second**
Ctrl-C is the interpreter's own again — an operator pressing it twice is no
longer asking to stop tidily. Nothing is installed off the main thread, where
CPython delivers no SIGINT to defer.

### The retry budget belongs to the endpoint, not to each request

Retries are for a *transient* refusal: re-send and it gets through, and a run
measured in hours must not end on the first busy socket. A **wedged** endpoint is
the other thing — every attempt costs the whole timeout and none of them will
return — and against it the per-request budget is not resilience, it is a
multiplier: at N workers every question in flight independently pays
`attempts x timeout` to establish the one fact the first round of attempts
already established. At the pinned 600 s and 3 attempts that is half an hour per
question, all of it after the answer was known.

`clients.EndpointCircuit` makes the budget the endpoint's. `attempts` consecutive
failures with no answer between them — however they were spread across whatever
was in flight — and the endpoint is presumed wedged; requests then fail
immediately, as `EndpointWedgedError`, a `LocalModelTransportError` like any
other except in what it cost to produce. Only *reachability* counts: a server
that answers with something this harness refuses is a server that is working
(§6, `LocalModelResponseError`, deliberately never retried), and letting that
trip the breaker would take a run down over a prompt.

The presumption is provisional, because the alternative is worse than the stall:
an endpoint written off for the rest of an overnight run over one bad minute.
After a cooldown exactly one request is let through as a probe — one, so a dead
endpoint costs one timeout per window rather than one per request — and an answer
closes the circuit. A probe that fails re-opens it and the window starts again.
One circuit belongs to one client, which is what the extraction stage shares
across its workers; two clients built separately over the same endpoint hold
separate presumptions about it, which is a bound on the claim rather than a
defect, since nothing here runs two of them at once.

### What a stopped pass reports

`QuestionExtraction.started` records that a question was never begun. It used to
be written and never read: the only path that set it false also raised before any
caller could reach the outcomes, so the fact had nowhere to go.
`QuestionExtractionError.not_started` is now made of it, and the interrupt path
counts it — the questions a re-run still has to get through, read off the
outcomes rather than asserted in prose beside them.

### The cache this retires

**Merging this change retires every extraction cache written before it**, exactly
as §8's widening did and for the same reason: `real_run.py` and `clients.py` are
both inside `_EXTRACTION_HARNESS_ROOTS`, so `extraction_harness_sha256` moves and
`extraction_identity` moves with it. The ways forward are the ones §8 names — a
new `--out-dir`, or re-running under the revision the record was written under —
and none of them carries a pre-merge cache across at half price.
