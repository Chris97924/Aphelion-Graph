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
