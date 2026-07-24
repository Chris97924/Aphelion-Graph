# LongMemEval 3-Arm Benchmark — Design

> **PINNED 2026-07-19 — pre-registered thresholds frozen by the maintainer. The
> §4 metric gates and the §5.2 model/seed pins are now binding; no pinned value
> may move after any arm is run. Execution runs in the next drive under exactly
> these gates.**
>
> This document is a *design*, not a result. It defines the arms, corpus,
> metrics, and pre-registered decision gates. No arm has been run. The
> thresholds in §4 were pinned by the maintainer on 2026-07-19 (previously
> drafts inherited from the roadmap's v0.2-era design) and are now frozen and
> binding. They may not be moved after any result is seen — running first and
> choosing thresholds afterward defeats the entire pre-registration guard.

**Status:** Pinned (design-only) — thresholds frozen 2026-07-19
**Date:** 2026-07-17
**Pinned:** 2026-07-19
**Amended:** 2026-07-22 — §2.3 Arm C coalescing-rule *rationale* strengthened (codex r3 residual P2, PR #16): the conflict-preservation / R4-projection reasoning is now spelled out. The normative rule is unchanged, no §4 threshold moved, and no arm has run — a protocol-legal pre-registration amendment (§6.3).
**Amended:** 2026-07-24 — §2.3 amendment's R4-exclusion enumeration completed with `valid_until` (PR #18 residual P2): it is the fourth §6.5 R4-trigger field (`polarity`/`valid_from`/`valid_until`/`supersedes`) and is excluded from the `content_hash` identity projection like the others. Rationale-only — the normative rule is unchanged, no §4 threshold moved, and no arm has run — a protocol-legal pre-registration amendment (§6.3).
**Targets:** aphelion 0.6.0 · wire spec 0.4.0 · schema 2.0
**Scope of this drive:** design only — no harness code, no benchmark execution.

---

## 1. Background & the G2 kill-gate

Aphelion shipped its full claim-semantics stack — content-hash identity
(`spec/content-hash.md`), the lifecycle state machine
(`spec/lifecycle-state-machine.md`), the R1–R4 reader-side conflict machinery
(`spec/v0.3-claim-semantics.md`), a package signer (`spec/v0.5-signer-trust.md`),
and notary attestation (`spec/v0.6-notary-attestation.md`) — on design
conviction and green unit tests. Every one of those layers was justified by an
argument about what *should* make memory better. None was ever measured against
the question the roadmap itself posed at gate **G2**:

> **G2 kill-gate (roadmap SSoT):** *benchmark shows no gain → spec 回修.*

That gate was never executed. The format matured from v0.3 to v0.6 without a
single empirical check on whether the event state machine, content-hash dedup,
and R4 conflict classification actually improve memory-QA quality over a plain
baseline. This document is the **補課** (make-up work): it operationalizes G2 so
the kill-gate can finally fire.

**Why now.** Aphelion is `aphelion 0.6.0` on PyPI, the `aphe` CLI is stable, and
the R1–R4 machinery is shipped and load-bearing. The format is "done" enough
that the honest question is now answerable: *does the machinery earn its
complexity?* If the benchmark shows no gain, the roadmap's own rule says revise
the spec — not ship more features on top of an unvalidated base.

**This is a kill-gate, not a victory lap.** The design deliberately makes a
positive result hard to manufacture: it includes a naive-dedup control (Arm B,
§2), pre-registers every threshold before any run (§4, §6), and treats a
negative outcome as a first-class, respected result that triggers `spec 回修`
per §8. A benchmark that can only confirm the hypothesis is not a kill-gate.

---

## 2. Arms

Three memory backends sit behind one shared QA pipeline (§7). The **only**
independent variable across arms is the memory-quality layer; the extractor, the
retriever, the answering model, and the judge are identical for A, B, and C.

### 2.1 Arm A — plain

Store each extracted memory as a flat claim (`.md` + YAML frontmatter). No
content-hash, no `provenance.jsonl` events, no R1–R4 fields. On a duplicate or an
updated fact, keep both copies. This is "dumb memory" — what you get from a
markdown-and-YAML store with none of aphelion's machinery. It is the floor.

### 2.2 Arm B — naive-dedup (the honest middle control)

Arm A **plus** exact-string-match dedup: two claims collapse iff their body text
is byte-equal after trivial whitespace trimming (strip leading/trailing
whitespace, collapse internal runs to a single space). No canonical projection,
no semantic hashing, no state machine, no valid-time. This is the three-line
dedup any engineer writes without a spec.

Arm B exists to answer the decisive question: **if Arm C beats Arm A but not
Arm B, then aphelion's event state machine, RFC-8785 content-hash, and R4
classification added nothing** — the win came from "dedup at all," which a naive
control already buys. C must beat B, not merely A, to justify the machinery.

### 2.3 Arm C — aphelion full

Arm C exercises exactly the memory-quality machinery under test:

| Mechanism | Spec | What it does in the arm |
|---|---|---|
| **content_hash dedup** | `spec/content-hash.md` | RFC 8785 (JCS) canonicalization of the identity projection → SHA-256. Two claims coalesce (`duplicate` merge-verdict) **only** when they share the same `claim_id` (same lineage) **and** their 64-hex `content_hash` is byte-equal — **never** by textual proximity, embedding similarity, or any fuzzy/near-duplicate heuristic. (Same `claim_id` with a differing `content_hash` is a hash-collision error, not a coalesce; see `spec/lifecycle-state-machine.md` §5.1.) |
| **Event state machine** | `spec/lifecycle-state-machine.md` | `create / revise / reaffirm / withdraw / supersede`; canonical event order `(occurred_at_ms, event_id_lex)`; `superseded` and `withdrawn` claims become read-only and are suppressed from retrieval surfacing. |
| **R4 conflict classification** | `spec/v0.3-claim-semantics.md` | Reader-side: subject-group the active set, apply R2 valid-time filtering, resolve the `supersedes` graph, emit `conflict_class ∈ {none, scope_mismatch, supersession, contradiction, ambiguity}`. The verdict governs surfacing: `none`/`supersession` yield a single `primary`; `ambiguity` yields a `primary` (the definite claim) plus the others; **`contradiction` yields NO `primary` — every conflicting claim is surfaced** (`src/aphelion/read_adapter.py` `_residual_default_policy`; `tests/test_read_adapter.py::test_polarity_divergence_returns_contradiction`). Surfacing removes only truly `superseded`/`withdrawn` claims. |

**Coalescing rule (pre-registered 2026-07-19, normative for Arm C).** Arm C MUST
coalesce two claims **iff both** conditions hold: (1) identical `claim_id` (same
lineage) **and** (2) byte-equal 64-hex `content_hash`. Coalescing by textual
proximity, cosine/embedding similarity, or any near-duplicate heuristic is
forbidden — content-hash identity is lineage-scoped, not a similarity match. The
Arm C **implementation** (next drive) MUST enforce both conditions and ship a
regression test proving a same-`content_hash` / different-`claim_id` pair does NOT
coalesce and that no proximity-only pair coalesces.

**Amendment 2026-07-22 (codex r3 residual P2, PR #16) — why the `claim_id` gate is
load-bearing.** The rule above was already lineage-gated at the 2026-07-19 pin; this
amendment records the conflict-preservation reason codex r3 flagged as under-stated,
and formally logs its closure. The `content_hash` identity projection
(`spec/content-hash.md` §3–§4) deliberately **excludes** the R4 conflict fields —
`supersedes`, `valid_from`, `valid_until`, `polarity`, `conflict_class` — as well as `claim_id`
itself; identity is projected over `subject`, `predicate`, `object`, `state`, and the
other content fields only. Two claims can therefore be byte-equal in `content_hash`
yet differ in R4 — e.g. opposite `polarity`, a live **contradiction**. Coalescing on
`content_hash` alone (dropping the `claim_id` gate) would merge such a
different-`claim_id` / same-`content_hash` pair **before** R4 runs and silently erase
the conflict — but that pair is *not* a duplicate; it is exactly the input the §2.3
R4 row must classify. A pre-R4 collapse both **inflates M2** (a false duplicate scored
as a real merge) and **poisons M3** (the erased contradiction never surfaces, so
stale/conflicting context escapes the contamination count). Gating coalescing on
`claim_id` keeps it lineage-scoped so cross-lineage `content_hash` collisions reach R4
intact. This strengthens rationale only: the normative rule text is unchanged, no §4
numeric gate moves, and no arm has run — a protocol-legal pre-registration amendment
(§6.3).

At query time Arm C returns, for each retrieved candidate set, the R4-resolved
result: `superseded`/`withdrawn` claims are removed, and the surviving active set
carries an R4 verdict. Arm C surfaces a single primary only when the verdict is
`none`, `supersession`, or `ambiguity`; when the verdict is `contradiction` it
surfaces **all** conflicting claims with no primary — not the raw pile A and B
return, but not a single artificially-chosen winner either.

**Harness note (contradiction handling).** Arm C's retrieval MUST preserve the
`contradiction` contract — surface every conflicting claim, pick no winner. An
implementation that collapses a contradiction to one claim would hide a live
conflict and could spuriously inflate M1 (accidentally "answering" from one
arbitrary side) and distort M3. The metric harness treats a collapsed
contradiction as an Arm C implementation bug, not a result.

**Mechanism → metric map.** content_hash dedup is designed to move **M2**;
the event SM (`supersede`/`withdraw` suppression) plus R4 is designed to move
**M1** (answer the *current* fact) and **M3** (don't surface the stale one);
canonical serialization determinism underwrites **M5**.

### 2.4 Signer / notary — EXCLUDED (with rationale)

The v0.5 signer (`spec/v0.5-signer-trust.md`) and v0.6 notary
(`spec/v0.6-notary-attestation.md`) are **out of scope** for every arm:

1. **Orthogonal to memory quality.** A signer answers "who attests these package
   bytes are unaltered"; a notary answers "who vouches this key belongs to this
   signer." Both are *trust/provenance* questions. A LongMemEval question
   ("what was my 5K personal best?") is answered from claim *content*; no arm's
   answer changes based on whether the package is signed or notarized. They add
   **zero retrieval signal** — including them would only add packaging steps and
   latency to metrics that measure memory quality, moving no gate.
2. **Dependency cost, no benefit.** Real Ed25519 signing needs the
   `aphelion[signer]` crypto extra (`cryptography>=42`); the core is otherwise
   zero-dep. Pulling a crypto dependency into a memory-quality benchmark buys
   nothing measurable here.

Trust is a separate benchmark with its own threat model (tamper detection,
key-substitution, revocation). It does not belong in the G2 memory-quality
kill-gate.

---

## 3. Corpus (real recon)

Recon was run against the on-disk data directory. All filenames, byte sizes, and
counts below are measured, not assumed.

### 3.1 Files

Directory: `E:/Workspace/longmemeval/data/`

| File | Bytes | ~Size | Role |
|---|---:|---|---|
| `longmemeval_s_cleaned.json` | 277,383,467 | 264.5 MiB | **LongMemEval_S** — full haystack (distractor-heavy). Primary retrieval corpus. |
| `longmemeval_oracle.json` | 15,388,478 | 14.7 MiB | Oracle (evidence-only sessions). Source of gold answers + evidence-session labels. |
| `custom_history/sample_haystack_and_timestamp.py` | 21,503 | 21.0 KiB | Helper script (haystack / timestamp sampler). |

Both JSON files are top-level arrays of **500** question records with identical
keys: `answer`, `answer_session_ids`, `haystack_dates`, `haystack_session_ids`,
`haystack_sessions`, `question`, `question_date`, `question_id`,
`question_type`.

The two files describe the **same 500 questions** at two haystack depths:

- **oracle**: mean **1.9** sessions/question (evidence only) — used for gold
  answers and to label which sessions carry the evidence.
- **S (cleaned)**: mean **47.7** sessions/question (min 38, max 62), mean
  **~494** turns/question (min 396, max 616) — the real retrieval challenge with
  distractor sessions. This is what the extractor ingests.

### 3.2 Question-type distribution (measured, identical in both files)

| question_type | count |
|---|---:|
| temporal-reasoning | 133 |
| multi-session | 133 |
| knowledge-update | **78** |
| single-session-user | 70 |
| single-session-assistant | 56 |
| single-session-preference | 30 |
| **total** | **500** |

Abstention (`_abs`-suffixed question_id) variants: **30**.

### 3.3 Correction to the v0.2 corpus plan

The roadmap's v0.2-era design assumed **100 knowledge-update + 100 multi-session
= 200 (100 each)**. Recon shows this is **not achievable**: LongMemEval_S
contains only **78** knowledge-update questions total. There is no larger
knowledge-update pool in standard LongMemEval.

**Recommended corrected split (N = 200):**

- **All 78 knowledge-update** questions — the M1 gate rides on this subset, so
  the full pool is used to maximize statistical power.
- **122 multi-session** questions — fixed-seed sample from the 133 available.

Alternative (balanced) split: 78 + 78 = 156; recorded but not recommended
(discards knowledge-update power without buying internal validity).

**Statistical consequence (must be read honestly).** M1's gate is measured on
**N = 78**. A +3pp difference is ≈ 2.3 questions; a Wilson 95% CI near 50%
accuracy at N = 78 is roughly ±11pp. **M1 is underpowered** and must be reported
with a bootstrapped confidence interval and read as *directional*. The
statistical weight of the benchmark rests on **M2**, whose labeled duplicate set
(drawn from exact restatements across *both* subsets) is the only metric whose
power is *not* bounded by the 78-question knowledge-update pool. **M3 shares
M1's N = 78 knowledge-update denominator** — old→new value labels exist only for
knowledge-update questions — so M3 carries the same CI caveat; it is nonetheless
more reliable than M1 at that N because it is a mechanical check on the retrieved
set (does the stale value appear) rather than a judge-scored accuracy. Report
bootstrapped CIs on both M1 and M3.
This is a real limitation of the available data, surfaced here rather than
papered over — and it is the reason the §8 decision table gives M1 a two-round
rule instead of acting on a single underpowered result.

### 3.4 Data pipeline note

- **oracle** supplies the gold answer and the evidence-session labels.
- **S** supplies the haystack the memory extractor ingests.
- knowledge-update questions inherently encode an *old-value → new-value* update
  (the gold answer is the latest value) — the natural substrate for M1 and M3.
- multi-session questions supply cross-session aggregation/QA breadth.

---

## 4. Metrics & pre-registered thresholds

Every threshold below is **PINNED 2026-07-19** by the maintainer, carried from the
v0.2-era design. Numbers are unchanged from v0.2 unless a justification is stated;
annotations add context without moving the number. **They are now binding and
frozen.** They may not be moved after any result is seen (§6.3).

| # | Metric | Gate (pre-registered) | Rationale |
|---|---|---|---|
| **M1** | QA accuracy on knowledge-update | **C − B ≥ +3 pp** | The honest test is C beating the *naive-dedup* control, not plain A. +3pp is the v0.2 minimum improvement deemed worth the state-machine complexity. **Caveat:** N = 78 → ≈ 2.3 questions; report a bootstrapped CI and treat as directional (§3.3). Report C − A as secondary context. |
| **M2** | Dedup F1 (exact-duplicate detection) | **(C.F1 > A.F1 + 0.10) AND (C.F1 ≥ B.F1 − ε), ε = 0.02 (pinned 2026-07-19)** | Two arms. C must beat no-dedup by a wide margin (`A + 0.10`) **and must not regress below the naive-dedup control B** (`B − ε`). Without the second arm the gate is a false-positive trap: `A=0.00, B=0.90, C=0.11` would "pass" on `A + 0.10` alone while C is catastrophically worse than the honest control, validating broken machinery. content_hash is a superset of exact-string match, so C ≥ B is structurally expected; ε = 0.02 tolerates measurement noise on a tie. A genuine `C < B − ε` means the projection is over- or under-merging (see §8). Highest-power metric. **Annotation (pre-registered 2026-07-19, threshold unchanged — interpretation guidance only):** the `content_hash`-superset expectation above holds only *within a lineage*. Under the §2.3 lineage-gated coalescing rule (same `claim_id` **and** byte-equal `content_hash`), cross-lineage byte-identical duplicates that Arm B collapses will **not** coalesce in Arm C, so a `C.F1 < B.F1 − ε` deficit is no longer *automatically* a projection over/under-merge bug. The §8 M2-fail diagnosis MUST therefore first check whether the deficit is entirely attributable to such cross-lineage exact duplicates (a linker lineage-fragmentation artifact) before concluding the identity projection is at fault. |
| **M3** | Stale-info contamination rate (denominator N = 78 KU) | **C ≤ 0.5 × A** | `superseded`/`withdrawn` suppression should at least halve the rate at which a stale (superseded) value appears in the retrieved context, vs plain storage. Contamination = fraction of the **78 knowledge-update** answers whose retrieved context contains the *old* value — old→new value labels exist only for that subset, so N = 78 (same CI caveat as M1; §3.3). Multi-session questions are **not** a current M3 substrate (no stale-value labels); extending M3 to them is labeled future work requiring stale-value annotation, not current measurability. |
| **M4** | Storage / latency | **sanity-only — no gate** (soft tripwire at 10× Arm A) | Aphelion trades storage/compute for correctness; this benchmark judges correctness, so M4 is context, not a gate. Report p50/p95 query latency and on-disk bytes/claim; flag only pathological >10× A regressions. |
| **M5** | Cross-tool round-trip byte-equality | **100 / 100 SHA-256 byte-identical** | The `spec/canonical-serialization.md` contract is absolute: any single mismatch is a spec hole, not a quality tradeoff. **Precondition:** the existing `scripts/external_reader.py` reproduces only the validator verdict, *not* canonical bytes — M5 requires work item `W-M5` (a full canonical independent reader) or an explicit re-scope before it can run; see §7.4. |
| **AG** | Adversarial-set advantage (bias guard §6, item 4) | **diagnostic tripwire (non-gating): C − B ≤ +3 pp on the 20 adversarial questions** | New rule, pinned 2026-07-19 (v0.2 named the adversarial set but pinned no number). On questions where aphelion's machinery structurally cannot help, C must not gain more than the very margin M1 requires it to gain on the real set; a larger adversarial gain signals arm-identity leakage or spurious signal. Non-gating because N = 20 (+3pp ≈ 0.6 questions cannot support a hard pass/fail); a breach **mandates** a leakage investigation before M1/M3 are trusted. Pinned here so the rule is fixed before any run. |

**Also pre-registered (see §5, §6):** fixed random seed, answering-model
temperature = 0, pinned answering + judge model identifiers. The commit that
lands this document is the pre-registration record.

---

## 5. Answering & judge model plan

Two model roles, both pinned:

- **Answering model** — reads the retrieved context and produces the answer.
  Runs at **temperature 0** with a **pinned seed**, identical across A/B/C.
- **Judge model** — scores the answer against gold (LongMemEval-style
  LLM-as-judge with a fixed rubric). 200 questions × 3 arms = 600 judgements.

### 5.1 Candidates

| Option | Pros | Cons |
|---|---|---|
| Local GB10 ollama `gpt-oss:120b` (`192.168.1.134:11434`) | Zero token cost; on-prem; fully reproducible; same model can serve all three arms → arm differences attributable to memory quality, not model variance. | Below-frontier capability; ollama has minor batch nondeterminism even at temp 0; weaker as a judge. |
| Pinned frontier API snapshot (dated Claude or GPT) | Higher capability; stronger judge fidelity; snapshot pin gives reproducibility. | Per-token cost; reproducibility depends on the vendor not deprecating the snapshot. |

### 5.2 Recommendation (pinned 2026-07-19)

**Split the roles:**

- **Answering model = local `gpt-oss:120b` on GB10.** Zero-cost and reproducible,
  and — crucially — the *same* model serves all three arms, so any A/B/C delta is
  memory quality, not model variance. Answering is the high-volume path (600+
  generations); keeping it local and free matters most here.
- **Judge model = a pinned frontier API snapshot.** Judging is lower-volume and
  fidelity matters more than cost; a stronger judge reduces scoring noise on M1.

Whatever is chosen, the **same answering model and the same retriever must serve
A, B, and C** — the only variable is the memory layer. That is the core
internal-validity guard.

**Pinned models, retriever & knobs (frozen 2026-07-19):**

- **Answering model** = `gpt-oss:120b` @ GB10 ollama (`192.168.1.134:11434`).
- **Extractor model** = `gpt-oss:120b` @ GB10 ollama (`192.168.1.134:11434`) — the
  same model as answering.
- **Judge model** = `claude-opus-4-8` via `claude -p` (subscription); fallback
  `gemini-2.5-pro`.
- **Retriever** = shared deterministic BM25 (stdlib), identical across arms.
- **Seed** = `20260717`.
- **Answering temperature** = 0.
- **Fairness constraint** — the answering model, extractor model, and retriever
  MUST be identical across arms A/B/C; the memory layer is the only independent
  variable.

---

## 6. Bias guards

All five guards are mandatory. They exist because a memory format's author has
every incentive, conscious or not, to build a benchmark its format wins.

1. **Blind scoring (arm masking).** The judge receives `(question, gold,
   candidate_answer)` with **no arm label**. Candidate answers from A/B/C are
   shuffled and de-identified before scoring; the arm id is hashed out of the
   judge payload so the judge cannot favor "the fancy one."
2. **Fixed seed + temperature 0.** All generation at temp 0 with the pinned seed;
   the retriever is seeded; sampling is disabled. Pinned in the pre-registration
   (§5.2).
3. **Pre-registered thresholds.** The entire §4 table is committed *before* any
   run. The commit SHA of this document is the pre-registration timestamp.
   Thresholds may not be moved after results are seen; if they are moved, it is a
   documented protocol violation recorded in the results, not a silent edit.
4. **20 adversarial questions.** A held-out set of question types where
   aphelion's machinery should **not** help — e.g. single-session-preference /
   single-session-user questions with no updates and no duplicates (no
   supersession, no dedup opportunity). If Arm C "wins" here, it is winning
   *dishonestly* (spurious signal, or arm identity leaking into the pipeline).
   **Adversarial rule (pre-registered — §4 row AG):** C − B ≤ +3 pp on the 20
   adversarial questions. This is a non-gating diagnostic tripwire — N = 20 is
   too small for a hard gate — fixed here in advance so the response is not
   chosen post-hoc; a breach mandates a leakage investigation before M1/M3 are
   trusted. This checks that C wins for the *right reason*.
5. **50-question human diff spot-check.** A human manually reviews 50 questions'
   Arm A vs Arm C retrieved contexts and answers, confirming the automated
   judge's verdicts are not systematically wrong. Catches judge failure modes the
   automated pipeline cannot self-detect.

---

## 7. Harness plan

**Design only — this drive builds none of the below.** `benchmarks/` does not
exist yet; this is the planned layout.

### 7.1 Layout sketch

```
benchmarks/
  longmemeval/
    README.md
    preregister.json      # frozen thresholds + seed + model pins (hash-committed)
    corpus.py             # load oracle + S, build the 200-Q split (fixed seed)
    pipeline.py           # shared QA pipeline (arm-agnostic)
    arms/
      plain.py            # Arm A  — MemoryStore
      naive_dedup.py      # Arm B  — MemoryStore
      aphelion.py         # Arm C  — MemoryStore (uses aphe + content_hash + SM + R4)
    metrics/
      m1_qa.py
      m2_dedup.py
      m3_contamination.py
      m4_perf.py
      m5_roundtrip.py
    run.py                # orchestrator → results.jsonl + report
```

### 7.2 Dependency policy

**The shipped core (`src/aphelion/**`) stays zero-dependency, stdlib-only**, per
the README contract. The benchmark harness **may** carry dependencies (an LLM
client, ollama/OpenAI SDK, an F1/metrics helper, a reporting library) because
`benchmarks/` is **not part of the installed `aphelion` package** — it lives
outside `src/`, so its dependencies never enter `pip install aphelion`. Policy:
`benchmarks/` declares its own optional group (e.g. `aphelion[bench]`) or a
separate requirements file; the `src/aphelion/**` import graph must remain
stdlib-only, guarded by the existing AST-scan precedent in
`tests/test_external_reader.py`.

### 7.3 How the arms share one QA pipeline

All three arms implement a single `MemoryStore` protocol:

```
class MemoryStore(Protocol):
    def ingest(self, sessions: list[Session]) -> None: ...
    def retrieve(self, question: str) -> list[Claim]: ...
```

`pipeline.py` is arm-agnostic: **extract → ingest → retrieve → answer → judge.**
The extractor (session → claims) and the retriever (e.g. BM25 or embedding
top-k) are **identical** across arms. Only the post-retrieval memory-quality
layer differs:

- **A** returns the raw candidate set.
- **B** returns it after exact-string dedup.
- **C** returns it after content_hash coalescing + R4 resolution + `superseded`/
  `withdrawn` suppression — a *post-filter over the same candidate set A and B
  see.*

This guarantees the only independent variable is the memory layer.

**Central validity risk (called out, not hidden).** Arm C can only win M1/M3 if
the extraction pipeline actually emits the R4 edges — `supersedes`,
`valid_from`, `polarity` — that mark an update. A shared *linker* pass assigns a
`supersedes` edge (and `valid_from`) when it detects a new claim updating an
existing subject; Arms A/B ignore those edges. **The linker's recall bounds Arm
C's ceiling**: if the linker fails to detect updates, Arm C degenerates to Arm B
and M1/M3 cannot move — which is precisely the "M1 fail, M2/M3 pass" branch in
§8 that triggers a retriever/linker-integration rerun before any spec retreat.
The linker design is a next-drive concern; this document only fixes the contract
that it is a shared, arm-independent stage.

### 7.4 Reuse of existing repo assets

- **M5 — the existing `scripts/external_reader.py` does NOT satisfy byte-equality
  as-is.** It is a stdlib-only independent reader (no `import aphelion`), but by
  its own contract it "is NOT a full validator": it reproduces only the
  `validator_verdict` (valid/invalid) plus a minimal notes block, "without
  claiming to reproduce the full Aphelion canonical output" (`external_reader.py`
  header §Scope; `emit_sample_json` docstring). Its `samples/*` cross-check
  compares verdict semantics, not canonical bytes. M5 as specified (100/100
  SHA-256 byte-identical) therefore has an unmet precondition; the execution
  drive MUST pick one before running M5:
  - **(a) Recommended — work item `W-M5`:** expand `external_reader.py` into a
    full canonical reader that emits the byte-exact canonical form
    (`spec/canonical-serialization.md`), so a genuinely independent
    implementation's bytes can be SHA-256-compared against the reference. This is
    the honest two-implementation test of the cross-tool determinism claim.
  - **(b) Fallback — re-scope M5:** if a second full reader is out of budget,
    restate M5 as the reference packer's own round-trip determinism (pack →
    unpack → re-pack byte-identity, already exercised by the repo's differential
    tests) plus external-reader verdict agreement — and mark M5 as *not yet* a
    true two-implementation cross-check until (a) lands.
  - **Decision (maintainer, 2026-07-19):** option **(a)** is pinned — `W-M5` (the
    full canonical independent reader) is scheduled for the **execution drive**.
    The M5 gate is the true two-implementation byte-equality check and therefore
    **cannot run before `W-M5` lands**; until then M5 is blocked, not waived and
    not silently downgraded to (b).
- **Metric fixtures** reuse `samples/`: `revise-withdraw-flow` (create→revise→
  withdraw chain, final state `withdrawn`) for M3 suppression; `contradictory-claim`
  for R4 `contradiction`; `duplicate-reaffirm-collision` for M2 dedup edges.
- **Arm C packaging** uses the `aphe` CLI (`init` / `pack` / `unpack` / `verify`).

---

## 8. Kill-gate decision table

Outcomes are read against the pre-registered §4 gates. This is the G2 kill-gate,
operationalized.

| Outcome | Diagnosis | Action |
|---|---|---|
| **All pass** (M1, M2, M3, M5 gates; M4 sane) | The machinery earns its complexity — measurably better memory quality than both the plain floor and the naive-dedup control. | **GA** — publish the result as validation of the claim-semantics stack. |
| **M5 fail** | Cross-tool determinism hole in canonical serialization — a correctness bug, not a quality tradeoff. Highest priority regardless of other metrics. | **Fix the serialization spec; do NOT publish** until M5 is 100/100. |
| **M1 fail + M2 & M3 pass** | The mechanism *works* (dedup and contamination-suppression are measurable) but does not convert into QA accuracy — most likely a retriever/linker-integration gap, and M1 is underpowered at N = 78. | **Rerun with retriever/linker integration.** Only after **2 failed rounds** retreat and revise the spec — do not over-react to one underpowered result. |
| **M2 fail** | Either arm fails: C does not clear `A + 0.10` (dedup not working at all), or C regresses below `B − ε` (the naive control beats the machinery → projection over/under-merging). | **Recheck the content-hash identity projection / whitelist** (`spec/content-hash.md` §3–§4): is it dropping or keeping the wrong fields? A `C < B − ε` failure specifically points at over-merging (projection too coarse) or under-merging (too fine). |
| **M3 fail** | `superseded`/`withdrawn` suppression not reducing contamination. | **Demote the event state machine** — question whether `supersede`/`withdraw` belong in the retrieval-surfacing path at all. |
| **All fail** | The machinery is not validated. | **Do not publish.** Escalate to spec revision per G2 (`benchmark shows no gain → spec 回修`). |

**Honoring G2.** A negative result is a *success of the process*, not a failure:
it fires the kill-gate the roadmap promised and routes the format back to `spec
回修` instead of shipping more unvalidated machinery. The two-round rule on the
M1 branch exists so that a single underpowered N = 78 result cannot trigger a
premature spec retreat.

---

## Appendix — spec grounding index

Every claim in this design is anchored in a repo artifact:

- `spec/content-hash.md` — RFC 8785 (JCS) + SHA-256 identity projection (M2, Arm C dedup).
- `spec/lifecycle-state-machine.md` — event SM, canonical event order, read-only `superseded`/`withdrawn` (M1/M3, Arm C SM).
- `spec/v0.3-claim-semantics.md` — R1–R4 fields + `conflict_class` reader-side derivation (M1/M3, Arm C R4).
- `spec/canonical-serialization.md` — byte-identity contract (M5).
- `spec/v0.5-signer-trust.md`, `spec/v0.6-notary-attestation.md` — excluded layers (§2.4 rationale).
- `scripts/external_reader.py` — independent stdlib reader (M5 mechanism).
- `samples/{revise-withdraw-flow,contradictory-claim,duplicate-reaffirm-collision}` — metric fixtures.
- `README.md` — `aphelion 0.6.0`, spec 0.4.0, schema 2.0, zero-dep core, `aphe` CLI.
