# DPKG Identity & Event Semantics

**Version:** 1.0
**Status:** Normative
**Date:** 2026-04-21

## 1. Identifier Taxonomy

DPKG defines four identifier classes. Each has a distinct scope and stability rule.

| Identifier | Scope | Format | Stability |
|---|---|---|---|
| `package_id` | one DPKG package | UUID v7 | Immutable for the lifetime of the package |
| `claim_id` | one logical claim (lineage root) | UUID v7 | Immutable across revisions of the same claim |
| `claim_instance_id` | one snapshot of a claim | UUID v7 | Unique per revision; changes on revise/supersede |
| `event_id` | one provenance event | UUID v7 | Immutable; uniquely identifies a line in `provenance.jsonl` |

All identifiers MUST be UUID v7 (RFC 9562). Rationale: lexicographic order ≈ creation time, useful for tar-entry ordering and JSONL tailing.

### 1.1 `package_id`

- Assigned once at package creation.
- MUST NOT change on re-packaging, re-signing, or metadata rewrites. Re-packaging the same logical contents produces the same `package_id`; any change to claims means a new `package_id`.
- Appears once in `manifest.json.package_id`.

### 1.2 `claim_id`

- Assigned on first creation of a claim (event type `create`).
- MUST be stable across `reaffirm`, `revise`, and `supersede` events — a revision is still "the same claim".
- A `withdraw` does **not** free the `claim_id`; withdrawn claims remain addressable.
- When a claim is superseded by a **different** claim, the superseding claim gets a **new** `claim_id`. `supersede` events carry both `claim_id` (the old) and `superseded_by_claim_id` (the new).

### 1.3 `claim_instance_id`

- Assigned on every state-changing event that emits a new content body: `create`, `revise`, `supersede`.
- NOT emitted on `reaffirm` (reaffirm references the prior instance).
- NOT emitted on `withdraw` (withdraw references the prior instance).
- Each `claim_instance_id` hashes over a specific canonical body — `claim_instance_id` + body bytes form a content-addressable pair.

### 1.4 `event_id`

- Assigned on every line written to `provenance.jsonl`, including `reaffirm` and `withdraw`.
- Ordering rule: line order in `provenance.jsonl` MUST be **monotonic non-decreasing** by the UUID v7 48-bit timestamp component. When two events share the same millisecond, the tie is broken deterministically by **ASCII codepoint comparison of the full `event_id` string** (ascending). Producers MUST sort using this combined key before writing; implementers in different languages emitting the same logical event sequence produce identical line order.

---

## 2. Event State Machine

Every claim exists in exactly one state at any point in package time. States:

| State | Meaning |
|---|---|
| `draft` | Author is preparing the claim; not yet published. |
| `active` | Claim is live and consumable. |
| `reaffirmed` | Transient state after a `reaffirm` event; decays back to `active`. |
| `revised` | Transient state after a `revise` event; decays back to `active` under the new instance. |
| `superseded` | A different claim has replaced this one; read-only. |
| `withdrawn` | Retracted by author; read-only. |

`reaffirmed` and `revised` are **emitted states** — they exist in the event record but a claim's steady-state representation in `manifest.json` is always `draft`, `active`, `superseded`, or `withdrawn`. `reaffirm` and `revise` are round trips through a transient state back to `active`.

### 2.1 State Diagram

```
   (nil) ──create──▶ draft ──publish──▶ active
                                          │
                                          ├──reaffirm──▶ reaffirmed ──▶ active
                                          │
                                          ├──revise────▶ revised ─────▶ active
                                          │
                                          ├──supersede─▶ superseded  (terminal)
                                          │
                                          └──withdraw──▶ withdrawn   (terminal)
```

### 2.2 Legal Transitions (exhaustive)

| # | From | Event | To | Notes |
|---|---|---|---|---|
| L01 | (nil) | `create` | `draft` | Only way to enter the system. |
| L02 | `draft` | `publish` | `active` | Moves a draft into the live set. |
| L03 | `draft` | `withdraw` | `withdrawn` | Abandon before publishing. |
| L04 | `active` | `reaffirm` | `reaffirmed` → `active` | No body change; timestamp refresh. |
| L05 | `active` | `revise` | `revised` → `active` | New `claim_instance_id`; same `claim_id`. |
| L06 | `active` | `supersede` | `superseded` | Requires `superseded_by_claim_id` on event. |
| L07 | `active` | `withdraw` | `withdrawn` | Retraction. |
| L08 | `reaffirmed` | (auto) | `active` | Transient; resolves within the same event. |
| L09 | `revised` | (auto) | `active` | Transient; resolves within the same event. |

### 2.3 Illegal Transitions (exhaustive complement)

Any From/Event combination not listed in 2.2 is illegal. The full enumeration:

| # | From | Event | Why illegal |
|---|---|---|---|
| X01 | (nil) | `publish` | Cannot publish without a prior `create`. |
| X02 | (nil) | `reaffirm` | Nothing to reaffirm. |
| X03 | (nil) | `revise` | Nothing to revise. |
| X04 | (nil) | `supersede` | Nothing to supersede. |
| X05 | (nil) | `withdraw` | Nothing to withdraw. |
| X06 | `draft` | `create` | Already exists. |
| X07 | `draft` | `reaffirm` | Cannot reaffirm unpublished. |
| X08 | `draft` | `revise` | Cannot revise unpublished; edit the draft directly. |
| X09 | `draft` | `supersede` | Cannot supersede unpublished. |
| X10 | `active` | `create` | Duplicate create. |
| X11 | `active` | `publish` | Already published. |
| X12 | `superseded` | `create` | Terminal. |
| X13 | `superseded` | `publish` | Terminal. |
| X14 | `superseded` | `reaffirm` | Terminal — reaffirm the superseding claim instead. |
| X15 | `superseded` | `revise` | Terminal. |
| X16 | `superseded` | `supersede` | Terminal. |
| X17 | `superseded` | `withdraw` | Terminal — already retired. |
| X18 | `withdrawn` | `create` | Terminal. |
| X19 | `withdrawn` | `publish` | Terminal. |
| X20 | `withdrawn` | `reaffirm` | Terminal. |
| X21 | `withdrawn` | `revise` | Terminal. |
| X22 | `withdrawn` | `supersede` | Terminal. |
| X23 | `withdrawn` | `withdraw` | Already withdrawn; idempotent attempts are errors. |
| X24 | `reaffirmed` | * | Illegal as a persisted state; transient only. |
| X25 | `revised` | * | Illegal as a persisted state; transient only. |

A validator MUST reject any `provenance.jsonl` containing an illegal transition (see `validator.md` §ERR-SEM-010).

---

## 3. Stability Invariants

- **I-1** `claim_id` is fixed from `create` until the end of the claim's lineage.
- **I-2** `claim_instance_id` is unique within the package; no two events share one.
- **I-3** `event_id` is unique across the full `provenance.jsonl`.
- **I-4** `package_id` does not appear inside individual claims, only in `manifest.json`.
- **I-5** Ordering of events in `provenance.jsonl` MUST follow §1.4: monotonic non-decreasing by UUID v7 timestamp, with ties broken by ASCII codepoint comparison of the full `event_id`.
