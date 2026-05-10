# Aphelion Claim Frontmatter Field Table

**Version:** 1.0
**Status:** Normative
**Date:** 2026-04-21

Each claim is a `.md` file with YAML frontmatter between `---` fences, followed by markdown body. Frontmatter MUST obey `canonical-serialization.md` Rule 6 (YAML canonical form).

## Field Table

| Name | Type | Required | Format / Constraint | Example |
|---|---|---|---|---|
| `claim_id` | string | yes | UUID v7 | `0190ab63-5f8a-7a61-9b14-ffaa20c1d00d` |
| `claim_instance_id` | string | yes | UUID v7, unique per revision | `0190ab63-5f8a-7a61-9b14-ffaa20c1d00e` |
| `type` | string | yes | snake_case identifier; application-defined vocabulary | `user_preference` |
| `state` | string | yes | enum: `draft` \| `active` \| `superseded` \| `withdrawn` | `active` |
| `created_at` | string | yes | ISO 8601 UTC `Z` | `2026-04-21T00:00:00Z` |
| `updated_at` | string | yes | ISO 8601 UTC `Z`, `>= created_at` | `2026-04-21T00:10:00Z` |
| `source` | string | yes | opaque origin tag (e.g. `conversation`, `manual`, `import:cmemory`) | `conversation` |
| `confidence` | number | no | `0.0 <= x <= 1.0`; MUST serialize as exactly 3 decimal digits (e.g. `0.900`, not `0.9`) | `0.850` |
| `subject` | string | no | NFC; non-empty if present | `chris` |
| `predicate` | string | no | NFC; non-empty if present | `prefers` |
| `object` | string | no | NFC; non-empty if present | `per-claim sha256` |
| `tags` | array of string | no | unique; each element NFC-normalized; sorted **case-sensitive** ascending by Unicode codepoint after NFC (uppercase precedes lowercase) | `[parallax, preference]` |
| `locale` | string | no | BCP 47 tag | `en-US` |
| `author` | string | no | display name | `Chris` |
| `author_uri` | string | no | RFC 3986 URI | `https://chris.example` |
| `labels` | object | no | application-defined; string→string | `{priority: high}` |
| `annotations` | object | no | application-defined; arbitrary JSON-compatible | `{source_turn: 42}` |

## Rules

1. Field order in the serialized file MUST be ASCII-codepoint-ascending. Example field ordering in a canonical file (alphabetical):
   ```
   annotations → author → author_uri → claim_id → claim_instance_id → confidence → created_at → labels → locale → object → polarity → predicate → source → state → subject → supersedes → tags → type → updated_at → valid_from → valid_until
   ```
   v0.3-r1r4 additions inserted in canonical position. Violations raise `PX_E_4143 / E_CLAIM_KEY_ORDER`; use `aphe canonicalize` to repair.
2. Unknown `format-*` fields MUST NOT appear. Unknown `application-defined` fields MAY appear only under `labels` or `annotations`.
3. `updated_at >= created_at`; otherwise `ERR-SEM-016`.
4. `claim_instance_id != claim_id` (they occupy different identity spaces).
5. `state` in frontmatter mirrors `manifest.json.claims[].state`; on conflict manifest wins (`ERR-SEM-020`).
6. **v0.3-r1r4 conditional requirement (Chris-pinned 2026-05-09)**: if any of `polarity`, `valid_from`, `valid_until`, or `supersedes` is present on a claim, then `subject` MUST also be present and non-empty; otherwise `PX_E_4144 / E_CLAIM_SUBJECT_REQUIRED_FOR_CONFLICT`. `confidence` is deliberately excluded from this trigger list — it is metadata, not a conflict-graph opt-in signal (Chris-confirmed 2026-05-09 PM after Phase-4 review surfaced the backward-compat hazard). `subject` itself remains `format-optional` at the schema-matrix level — the conditional check is enforced by the v0.3 validator only. See `spec/v0.3-claim-semantics.md` §6.5 + `adr/0002-v0.3-claim-semantics-r1r4.md`.

## v0.3-r1r4 added fields (additive — see `spec/v0.3-claim-semantics.md`)

| Name | Type | Required | Format / Constraint | Example |
|---|---|---|---|---|
| `valid_from` | string | no (R2) | quoted ISO 8601 UTC `Z`, exact 20 chars | `"2026-05-09T10:00:00Z"` |
| `valid_until` | string | no (R2) | quoted ISO 8601 UTC `Z`, exact 20 chars; `>= valid_from` if both present | `"2026-12-31T23:59:59Z"` |
| `polarity` | string | no (R3) | enum `{affirm, negate, unknown}`, lowercase ASCII; defaults to `affirm` if absent | `"affirm"` |
| `supersedes` | array<string> | no (R4) | claim_id values (UUID v7), lex-sorted + dedupe; cross-package allowed (lenient warning if dangling) | `["0193e2b1-0001-7000-8000-00000000aaaa"]` |

## Example

```markdown
---
claim_id: "0190ab63-5f8a-7a61-9b14-ffaa20c1d00d"
claim_instance_id: "0190ab63-7c22-7b80-9b14-ffaa20c1d00e"
confidence: 0.900
created_at: "2026-04-21T00:00:00Z"
source: "conversation"
state: "active"
tags:
  - "parallax"
  - "preference"
type: "user_preference"
updated_at: "2026-04-21T00:00:00Z"
---
Chris prefers per-claim SHA-256 as the Aphelion content-hash granularity.
```
