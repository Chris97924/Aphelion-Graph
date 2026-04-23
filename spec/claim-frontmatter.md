# DPKG Claim Frontmatter Field Table

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
   annotations → author → author_uri → claim_id → claim_instance_id → confidence → created_at → labels → locale → object → predicate → source → state → subject → tags → type → updated_at
   ```
2. Unknown `format-*` fields MUST NOT appear. Unknown `application-defined` fields MAY appear only under `labels` or `annotations`.
3. `updated_at >= created_at`; otherwise `ERR-SEM-016`.
4. `claim_instance_id != claim_id` (they occupy different identity spaces).
5. `state` in frontmatter mirrors `manifest.json.claims[].state`; on conflict manifest wins (`ERR-SEM-020`).

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
Chris prefers per-claim SHA-256 as the DPKG content-hash granularity.
```
