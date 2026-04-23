# DPKG Schema Responsibility Matrix

**Version:** 1.0
**Status:** Normative
**Date:** 2026-04-21

## Owner Tags (exactly one per field)

| Tag | Meaning |
|---|---|
| `format-required` | DPKG format mandates the field. Missing → validator ERROR. |
| `format-optional` | DPKG format recognizes the field. Producers MAY emit; consumers MUST handle absence. |
| `application-defined` | Out of DPKG's concern. Applications may add, DPKG validators MUST ignore. |

## Mirror Conflict Rule

Some fields appear both in `manifest.json` (package-level) and in per-claim frontmatter (claim-level). On conflict: **`manifest.json` wins**. A validator MUST emit `ERR-SEM-020` if they disagree, but the canonical value for consumers is always `manifest.json`.

### Mirrored fields (complete enumeration)

The following fields — and ONLY these fields — are mirrored between `manifest.json.claims[].*` and per-claim frontmatter:

- `claim_id`
- `claim_instance_id`
- `state`
- `tags`

All other fields are single-homed. Specifically:

- **Manifest-only** (no frontmatter counterpart; validators MUST NOT cross-check): `hash`, `path`, `superseded_by_claim_id`, `withdrawn_reason`, `labels` (manifest-scoped).
- **Frontmatter-only** (no manifest counterpart): `type`, `created_at`, `updated_at`, `source`, `confidence`, `subject`, `predicate`, `object`, `locale`, `author`, `author_uri`, `annotations`, `labels` (claim-scoped).

`labels` appears on both sides but is NOT mirrored — the manifest's `labels` and the claim's `labels` are independent application-defined maps. Validators MUST NOT compare them.

---

## `manifest.json` Fields

| Field | Type | Owner |
|---|---|---|
| `package_id` | uuid-v7 | format-required |
| `format_version` | string (`"1.0"`) | format-required |
| `created_at` | iso8601-Z | format-required |
| `producer` | string | format-required |
| `claims` | array<object> | format-required |
| `claims[].claim_id` | uuid-v7 | format-required |
| `claims[].claim_instance_id` | uuid-v7 | format-required |
| `claims[].state` | enum(draft,active,superseded,withdrawn) | format-required |
| `claims[].hash` | sha256-hex | format-required |
| `claims[].path` | string | format-required |
| `claims[].superseded_by_claim_id` | uuid-v7 | format-optional |
| `claims[].withdrawn_reason` | string | format-optional |
| `claims[].tags` | array<string> | format-optional |
| `claims[].labels` | object<string,string> | application-defined |
| `provenance_path` | string (`"provenance.jsonl"`) | format-required |
| `license` | string (SPDX) | format-required |
| `notice_path` | string | format-optional |
| `signature` | object | format-optional |
| `signature.algorithm` | string | format-optional |
| `signature.public_key` | string | format-optional |
| `signature.value` | string (base64) | format-optional |
| `extensions` | object | application-defined |

---

## Claim Frontmatter Fields (YAML inside `claim.md`)

| Field | Type | Owner |
|---|---|---|
| `claim_id` | uuid-v7 | format-required |
| `claim_instance_id` | uuid-v7 | format-required |
| `state` | enum | format-required |
| `type` | string | format-required |
| `created_at` | iso8601-Z | format-required |
| `updated_at` | iso8601-Z | format-required |
| `source` | string | format-required |
| `confidence` | number (0.0–1.0) | format-optional |
| `subject` | string | format-optional |
| `predicate` | string | format-optional |
| `object` | string | format-optional |
| `tags` | array<string> | format-optional |
| `locale` | string (BCP 47) | format-optional |
| `author` | string | format-optional |
| `author_uri` | string | format-optional |
| `labels` | object | application-defined |
| `annotations` | object | application-defined |

---

## `provenance.jsonl` Event Fields

| Field | Type | Owner |
|---|---|---|
| `event_id` | uuid-v7 | format-required |
| `event_type` | enum(create,publish,reaffirm,revise,supersede,withdraw) | format-required |
| `timestamp` | iso8601-Z | format-required |
| `claim_id` | uuid-v7 | format-required |
| `claim_instance_id` | uuid-v7 | format-required-on(create,revise,supersede); format-optional otherwise |
| `actor` | string | format-required |
| `prev_event_id` | uuid-v7 | format-required-on(non-create); MUST-be-absent-on(create) |
| `superseded_by_claim_id` | uuid-v7 | format-required-on(supersede) |
| `reason` | string | format-optional |
| `extensions` | object | application-defined |

---

## Rule Summary

- No field listed above is ambiguous. Every name maps to exactly one owner tag.
- Validators MUST treat `application-defined` fields as pass-through: ignored for DPKG correctness, preserved on round-trip.
- Producers MUST NOT name their own fields using any of the `format-required` or `format-optional` names for different purposes.
- On `manifest.json` vs claim frontmatter mismatch for a mirrored field (`claim_id`, `claim_instance_id`, `state`): the `manifest.json` value is canonical.
