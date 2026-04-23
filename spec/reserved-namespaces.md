# Aphelion Reserved Namespaces

**Version:** 1.0
**Status:** Normative
**Date:** 2026-04-21

## Purpose

Two prefix namespaces are reserved for application-defined extensions. Aphelion
tooling treats them as opaque: preserved verbatim on read/write, excluded from
identity computation, ignored by diff comparisons for semantic equality.

## Reserved Prefixes

| Prefix | Audience | Example key |
|---|---|---|
| `parallax:` | Parallax adapter metadata | `parallax:aggregation_level` |
| `internal:` | Any consumer's private overlay | `internal:debug_trace_id` |

These prefixes MAY appear as keys anywhere an extension object is permitted
(manifest `extensions`, claim frontmatter `annotations`/`labels`, provenance
event free-form fields). They MUST NOT appear as top-level required manifest
fields or as frontmatter keys defined in `schema-matrix.md`.

## Normative Rules

1. **Preservation.** Aphelion packers and unpackers MUST round-trip reserved-prefix
   keys byte-identically (after NFC normalization and canonical sort).
2. **Identity.** The `content_hash` canonical projection MUST exclude all keys
   whose name starts with `parallax:` or `internal:`. See `spec/content-hash.md`.
3. **Diff.** `aphelion diff` MUST NOT report differences in reserved-prefix keys
   under the `per_claim_evidence_diff.changed` layer. A separate
   `extensions_diff` layer MAY surface them informationally.
4. **Validator.** The validator MUST accept any valid JSON value for
   reserved-prefix keys without type constraints.
5. **Exchange profile.** The set of semantically meaningful reserved keys for
   a given adapter is documented in that adapter's exchange profile (e.g.
   `spec/parallax-exchange.md` in the Parallax repo). Aphelion has no view into
   them.

## Rationale

Adapters such as the Parallax import/export layer need to carry round-trip
metadata (originating table ids, aggregation levels, cache annotations)
without affecting the canonical Aphelion identity surface. Reserving fixed
prefixes lets validators ignore them safely while preserving application
state.
