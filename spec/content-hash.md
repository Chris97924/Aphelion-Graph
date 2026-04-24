# Aphelion content_hash — Canonicalization & Identity

**Version:** 0.3.0
**Status:** Normative
**Date:** 2026-04-21
**Supersedes:** `canonical-serialization.md` §Rule 1 for claim-level identity hashing.

## 1. Purpose

Two independent implementations MUST compute the same 64-hex-character
`content_hash` for the same logical claim payload, regardless of language,
platform, or locale. This document fixes the canonical byte form, the
hash algorithm, and the projection of a claim that participates in
identity.

## 2. Algorithm

```
content_hash = lowercase_hex( SHA-256( canonical_bytes( projection(claim) ) ) )
```

- Canonicalization: **RFC 8785 — JSON Canonicalization Scheme (JCS)**.
- Hash: **SHA-256** (FIPS 180-4), output 32 bytes.
- Encoding of output: 64 lowercase hex characters (`[0-9a-f]{64}`).
  Implementations MUST NOT emit uppercase or mixed-case hex.

RFC 8785 is normative. Where `canonical-serialization.md` Rule 1 and
RFC 8785 disagree on detail (e.g. number form for non-integer values),
**RFC 8785 governs for content_hash** and `canonical-serialization.md`
governs for the on-tar JSON files.

## 3. Projection — fields that participate in identity

The canonical projection is the ordered set of frontmatter fields below.
Any field not in this list MUST be dropped before canonicalization.
Any field in this list that is absent from the source claim MUST be
omitted entirely (it MUST NOT be emitted as `null`, `""`, `0`, or `[]`).

```
annotations
author
author_uri
confidence
labels
locale
object
predicate
source
state
subject
tags
type
```

Notes:

- `claim_id` and `claim_instance_id` are identifiers, **not** identity
  fields. They are excluded from the projection; otherwise the hash
  would be tautological.
- `created_at`, `updated_at`, and any other timestamp are excluded
  (see §4).
- Archive-level metadata (tar mtime/uid/gid/atime, file permission bits,
  `package_id`, `producer`, `license`, `signature`, `format_version`,
  `aphelion_spec_version`, `exchange_profile_version`) is excluded.

## 4. Explicit exclusion list

The following keys MUST be stripped from the projection before
canonicalization. Implementations MUST enforce this list even when the
key appears nested inside `annotations` or `labels`.

| Key / prefix | Rationale |
|---|---|
| `content_hash` | Self-reference; would break fixed-point computation |
| `hash` | Manifest echo of content_hash; excluded identically |
| `created_at` | Wall-clock timestamp; identity is time-independent |
| `updated_at` | Ditto |
| `last_seen_at` | Caching/aggregation metadata; not on-wire identity |
| `package_id` | Archive identifier; not claim identity |
| `archive_digest` | Tar-bytes hash; see §6 |
| `tar_mtime`, `tar_uid`, `tar_gid`, `tar_atime` | File metadata |
| `signature` | Detached signature over the package, not the claim |
| `parallax:*` (prefix) | Adapter-reserved namespace |
| `internal:*` (prefix) | Consumer-private namespace |

Reserved-prefix keys (`parallax:` / `internal:`) MUST be preserved
verbatim on the wire, but MUST NOT affect `content_hash`. See
`spec/reserved-namespaces.md`.

## 5. Determinism rules

RFC 8785 already pins JSON object key order (I-JSON), string escapes,
and number form. In addition:

1. **Unicode**: every string value MUST be NFC-normalized before
   canonicalization. NFD inputs hash identically to their NFC
   counterparts.
2. **Confidence**: the `confidence` field is a number in `[0.0, 1.0]`
   rendered with exactly 3 decimal places in the JSON canonical form
   (e.g. `0.900`, not `0.9` or `9.0e-1`). See
   `canonical-serialization.md` Rule 1.5 for the rationale.
3. **Tag order**: `tags` MUST be sorted ascending by Unicode codepoint
   after NFC normalization before canonicalization, so input order is
   irrelevant to the hash.
4. **Empty absences**: absent optional fields are omitted. `[]` vs
   missing `tags` hash differently and that is intentional.

## 6. Archive digest vs content_hash

`archive_digest` = SHA-256 of the packaged tar byte stream (see
`packaging.md`). It is **distinct** from any claim's `content_hash`.

- `content_hash` identifies a claim's semantic payload; repackaging the
  same claims produces the same `content_hash` values.
- `archive_digest` identifies a packaging event; re-packaging the same
  claims can produce different archive digests if tar metadata
  (producer, created_at, file ordering) differs.

Implementations MUST NOT use `archive_digest` in claim-level identity
computation and MUST NOT use `content_hash` to attest package integrity.

## 7. Test vectors

Authoritative test vectors live at `tests/vectors/hash_vectors.json`.
Every conformant implementation MUST reproduce the `expected_hash` for
every entry. See also `tests/test_content_hash.py`.

## 8. Migration from format_version 1.x (v0.3)

The v1.x hash in `manifest.json.claims[].hash` was defined against the
older `canonical-serialization.md` Rule 1 as extended by v0.3. For
claims authored under format_version 2.0 the `hash` field MUST be
computed per this document. v0.4 validators reject v1.x packages
directly; run `aphe migrate` (see `spec/migration-v0.3-to-v0.4.md`) to
lift the manifest, then re-validate. Strict mode requires v0.4
canonical hashing whenever `aphelion_spec_version >= "0.4.0"`.
