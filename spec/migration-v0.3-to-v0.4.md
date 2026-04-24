# Migration v0.3 → v0.4

**Status:** Normative
**Version:** 0.4.0
**Date:** 2026-04-24

## 1. Why v0.4 is a wire break

v0.3 (2026-04-23) finished the DPKG → Aphelion rename on everything
*except* three items whose on-disk names had already been published to
downstream consumers: `dpkg_spec_version` in `manifest.json`, the
aggregate schema artifact name `schemas/dpkg-v0.3.json`, and the
`PX_E_*` error-code prefix. Preserving them in v0.3 let existing
packages keep validating.

v0.4 is the release where those last names come off the wire. After
v0.4, no Aphelion implementation should accept a manifest that carries
`dpkg_spec_version` or advertises `format_version` 1.0 / 1.1.

## 2. Concrete changes

| Item | v0.3 (kept on wire) | v0.4 (after migration) |
|---|---|---|
| `manifest.format_version` | `"1.0"` (legacy), `"1.1"` (current) | `"2.0"` |
| Manifest spec-version field | `dpkg_spec_version` (optional, semver) | `aphelion_spec_version` (optional, semver) |
| Aggregate schema artifact | `schemas/dpkg-v0.3.json` | `schemas/aphelion-v0.4.json` (new; the v0.3 file remains as a historical artifact) |
| Sample diff schema | `schemas/diff-v0.3.json` | `schemas/diff-v0.4.json` |
| Sample expected-normalized schema | `schemas/expected-normalized-v0.3.json` | `schemas/expected-normalized-v0.4.json` |

`PX_E_*` error codes remain unchanged — they are the Parallax-ecosystem
error taxonomy and their stability extends beyond Aphelion itself.

## 3. Migration contract

The reference CLI ships `aphe migrate` (`aphelion.migrate` module) as a
one-shot, forward-only transform. It is intentionally **not** a
generic migration framework.

### 3.1 Preconditions

Given an input manifest `M`:

- `M["format_version"]` is one of `{"1.0", "1.1"}`.
- `M` passes v0.3 syntax validation (the migration does not attempt to
  salvage malformed manifests).

### 3.2 Postconditions

The returned manifest `M'` satisfies:

- `M'["format_version"] == "2.0"`.
- `M'["aphelion_spec_version"] == "0.4.0"`.
- Neither top-level `M'["dpkg_spec_version"]` nor
  `M'["extensions"]["dpkg_spec_version"]` exists.
- Every other key in `M` is copied verbatim, including `claims`,
  `created_at`, `producer`, and any application-defined keys under
  `extensions` other than `dpkg_spec_version`.
- `M'` passes v0.4 strict validation.

### 3.3 Archive and directory wrappers

`migrate_directory(src, dst)` recursively copies every file under
`src` to `dst` byte-for-byte, then rewrites only `manifest.json`
through the transform above. Claim files and `provenance.jsonl` are
preserved exactly — their hashes continue to match.

`migrate_archive(src.aphelion.tar, dst.aphelion.tar)` does the same
for packed archives: every non-manifest member is passed through
unchanged; `manifest.json` is rewritten inside a new deterministic
`ustar` archive.

### 3.4 Archive budget (required)

Because `migrate_archive` reads a potentially-untrusted v0.3 tar, it
MUST enforce the same extraction policy caps as `aphelion.unpacker`:

| Cap | Default | Error code |
|---|---|---|
| `MAX_ARCHIVE_MEMBERS` | `10_000` | `PX_E_6009` (`FILE_COUNT_EXCEEDED`) |
| `MAX_ARCHIVE_MEMBER_BYTES` | `25 MiB` | `PX_E_6010` (`FILE_BYTES_EXCEEDED`) |
| `MAX_ARCHIVE_TOTAL_BYTES` | `100 MiB` | `PX_E_6011` (`TOTAL_BYTES_EXCEEDED`) |

Caps are checked against the tar header's declared `size` **before**
reading member bytes into memory, so a hostile oversized member cannot
force an OOM via `extractfile().read()`. Tar members that are neither
regular files nor directories (symlink / hardlink / device / fifo)
raise `PX_E_6008` (`DISALLOWED_MEMBER_TYPE`). Directory entries pass
through as header-only members to preserve on-disk layout.

Implementations MAY raise the caps, but MUST NOT lower them below the
defaults without spec amendment.

### 3.5 Atomicity

`migrate_archive` writes the output tar through a sibling `.tmp`
file, then atomically renames it into place via `os.replace`.
Interrupted migrations never leave a half-written destination that the
refuses-existing branch would subsequently lock in.

### 3.6 CLI contract

`aphe migrate` refuses to overwrite an existing destination unless
`--force` is passed.

## 4. What migration does NOT do

- Rename downstream wire fields outside the Aphelion package (e.g.
  Parallax's `dpkg_doc_id` SQL column migrates via `m0012`, not via
  this tool).
- Downgrade a v0.4 package to v0.3. v0.4 is forward-only.
- Re-sign a signed manifest. If `signature` is present, the new
  manifest's `aphelion_spec_version` change invalidates the old
  signature and the package owner must re-sign.
