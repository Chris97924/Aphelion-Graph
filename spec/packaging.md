# DPKG Packaging Spec

**Version:** 1.0
**Status:** Normative
**Date:** 2026-04-21

## Package Layout

A DPKG package is a `tar.gz` archive containing:

```
manifest.json
provenance.jsonl
LICENSE
NOTICE                       (optional)
claims/<claim_id>.md         (one per claim, filename = claim_id)
schemas/*.json               (optional; embedded schemas)
signatures/*.sig             (optional)
```

Path rules:
1. Paths MUST use forward slashes.
2. Paths MUST NOT contain `..`, absolute prefixes (`/`), or drive letters.
3. Filenames MUST be NFC-normalized lowercase where the content is not a UUID.
4. `claims/<uuid>.md` — the UUID MUST equal the claim's `claim_id` (lowercase hex).

## Rule 1 — tar Production

Follow `canonical-serialization.md` Rule 5 exactly:

- Format: POSIX ustar. Use pax extended headers only when strictly needed (paths > 100 bytes or non-ASCII).
- Entries in lexicographic order by full path.
- `mtime = 0`, `uid = 0`, `gid = 0`, `uname = ""`, `gname = ""`.
- File mode: `0644` for files, `0755` for directories.
- No device entries, no symlinks, no hardlinks.
- End archive with exactly two 512-byte zero blocks.

## Rule 2 — gzip Production

The uncompressed `*.dpkg.tar` stream is the canonical reproducibility surface (see Rule 4). The `*.dpkg.tar.gz` artifact is **conditionally reproducible**: two implementers produce byte-identical `.tar.gz` only if both use the same deflate encoder with the same parameters. Standard `zlib`/`gzip` at "level 6" does NOT meet this bar — zlib 1.2 vs 1.3, Go `compress/gzip`, and Node `zlib` produce different deflate streams for identical input because match-finder heuristics differ.

### Rule 2.a — Artifact header (MUST)

Every conformant producer MUST emit the following gzip header bytes regardless of compressor choice:

1. gzip **format version 1** (RFC 1952), compression method deflate.
2. Header flags: `FNAME = 0`, `FCOMMENT = 0`, `FHCRC = 0`, `FEXTRA = 0`. No filename, no comment, no extra field.
3. MTIME field: `0x00000000`.
4. XFL byte: `0x02` (maximum compression) when using the reference compressor in Rule 2.b, else `0x00`.
5. OS byte: `0xFF` (unknown).
6. No trailing bytes beyond the gzip ISIZE footer.

### Rule 2.b — Reference compressor (SHOULD for byte-identity)

To achieve byte-identical `*.dpkg.tar.gz` across independent implementers, producers SHOULD use **Zopfli** with parameters `numiterations=15, blocksplitting=true, blocksplittinglast=false`. Zopfli is deterministic across ports (google/zopfli and its language bindings produce identical deflate output for identical input).

Producers that use a non-Zopfli compressor (stdlib `gzip` at any level) MUST still comply with Rule 2.a, but MUST NOT claim artifact-level byte-identity; their packages remain conformant but the `.tar.gz.sha256` is implementation-local.

### Rule 2.c — Verification

Artifact byte-identity is VERIFIED only via `*.dpkg.tar.sha256` (the tar-stream digest). `*.dpkg.tar.gz.sha256` is a transport checksum, not a reproducibility witness, unless Rule 2.b is followed.

## Rule 3 — sha256 Production

Three digest classes are produced.

### 3.a Per-claim digest (`manifest.json.claims[].hash`)

`claims[].hash` MUST be SHA-256 computed over the **complete canonical `.md` file bytes** for that claim, exactly as those bytes are written into the tar archive.

Concretely, the hashed byte stream is:

1. Literal opening `---\n` (4 bytes: `0x2D 0x2D 0x2D 0x0A`).
2. Canonical YAML frontmatter per `canonical-serialization.md` Rule 6 (NFC, LF, keys ASCII-sorted, no trailing whitespace).
3. Literal closing `---\n` (4 bytes).
4. Claim body: NFC-normalized, LF line endings, no trailing whitespace, terminated by exactly one LF. An empty body is a single LF byte (total trailing sequence `---\n\n`). See `canonical-serialization.md` Rule 6 §12.

No part is excluded. No part is hashed twice. The hash input is byte-exact with the claim file's tar-entry payload. Implementers MUST NOT hash a JSON projection of the frontmatter, the body alone, or any other subset.

### 3.b Package digest (`*.dpkg.tar.sha256`)

SHA-256 over `*.dpkg.tar` bytes (the uncompressed canonical tar stream). This is the canonical package fingerprint for signing and external reference.

### 3.c Artifact digest (`*.dpkg.tar.gz.sha256`)

SHA-256 over `*.dpkg.tar.gz` bytes (the compressed on-disk artifact). Used by transports (HTTP `Content-SHA256`, mirror verification).

Per-claim digests are carried inside `manifest.json`. The package and artifact digests MUST be distributed alongside the artifact:

```
package.dpkg.tar.gz             (artifact)
package.dpkg.tar.sha256         (hex, lowercase, 64 chars, LF terminated)
package.dpkg.tar.gz.sha256      (hex, lowercase, 64 chars, LF terminated)
```

Each `.sha256` file contains exactly `<64 hex chars><LF>` — no filename, no algorithm prefix, no second field.

## Rule 4 — Reproducibility Guarantee

Given identical logical inputs (same claims, same provenance events, same manifest fields) and following all rules in this spec set, every conformant implementer MUST produce byte-identical:

- `manifest.json`
- `provenance.jsonl`
- `claims/*.md` files
- `package.dpkg.tar` stream (and therefore identical `package.dpkg.tar.sha256`)

`package.dpkg.tar.gz` byte-identity is **conditional** on Rule 2.b: guaranteed only when both implementers use Zopfli with the specified parameters. Standard-library gzip producers remain conformant but are not expected to agree on the `.tar.gz` bytes — their conformance is judged against the `.tar.sha256`, not the `.tar.gz.sha256`.

Deviation from the MUST byte-identity surface is a spec defect or an implementation defect, never "expected variance".

## Rule 5 — Forbidden Inputs

The following MUST cause the packager to abort with an error rather than silently normalize:

- Claims whose `claim_id` is not UUID v7.
- Timestamps not in UTC `Z` form.
- File contents containing unpaired surrogates.
- `provenance.jsonl` with out-of-order events.
- Any referenced claim file missing from `claims/`.

Silent normalization is forbidden because it masks producer bugs that would otherwise surface at the validator.

## Rule 6 — Archive Format Freeze (v0.3.0)

The wire format for v0.3.0 is **frozen to POSIX `ustar`, stored uncompressed**. ZIP, bz2, xz, and 7z containers are explicitly **not permitted** for `format_version` 1.x. A future MAJOR bump may introduce another container; consumers MUST reject any archive whose leading bytes do not match `ustar\0` at offset 257.

Forbidden archive features (MUST reject at unpack time):

- Symbolic links (`type == LNKTYPE` or `SYMTYPE`).
- Hard links.
- Device nodes (`CHRTYPE`, `BLKTYPE`, `FIFOTYPE`).
- Absolute paths (leading `/`).
- Parent-directory traversal (any path segment equal to `..`).
- Nested archives (`*.tar`, `*.zip`, `*.tar.gz` inside the DPKG archive).
- Windows drive prefixes (`C:\`) and backslash separators.

Filename rules inside the archive:

- Encoded as UTF-8, NFC-normalized.
- POSIX separators only (`/`); no backslashes.
- Text payloads use LF line endings exclusively; the packager MUST refuse CR/CRLF.

## Rule 7 — Extraction Limits

The reference unpacker enforces the following hard ceilings. External
implementers SHOULD match these or be stricter.

| Limit | Value | Rationale |
|---|---|---|
| `max_decompressed_size` (whole archive) | **100 MiB = 104_857_600 bytes** | Hard ceiling; refusal is `PX_E_6011` |
| Single-file size | ≤ 50 MiB recommended; reference impl caps at 25 MiB | Defense in depth against zip-bomb payloads |
| `max_files` | 10 000 | Caps filesystem inode pressure |
| `max_compression_ratio` | 100 × archive size | Detects pathological ratios |
| `max_path_length` | 512 bytes (NFC-normalized) | Matches long-filename paxheader bounds |

The constant `PACKAGE_TOTAL_BYTES_LIMIT = 104_857_600` in
`src/dpkg/unpacker.py` is normative and mirrored in this document.

## Rule 8 — Archive Digest vs Content Hash (DISTINCT)

The **archive digest** (`*.dpkg.tar.sha256`, Rule 3.b) and the
**claim content hash** (`content_hash` computed per
`spec/content-hash.md`) are two different digests serving different
purposes:

- `archive_digest` identifies a particular packaged byte stream.
- `content_hash` identifies the semantic claim payload, canonicalized
  per RFC 8785 JCS.

`archive_digest` MUST NOT appear in claim identity calculations, diff
equality checks, or any other semantic comparison. Two packages with
different archive_digests MAY still contain identical claims, and the
round-trip test (§P6) relies on this independence.
