# Aphelion Canonical Serialization Spec

**Version:** 1.0
**Status:** Normative
**Date:** 2026-04-21

## Purpose

Two independent implementers reading this document MUST produce byte-identical Aphelion artifacts from the same logical input. Reserved keywords MUST, MUST NOT, SHOULD, MAY follow RFC 2119.

---

## Rule 1 — JSON Canonical Form

> All JSON objects MUST be serialized with keys sorted by ASCII codepoint order, UTF-8 NFC-normalized, LF line endings, no trailing whitespace.

Concretely:

1. **Key order**: object keys MUST be sorted ascending by Unicode codepoint (`"a" < "b" < "z" < "{"`). Recursively: nested objects also sorted.
2. **Encoding**: UTF-8 without BOM. All string values MUST be Unicode Normalization Form C (NFC).
3. **Separators**: `","` between elements, `":"` between key and value. No spaces. (Python: `json.dumps(..., separators=(",", ":"))`.)
4. **Escaping**: Only the minimal JSON escapes — `\"`, `\\`, `\b`, `\f`, `\n`, `\r`, `\t`, and `\u00XX` for control chars 0x00–0x1F. Non-ASCII characters MUST be emitted raw (not `\uXXXX` escaped).
5. **Number form**: integers emitted without fractional/exponent part. **Format-required numeric fields MUST NOT use free-form floats** — `shortest round-trip` float serialization is language-dependent (ECMA-262 ToString, Python `repr`, and Go `strconv` disagree on subnormals and 0.1+0.2-class values). Each numeric field MUST be declared in `spec/schema-matrix.md` or `spec/claim-frontmatter.md` as either (a) an integer, or (b) a fixed-decimal with an explicit digit count (e.g. `confidence` is always exactly 3 decimal digits: `0.900`). Application-defined fields MAY carry free-form floats; validators MUST NOT apply byte-identity guarantees to such values. Reject NaN / Infinity unconditionally.
6. **Terminator**: the serialized JSON document MUST end with exactly one LF byte (`0x0A`).

**Worked hash example (reviewer reproduction):**

Input logical object:
```
{ "b": 2, "a": "café" }
```
Canonical bytes (hex, 20 bytes):
```
7b 22 61 22 3a 22 63 61 66 c3 a9 22 2c 22 62 22 3a 32 7d 0a
```
Canonical string:
```
{"a":"café","b":2}\n
```
SHA-256 (verified):
```
d2995dc401d3e4b85320775178dbf4cff5393f8ba3b6f63c489ea7acde97f682
```
Any conformant implementer MUST reproduce this exact hash from the exact 20 input bytes above.

---

## Rule 2 — UTF-8 NFC Normalization

1. All text (JSON strings, markdown bodies, YAML values, filenames inside the tar) MUST be UTF-8 encoded, NFC-normalized before hashing or serialization.
2. An implementer MUST apply NFC **before** sorting keys, so codepoint order is computed on normalized form.
3. Unpaired surrogates MUST be rejected as a syntax error (see `validator.md` §ERR-SYN-003).

---

## Rule 3 — Line Endings & Whitespace

1. All text files (`.md`, `.json`, `.jsonl`, `.yaml`) MUST use LF (`0x0A`) line endings. CRLF is a syntax error.
2. No trailing whitespace on any line (no `0x20` or `0x09` immediately before `0x0A`).
3. Every text file MUST end with exactly one terminating LF. A trailing blank line (two LFs) is a syntax error.
4. Horizontal tabs are allowed only inside code blocks in markdown; everywhere else, indentation MUST use spaces.

---

## Rule 4 — Timestamps

1. All timestamps MUST be UTC ISO 8601 with the literal `Z` suffix: `YYYY-MM-DDTHH:MM:SSZ` or `YYYY-MM-DDTHH:MM:SS.sssZ` (millisecond precision).
2. Offsets other than `Z` are forbidden (no `+00:00`, no `-07:00`).
3. Sub-second precision MUST be zero-padded to exactly 3 digits when present. Implementers MUST NOT emit 6-digit microsecond timestamps in canonical form.
4. Timestamps that represent "unset" MUST be omitted from the JSON object, not emitted as `null` or `""`.

---

## Rule 5 — tar Entry Canonicalization

When packaging into `*.aphelion.tar`:

1. **Format**: POSIX ustar. **ustar `prefix`+`name` split is FORBIDDEN.** Any entry whose path exceeds 100 bytes OR contains any non-ASCII byte MUST use a pax extended header immediately preceding the ustar entry. The pax header MUST contain **exactly one record**: `path=<value>`. No `mtime`, `atime`, `ctime`, `uid`, `gid`, `uname`, `gname`, `size`, or custom records may be emitted. When future rules add additional pax records, they MUST appear in alphabetical order by key.
2. **Entry order**: entries MUST appear in lexicographic order by full path (ASCII codepoint). Directory-prefix collisions (e.g. `claims/a.md` vs `claims/a/b.md`) resolve by direct codepoint comparison of the full path string; `.` (0x2E) < `/` (0x2F), so `claims/a.md` sorts before `claims/a/b.md`.
3. **mtime**: every entry's modification time MUST be `0` (Unix epoch).
4. **atime / ctime**: MUST NOT be emitted (ustar doesn't; pax headers MUST omit).
5. **uid / gid**: MUST be `0`. **uname / gname**: MUST be empty strings.
6. **mode**: regular files `0644`, directories `0755`. No other bits. No setuid/setgid/sticky.
7. **Device major/minor**: `0`.
8. **Link name**: empty for regular files.
9. **Padding**: tar 512-byte block padding MUST be zero bytes.
10. **EOF**: exactly two zero-filled 512-byte blocks terminate the archive. No extra trailing bytes.

---

## Rule 6 — YAML Frontmatter Canonicalization

For claim `.md` files with YAML frontmatter between `---` fences:

1. **Delimiters**: opening `---\n` and closing `---\n`. No spaces after `---`.
2. **Key order**: keys sorted ASCII codepoint order (same rule as JSON).
3. **Scalar style**: **ALL string scalars MUST be double-quoted.** Plain scalars are forbidden for strings. This is total and unconditional — there is no "quote only when needed" branch. Rationale: eliminates every ambiguity around YAML plain-scalar reserved indicators (`-`, `?`, `!`, `&`, `*`, `[`, `]`, `{`, `}`, `,`, `%`, leading `@`, leading `` ` ``), leading/trailing whitespace, empty strings, and values that would otherwise parse as `true`/`false`/`null`/numbers. Inside a double-quoted string, escapes MUST be the minimal JSON-compatible set (`\"`, `\\`, `\n`, `\r`, `\t`, and `\u00XX` for control chars); non-ASCII characters are emitted raw.
4. **Flow style**: forbidden for root-level mappings. Sequences MAY use block style only (`- item` on its own line).
5. **No comments**: YAML comments (`#`) are forbidden in canonical frontmatter.
6. **No anchors / aliases / tags**: `&`, `*`, `!!type` forbidden.
7. **Timestamps**: ISO 8601 with `Z` suffix per Rule 4. **All ISO-8601 timestamps MUST be double-quoted.** YAML MUST NOT auto-cast timestamps to native YAML timestamps.
8. **Booleans**: `true` / `false` only. YAML aliases `yes`/`no`/`on`/`off` are forbidden.
9. **Nulls**: omit the key; do not emit `null`, `~`, or empty.
10. **Numbers**: integers emitted without leading zeros or sign (except for negatives). Floats MUST be emitted with a **fixed decimal width specified by the field definition** (e.g. `confidence` is always exactly 3 decimals — `0.900`, never `0.9`); per-field widths are defined in `spec/claim-frontmatter.md`. NaN / Infinity are forbidden.
11. **Sequences**: elements NFC-normalized. When a field definition requires sort order, the sort MUST be case-sensitive ASCII-codepoint-ascending computed **after** NFC.
12. **Terminator**: body begins immediately after closing `---\n`; no leading blank line. The body MUST end with exactly one LF byte. **An empty body is represented as a single LF byte** immediately following the closing `---\n` — i.e., a claim with no body text has the literal trailing sequence `---\n\n`. Implementers MUST NOT omit the body LF, and MUST NOT emit two LFs.

---

## Determinism Checklist (for implementer self-test)

Given identical logical input, an implementer MUST produce identical bytes for:

- [ ] `manifest.json` (JSON canonical form)
- [ ] every `claim.md` (YAML canonical frontmatter + LF-normalized body)
- [ ] `provenance.jsonl` (each line JSON-canonical, LF terminated)
- [ ] `package.aphelion.tar` (ustar canonical form)
- [ ] `package.aphelion.tar.gz` (see `packaging.md` Rule 3 for gzip determinism)
- [ ] `package.aphelion.tar.gz.sha256`

If any of the above differs between two conformant implementers, this document is defective — file an issue against the spec.
