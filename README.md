# DPKG — Deterministic Package Format

Reference CLI implementation (v0.2.2). **Zero runtime dependencies** (stdlib
only). Python 3.10+.

- CI: Linux / macOS / Windows × Python 3.10 / 3.11 / 3.12 — 9-cell matrix
- Output: human (ANSI-colored) by default; `--json` for scripting
- Error model: machine-readable `PX_E_<CCNN>` on stderr, always JSON lines

## Quickstart (5 minutes)

```bash
# 1. Install (editable is fine; zero deps)
pip install -e .

# 2. Check the version — shows package + spec + schema
dpkg --version
# dpkg 0.2.2 (spec 0.2.2, schema 1.0)

# 3. Create an empty skeleton
dpkg init ./my-pkg
#   [ok] Initialized empty DPKG skeleton in my-pkg
#   Next steps:
#     1. Add claim files under my-pkg/claims/<uuid>.md
#     2. Register each claim in manifest.json
#     3. Run `dpkg validate my-pkg` to confirm.

# 4. Validate (syntax + schema)
dpkg validate ./my-pkg
#   [ok] my-pkg: syntax + schema OK (0 event(s))

# 5. Pack -> uncompressed deterministic tar
dpkg pack ./my-pkg ./my-pkg.dpkg.tar
#   [ok] my-pkg -> my-pkg.dpkg.tar

# 6. Unpack safely (streaming, path-traversal / zip-bomb hardened)
dpkg unpack ./my-pkg.dpkg.tar ./unpacked
#   [ok] my-pkg.dpkg.tar -> unpacked

# 7. Verify (semantic cross-reference: hash / fileset / chain / refs)
dpkg verify ./unpacked
#   [ok] unpacked: semantic cross-reference OK
```

## Output modes

Every command supports two orthogonal flags:

| Flag         | Effect                                                           |
|--------------|------------------------------------------------------------------|
| `--json`     | stdout is a single JSON line; no hints, no color                 |
| `--no-color` | force plain text even on a tty                                   |

Color is automatically disabled when stdout is not a tty or when the
[`NO_COLOR`](https://no-color.org) env variable is set — so piping to
files / CI logs stays clean without any flag.

```bash
$ dpkg --json validate ./my-pkg
{"command":"validate","event_count":0,"ok":true,"source":"./my-pkg","summary":"./my-pkg: syntax + schema OK (0 event(s))"}
```

Errors are **always** JSON lines on stderr (with or without `--json`) so
shell pipelines can branch on the error code field:

```bash
$ dpkg validate ./broken 2>&1 >/dev/null | head -1
{"code":"PX_E_4001","msg":"...","severity":"error"}
```

## Commands

### `init`

Create an empty DPKG skeleton. Default **refuses** an existing
`manifest.json` / `provenance.jsonl` to protect existing data; overwriting
requires both `--force` **and** `--i-know-what-im-doing`.

```bash
dpkg init DEST [--spec-version 0.2.2] [--force --i-know-what-im-doing]
```

### `validate`

Syntax-layer check of `manifest.json` + `provenance.jsonl` in a source
directory. No semantic cross-referencing — that is `verify`'s job.

```bash
dpkg validate SOURCE_DIR
```

### `pack`

Deterministic archive creation. Byte-identical output for byte-identical
input. Output is an uncompressed POSIX `ustar` archive (gzip is deferred so
`mtime`, Zlib flags, and header bytes cannot break byte-identity across
implementations).

```bash
dpkg pack SOURCE_DIR OUT.dpkg.tar
```

### `unpack`

Safe streaming extract. Rejects path traversal, absolute paths, Windows
drive paths, backslashes, symlinks, hardlinks, devices, fifos, zip bombs,
and over-budget archives. Uses `tarfile.next()` in a streaming loop —
never `tar.extractall()`.

```bash
dpkg unpack ARCHIVE.dpkg.tar DEST/
```

Budget flags (conservative defaults):

- `--max-files 10000`
- `--max-total-bytes 104857600` (100 MiB)
- `--max-file-bytes 26214400` (25 MiB)
- `--max-compression-ratio 100`
- `--max-path-length 512`

### `verify`

Post-unpack semantic cross-reference:

1. Every manifest claim hash matches the actual claim file bytes
   (`PX_E_5001` / `HASH_MISMATCH`).
2. Archive file set matches the manifest exactly
   (`PX_E_5002` / `FILESET_DIVERGENCE`).
3. Provenance events form a valid chain per claim
   (`PX_E_5003` / `CHAIN_BROKEN`).
4. Every event references a known claim
   (`PX_E_5004` / `DANGLING_REFERENCE`).

```bash
dpkg verify UNPACKED_DIR/
```

See [`spec/error-codes.md`](spec/error-codes.md) for the full
`PX_E_<CCNN>` registry.

## Deferred

- `diff` → v0.3.0 (semantic archive diff + Parallax exchange contract)

## Exit codes

- `0` success
- `1` generic / unexpected error
- `2` usage / argparse error
- `3` validation, security, or semantic failure

## Spec

`dpkg --version` reports three numbers:

- **Package** (`0.3.0`) — the version of this CLI / Python library.
- **Spec** (`0.3.0`) — the version of the on-disk DPKG format this build
  targets (spec version is tracked independently from package version so
  maintenance releases can ship without bumping the format).
- **Schema** (`1.1`) — the `format_version` field written into new
  `manifest.json` files; `1.0` packages still validate.

See `spec/canonical-serialization.md` for the canonical byte-level contract
every conformant implementer must reproduce (worked example:
`{"a":"café","b":2}\n` → SHA-256
`d2995dc401d3e4b85320775178dbf4cff5393f8ba3b6f63c489ea7acde97f682`).

## External Reader Conformance

DPKG ships a stdlib-only reference reader at
`scripts/external_reader.py` (~170 LOC, no `import dpkg`). It
demonstrates the wire format is self-describing: an independent
reader can classify every sample under `samples/` as valid / invalid
without touching the reference validator.

```bash
# Cross-check every sample against its expected-normalized.json:
python scripts/external_reader.py samples/

# Emit normalized JSON for one sample on stdout:
python scripts/external_reader.py samples/architecture-claim/
```

Exit code is `0` on agreement, `1` on mismatch.
`tests/test_external_reader.py` guards the stdlib-only contract via an
AST scan that forbids any `dpkg` / `parallax` / `memory` imports.
