# Aphelion — Deterministic Package Format

Reference CLI implementation (v0.5.0). **Zero runtime dependencies** (stdlib
only). Python 3.10+.

- CI: Linux / macOS / Windows × Python 3.10 / 3.11 / 3.12 — 9-cell matrix
- Output: human (ANSI-colored) by default; `--json` for scripting
- Error model: machine-readable `PX_E_<CCNN>` on stderr, always JSON lines

## Quickstart (5 minutes)

```bash
# 1. Install (editable is fine; zero deps)
pip install -e .

# 2. Check the version — shows package + spec + schema
aphe --version
# aphelion 0.5.0 (spec 0.4.0, schema 2.0)

# 3. Create an empty skeleton
aphelion init ./my-pkg
#   [ok] Initialized empty Aphelion skeleton in my-pkg
#   Next steps:
#     1. Add claim files under my-pkg/claims/<uuid>.md
#     2. Register each claim in manifest.json
#     3. Run `aphelion validate my-pkg` to confirm.

# 4. Validate (syntax + schema)
aphelion validate ./my-pkg
#   [ok] my-pkg: syntax + schema OK (0 event(s))

# 5. Pack -> uncompressed deterministic tar
aphelion pack ./my-pkg ./my-pkg.aphelion.tar
#   [ok] my-pkg -> my-pkg.aphelion.tar

# 6. Unpack safely (streaming, path-traversal / zip-bomb hardened)
aphelion unpack ./my-pkg.aphelion.tar ./unpacked
#   [ok] my-pkg.aphelion.tar -> unpacked

# 7. Verify (semantic cross-reference: hash / fileset / chain / refs)
aphelion verify ./unpacked
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
$ aphelion --json validate ./my-pkg
{"command":"validate","event_count":0,"ok":true,"source":"./my-pkg","summary":"./my-pkg: syntax + schema OK (0 event(s))"}
```

Errors are **always** JSON lines on stderr (with or without `--json`) so
shell pipelines can branch on the error code field:

```bash
$ aphelion validate ./broken 2>&1 >/dev/null | head -1
{"code":"PX_E_4001","msg":"...","severity":"error"}
```

## Commands

### `init`

Create an empty Aphelion skeleton. Default **refuses** an existing
`manifest.json` / `provenance.jsonl` to protect existing data; overwriting
requires both `--force` **and** `--i-know-what-im-doing`.

```bash
aphelion init DEST [--spec-version 0.4.0] [--force --i-know-what-im-doing]
```

### `validate`

Syntax-layer check of `manifest.json` + `provenance.jsonl` in a source
directory. No semantic cross-referencing — that is `verify`'s job.

```bash
aphelion validate SOURCE_DIR
```

### `pack`

Deterministic archive creation. Byte-identical output for byte-identical
input. Output is an uncompressed POSIX `ustar` archive (gzip is deferred so
`mtime`, Zlib flags, and header bytes cannot break byte-identity across
implementations).

```bash
aphelion pack SOURCE_DIR OUT.aphelion.tar
```

### `unpack`

Safe streaming extract. Rejects path traversal, absolute paths, Windows
drive paths, backslashes, symlinks, hardlinks, devices, fifos, zip bombs,
and over-budget archives. Uses `tarfile.next()` in a streaming loop —
never `tar.extractall()`.

```bash
aphelion unpack ARCHIVE.aphelion.tar DEST/
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
aphelion verify UNPACKED_DIR/
```

See [`spec/error-codes.md`](spec/error-codes.md) for the full
`PX_E_<CCNN>` registry.

### `migrate`

One-shot v0.3 → v0.4 wire migration. Works on unpacked directories or
`.aphelion.tar` archives. See `spec/migration-v0.3-to-v0.4.md` for the
normative contract.

```bash
aphe migrate SRC DST [--force]
# Directory in -> directory out (matches source shape)
# .aphelion.tar in -> .aphelion.tar out
```

## Exit codes

- `0` success
- `1` generic / unexpected error
- `2` usage / argparse error
- `3` validation, security, or semantic failure

## Spec

`aphelion --version` reports three numbers:

- **Package** (`0.5.0`) — the version of this CLI / Python library.
- **Spec** (`0.4.0`) — the version of the on-disk Aphelion format this build
  targets (spec version is tracked independently from package version so
  maintenance releases can ship without bumping the format).
- **Schema** (`2.0`) — the `format_version` field written into new
  `manifest.json` files. v0.3 packages (`1.0` / `1.1`) are rejected;
  run `aphe migrate SRC DST` to lift them first (see
  `spec/migration-v0.3-to-v0.4.md`).

See `spec/canonical-serialization.md` for the canonical byte-level contract
every conformant implementer must reproduce (worked example:
`{"a":"café","b":2}\n` → SHA-256
`d2995dc401d3e4b85320775178dbf4cff5393f8ba3b6f63c489ea7acde97f682`).

## External Reader Conformance

Aphelion ships a stdlib-only reference reader at
`scripts/external_reader.py` (~170 LOC, no `import aphelion`). It
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
AST scan that forbids any `aphelion` / `parallax` / `memory` imports.
