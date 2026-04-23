# Changelog

## [0.3.0] — 2026-04-21

### Added

- `format_version` 1.1 — the wire-schema bump accepted alongside 1.0.
  `manifest.schema.json` `format_version` is now `enum: ["1.0", "1.1"]`;
  the validator accepts both, packers emit 1.1 for new skeletons.
- `dpkg.lifecycle` — state-machine enforcement module (pure stdlib).
  Walks provenance per `claim_id` in canonical `(occurred_at_ms,
  event_id_lex)` order, raising `PX_E_5101`
  (`ERR-SEM-LIFECYCLE-ILLEGAL`) on illegal transitions and
  `PX_E_5102` (`REAFFIRM_MISSING_TARGET`) when a `reaffirm` lacks
  `target_claim_instance_id`. Wired into `validate_package` as the
  third pass so every validate call enforces semantic lifecycle.
- `target_claim_instance_id` enforcement (spec §5.5) —
  `dpkg.lifecycle` rejects `create` / `publish` that carry the field
  (→ `PX_E_5101`, neither has a prior instance to point at) and
  `reaffirm` / `revise` / `supersede` / `withdraw` that omit it
  (→ `PX_E_5102` for `reaffirm`, `PX_E_5101` for the other three).
  `dpkg.validator` additionally pattern-checks the field against
  UUID-v7 (`PX_E_4001`) at the schema layer.
- `dpkg diff <a> <b>` command + `dpkg.diff` module — layered diff
  (manifest / claim-set / per-claim evidence / provenance timeline).
  `--json` emits a structured payload validated against
  `schemas/diff-v0.3.json` (`diff_spec_version: "0.3.0"`); the
  human-text form carries the mandatory
  `"NOTE: Human-readable diff is informational only; the JSON form
  (--json) is the machine contract"` banner. Exit 0 iff the diff is
  empty.
- `dpkg validate --strict` / `--lenient` mutually-exclusive modes
  (default strict).
- `schemas/dpkg-v0.3.json` — aggregate JSON Schema that `$ref`s
  manifest / claim-frontmatter / provenance-event, giving an external
  consumer a single document to point a JSON Schema validator at.
- `schemas/diff-v0.3.json` — JSON Schema for the diff output shape.
- `schemas/expected-normalized-v0.3.json` — schema for the
  `expected-normalized.json` fixture companion format.
- `scripts/external_reader.py` — stdlib-only reference reader
  (~160 LOC) that classifies every sample under `samples/` without
  importing `dpkg` / `parallax` / `memory`. Proves the wire format
  is self-describing. `tests/test_external_reader.py` guards the
  stdlib-only contract via AST scan and the verdict contract via
  subprocess exit code.
- 8 canonical samples under `samples/` — each with `manifest.json`,
  `provenance.jsonl`, claim files, `README.md`, and
  `expected-normalized.json`: `architecture-claim`,
  `contradictory-claim`, `duplicate-reaffirm-collision`,
  `minimal-empty`, `multi-source-claim`, `revise-withdraw-flow`,
  `unicode-normalization`, `withdraw-then-illegal-reaffirm`.
- `spec/content-hash.md`, `spec/lifecycle-state-machine.md`,
  `spec/VERSIONING.md`, `spec/reserved-namespaces.md`,
  `spec/error-codes.md`, `adr/0001-content-hash-granularity.md`,
  plus the normative Parallax-side mirror
  `<parallax-repo>/spec/parallax-exchange.md`.
- `.forbidden-terms.txt` + `scripts/check_forbidden_terms.py` +
  `tests/test_forbidden_terms.py` — CI-enforced guard against the
  public leaking of pre-rename terms. Pre-commit hook installable
  separately.
- Reserved namespace prefixes `parallax:` / `internal:` — opaque
  pass-through in DPKG. Excluded from content-hash computation.
  Adapter layer MUST strip them on export.
- Version axes separated: `format_version` (wire, semver MAJOR.MINOR)
  and `dpkg_spec_version` (release, semver). Unknown MAJOR is
  `PX_E_3003` (hard reject); known MAJOR + unknown MINOR is
  `PX_E_3001` (warn in `--lenient`, reject in `--strict`). See
  `spec/VERSIONING.md`.
- Archive format frozen at uncompressed POSIX ustar. Extraction
  limits codified in `spec/packaging.md` §7: `max_decompressed_size`
  100 MiB, `max_files` 10 000, `max_file_bytes` 25 MiB,
  `max_compression_ratio` 100, `max_path_length` 512. Module
  constants `PACKAGE_TOTAL_BYTES_LIMIT` and
  `PACKAGE_SINGLE_FILE_BYTES_LIMIT` exported by `dpkg.unpacker`.
- Error code bands documented: 1NN TYPE, 2NN STRUCTURE, 3NN VERSION,
  4NN FORMAT, 5NN CONSISTENCY, 6NN SECURITY.

### Changed

- `SCHEMA_VERSION_MAX` bumped `1.0` → `1.1`; `SPEC_VERSION`
  `0.2.2` → `0.3.0`; package `__version__` `0.2.2` → `0.3.0`.
- `init_skeleton` now stamps `format_version: "1.1"` and
  `dpkg_spec_version: "0.3.0"` by default (older spec versions
  remain accepted via `--spec-version`).
- `validate_package` now runs three passes in order: (1) shape /
  type, (2) chain integrity, (3) lifecycle state machine. The
  additional lifecycle pass catches errors that previously slipped
  through when only the verifier was run.

## [0.2.2] — 2026-04-21

### Added

- `.github/workflows/ci.yml`: 9-cell CI matrix (ubuntu-latest /
  windows-latest / macos-latest × Python 3.10 / 3.11 / 3.12). Windows +
  py3.11 listed first in the matrix because the 2026-04-19 cp950 incident
  showed it is the most fragile cell, so surfacing failures there earliest
  saves runtime on the other 8. Each cell runs `pytest --cov ... --cov-fail-under=80`
  plus a `init → validate → pack → unpack → verify` smoke test (bash on
  Linux/macOS, PowerShell on Windows).
- `dpkg.output.Writer` + `detect_color`: bound output policy (`json_mode`,
  `color`, stdout) threaded through every subcommand. Color is auto-off for
  non-tty streams and when `NO_COLOR` is set (per https://no-color.org).
- `dpkg --json`: global flag that switches success output on stdout to a
  single JSON line `{"ok": true, "command": ..., "summary": ..., ...}`
  suitable for shell pipelines. Errors stay as JSON lines on stderr whether
  or not `--json` is passed, preserving the v0.2.1 error contract.
- `dpkg --no-color`: force plain text even when stdout is a tty.
- `dpkg --version` dual display: now reports package + spec + schema
  (`dpkg 0.2.2 (spec 0.2.2, schema 1.0)`) so users never have to guess
  which number their validator cares about. Closes Top-5 risk #5.
- `SPEC_VERSION` constant in `dpkg.__init__` (tracked independently from
  `__version__` so a maintenance release can ship without bumping the
  on-disk format).
- `tests/test_cli_output.py`: 15 tests covering --json structure, ANSI
  stripping in non-tty / `NO_COLOR` / `--no-color`, Writer unit behavior,
  `--version` dual display, and a full 5-step JSON-mode pipeline smoke.
- README quickstart rewritten as a copy-pastable 5-minute walkthrough with
  expected output for every command.

### Changed

- `dpkg.initializer.SUPPORTED_SPEC_VERSIONS` accepts `0.2.2` in addition to
  `0.2.0` / `0.2.1`.
- `src/dpkg/cli.py` refactored to use `Writer` for success output; error
  handling paths (`DpkgError` / `FileNotFoundError` / catch-all) unchanged.

### Risk mitigations (v0.2.2 Top-5)

| # | Risk                                | Mitigation shipped in this release                               |
|---|-------------------------------------|------------------------------------------------------------------|
| 1 | `init` destroys existing DB         | Two-key gesture (`--force` + `--i-know-what-im-doing`) from v0.2.1 carried through — CI smoke exercises default-safe path. |
| 3 | Error code granularity              | Registry stable since v0.2.1; no new codes in this release.      |
| 4 | Windows cp950 / newlines            | CI sets `PYTHONIOENCODING=utf-8` + `PYTHONUTF8=1`; Windows+py3.11 first in the matrix. |
| 5 | Spec vs package version confusion   | `--version` now shows both numbers side by side.                 |

## [0.2.1] — 2026-04-21

### Added

- `dpkg.error_codes`: canonical `ErrorCode` registry using the
  `PX_E_<CCNN>` scheme across six category bands (1NN TYPE, 2NN STRUCTURE,
  3NN VERSION, 4NN FORMAT, 5NN CONSISTENCY, 6NN SECURITY) plus a 9NN GENERIC
  fallback. Single source of truth for every machine-readable error code
  emitted by the package. See `spec/error-codes.md`.
- `dpkg.initializer` + `dpkg init` CLI subcommand: creates a DPKG skeleton
  (`manifest.json`, `provenance.jsonl`, `claims/`) in an empty destination.
  Default refuses an existing package; overwrite requires both `--force`
  **and** `--i-know-what-im-doing` (two-key safety gesture). Supports
  `--spec-version 0.2.0` / `0.2.1` via `extensions.dpkg_spec_version`.
- `tests/test_properties.py`: four `hypothesis`-based property tests
  covering canonical JSON round-trip, unknown-field rejection, non-UUID
  claim_id rejection, and `init` determinism.
- Extended fixture factory to 41 golden cases.

### Changed

- All source modules migrated from legacy `ERR-VAL-*` / `ERR-SEM-*` /
  `ERR-SEC-*` string literals to `ErrorCode.*` enum members. No hardcoded
  `PX_E_*` strings remain outside `error_codes.py`.
- `README.md` + `spec/validator.md`: reference the new registry; former
  `ERR-SEM-*` codes are annotated as migrated.

### Coverage

- 123 tests pass (up from 89 baseline).
- `dpkg.validator`: 99%, `dpkg.verifier`: 96%, `dpkg.initializer`: 98%,
  `dpkg.error_codes`: 98%, package total: 93%.

## [0.2.0] — 2026-04-21

### Added

- `dpkg.canonical_json`: deterministic JSON serializer (NFC at insert time,
  duplicate-key rejection, NaN/Infinity rejection, float rejection). Reproduces
  the spec worked example (`{"a":"café","b":2}\n`) to SHA-256
  `d2995dc401d3e4b85320775178dbf4cff5393f8ba3b6f63c489ea7acde97f682`.
- `dpkg.canonical_tar`: deterministic uncompressed POSIX ustar writer with
  fixed mtime/uid/gid/uname/gname, NFC-sorted member order, and rejection of
  symlink/hardlink/device/fifo members.
- `dpkg.errors`: exception hierarchy (`DpkgError`, `SchemaError`,
  `SecurityError`, `SemanticError`, `VerificationError`) with
  machine-readable codes and single-line JSON emission to stderr.
- `dpkg.validator`: hand-coded strict-subset validator for `manifest.json`
  and `provenance.jsonl` events (no `jsonschema` dependency).
- `dpkg.packer`: deterministic source-dir → `.dpkg.tar` packing with hash
  recomputation and re-canonicalization.
- `dpkg.unpacker`: safe streaming extract with budgets for file count,
  total bytes, per-file bytes, compression ratio, and path length. Rejects
  path traversal, absolute paths, Windows drive paths, backslashes,
  symlinks, hardlinks, devices, and fifos.
- `dpkg.verifier`: four-check semantic verification (hash, fileset, chain,
  refs).
- `dpkg.cli`: `argparse`-based CLI exposing `validate`, `pack`, `unpack`,
  `verify` (`init` deferred to v0.2.1; `diff` deferred to v0.3.0).
- Golden fixture suite: 33 cases across `valid/` (8), `invalid-syntax/` (10),
  `invalid-semantic/` (6), `archive-security/` (7), and `round-trip/` (4),
  each with a README describing expected exit code and error code.
- pytest suite: 87 tests covering worked-example reproduction, round-trip
  byte-equality, security rejections, and every ERR-* code path.

### Invariants

- `pyproject.toml`: `dependencies = []` — zero runtime dependencies.
- `pack(src) → bytes` is byte-deterministic across runs (verified via
  SHA-256 equality in unit tests).
- `pack → unpack → pack` yields byte-identical archives (verified across 4
  round-trip fixtures including NFD-input normalisation).
