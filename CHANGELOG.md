# Changelog

## [Unreleased] (v0.6)

### Added

- **R7.2 — Notary attestation envelope** per the new
  `spec/v0.6-notary-attestation.md`. This fills the v0.5 §4 trust-notary
  *extension point* (which only ever yielded `"verified-locally"`) with a
  pinned envelope format and verification path:
  - **`NotaryAttestationEnvelope`** frozen dataclass
    (`src/aphelion/trust.py`) — a notary's detached attestation that a
    `key_fingerprint` is the key it associates with a `signer_id`. Fields:
    `notary_id`, `signer_id`, `key_fingerprint`, `algorithm`, `signed_at_iso`,
    `signature_b64`.
  - **`compute_attestation_canonical_hash`** — `sha256` over the canonical
    JSON of `{key_fingerprint, notary_id, signer_id}`. Binds notary, signer,
    and key; deliberately does NOT bind a package hash, so one attestation is
    reusable across every package that key signs.
  - **`canonical_attestation_bytes`** / **`parse_attestation_line`** — byte-
    deterministic round-trip over the existing canonical-JSON machinery;
    structural failures raise `E_SIGNATURE_MALFORMED`.
  - **`resolve_notary_attestation(signer_manifest, attestation,
    notary_manifest)`** — returns `"verified-by-notary"` when every §3 rule
    holds: signer/key/notary identity binding, registry algorithm,
    pre-dispatch algorithm-match confused-deputy guard, notary fingerprint
    recompute, and signature verification (hmac-sha256 reference + real
    ed25519 under the `[signer]` extra).
- New error code **`E_SIGNER_NOTARY_INVALID`** (`spec/error-codes.md`,
  `spec/v0.6-notary-attestation.md` §4) for an attestation that is
  structurally present but fails an identity/fingerprint binding check.

### Compatibility

- Strictly additive over v0.5. The v0.5 `resolve_notary` stub and the
  `NotaryAttestation` `Literal` (`"verified-locally"` | `"verified-by-notary"`)
  are unchanged; a package with no attestation behaves exactly as before. No
  mandatory new file. `E_SIGNER_NOTARY_REQUIRED` wiring (v0.5) is unchanged.

### Tests

- 537 tests GREEN (was 513). +24 in `tests/test_trust_notary_envelope.py`
  (canonical-hash determinism + field binding, envelope round-trip + malformed
  rejection, full §3 rule sequence per error code, ed25519 round-trip/tamper
  under the `[signer]` extra, and regression guards that the v0.5 stub and
  Literal are untouched).

## [0.5.1] — 2026-06-15

### Fixed

- **Signer manifest guard** (`src/aphelion/validator.py`): `validate_signatures`
  loaded `manifest.json` behind a bare `assert manifest_member is not None`.
  Under `python -O` the assert is stripped, so a crafted archive whose
  `manifest.json` is a non-regular member (directory / symlink) made
  `tarfile.extractfile()` return `None` and surfaced a raw `AttributeError`
  on `.read()` instead of a typed validation error; an absent `manifest.json`
  raised `KeyError`. Replaced the assert with explicit typed raises matching
  the codebase's None-handling idiom: `SchemaError` `MISSING_FILE` for an
  absent manifest, `SecurityError` `DISALLOWED_MEMBER_TYPE` for a non-regular
  member. The guard now holds with asserts stripped.

### Changed

- Applied ruff safe autofixes (F401 unused imports, E741 ambiguous variable
  names). No behavioural change.

### Tests

- 513 tests GREEN (was 412 in v0.5.0). Added RED-first coverage in
  `tests/test_verifier_signed.py` for the absent-manifest and
  non-regular-manifest shapes, including a `python -O` subprocess check
  confirming the guard holds when asserts are stripped.

### Compatibility

- Fully backward-compatible bugfix release. No format, schema, or public API
  changes; every package that validated under v0.5.0 still validates.

## [0.5.0] — 2026-04-27

### Added (additive — v0.4 readers ignoring `signatures.jsonl` + `signers/` still validate every previously-conforming v0.4 package unchanged)

- **Signer / trust extension** per `spec/v0.5-signer-trust.md`. Three roles
  separated: `author` (v0.3 frontmatter, unchanged), `approver` (new
  optional `approvers: [...]` frontmatter), `signer` (new package-level,
  per-package signature envelope).
- **`SignatureEnvelope`** + **`SignerManifest`** frozen dataclasses
  (`src/aphelion/signer.py`). Package signatures are detached, append-only,
  written to `signatures.jsonl` at archive root, lex-sorted by
  `(signer_id, signed_at_iso)` for byte-deterministic round-trip.
- **Algorithm registry**: `hmac-sha256` (TEST-ONLY reference; emits a
  warning when verified unless `--allow-test-algorithms`) and `ed25519`
  (RFC 8032; real impl available under `aphelion[signer]` extra requiring
  `cryptography >= 42`; algorithm-agnostic core ships in stdlib).
- **`src/aphelion/sig_pack.py`** — `write_signatures_jsonl` /
  `read_signatures_jsonl` / `is_sorted_correctly`. Pure, deterministic,
  spec §2.4 line-ordering enforced; mismatch raises
  `E_SIGNATURE_ORDER` / `E_SIGNATURE_MALFORMED`.
- **`src/aphelion/trust.py`** — `resolve_notary` /
  `attestation_is_acceptable` extension-point stubs per spec §4. v0.5
  performs zero notary I/O; every lookup yields `verified-locally`.
  Normative resolver protocol reserved for v0.6+.
- **Verifier integration** (`src/aphelion/verifier.py`):
  `verify_package(tar_path, *, require_signed=False, require_notary=False)
  -> VerifyResult`. Spec §5 verification chain runs whenever
  `signatures.jsonl` is present in the archive, regardless of
  `require_signed` (presence opts the package into §5). `require_signed`
  controls whether ABSENCE is an error; `require_notary` controls whether
  `verified-locally` is acceptable.
- **CLI**: new `aphe sign --package … --signer-id … --algorithm
  {hmac-sha256,ed25519} --key-file … --out …` subcommand, plus
  `--require-signed` / `--require-notary` flags on `aphe verify`. Existing
  CLI subcommands unchanged.
- **`src/aphelion/unpacker.py`** — additive read-only accessors
  `extract_signatures_jsonl(tar_path) -> bytes | None` and
  `extract_signer_manifests(tar_path) -> Mapping[str, bytes]`.
- **`src/aphelion/validator.py`** — `validate_signatures(tar_path)
  -> tuple[SignatureEnvelope, ...]`, full §5 rule sequence: parse, order
  check, manifest lookup, fingerprint recompute, canonical-hash recompute,
  algorithm registry, signature verify.
- Optional dependency: `aphelion[signer] = ["cryptography>=42"]`.
- Spec error codes (§6): `E_SIGNATURE_MALFORMED`, `E_SIGNATURE_HASH_MISMATCH`,
  `E_SIGNATURE_INVALID`, `E_SIGNATURE_ORDER`, `E_SIGNER_MISSING`,
  `E_SIGNER_MALFORMED`, `E_SIGNER_FINGERPRINT_MISMATCH`,
  `E_SIGNER_ALGORITHM_UNKNOWN`, `E_SIGNER_ALGORITHM_UNAVAILABLE`,
  `E_SIGNER_REQUIRED`, `E_SIGNER_NOTARY_REQUIRED`. Documented in
  `spec/error-codes.md`.

### Tests

- 412 tests GREEN (was 305 in v0.4.0). +107 in v0.5: 57 in `test_signer.py`,
  19 in `test_sig_pack.py`, 9 in `test_trust.py`, 22 in
  `test_verifier_signed.py`. Coverage: signer.py / sig_pack.py / trust.py
  100%; validator.py 96%; verifier.py 97%; unpacker.py 97%; cli.py 85%.

### Compatibility

- v0.5 is **strictly additive**. Existing v0.4 packages verify with
  identical behavior. v0.5 reader on an unsigned v0.4 package returns
  `VerifyResult(envelopes=(), attestations=())` and exits 0. No v0.4 →
  v0.5 migration is required.

## [0.4.0] — 2026-04-24

### Breaking (wire seal)

- `manifest.format_version` is now `"2.0"` only. v0.3 packages
  (`"1.0"` / `"1.1"`) are rejected with `PX_E_3003`
  (`ERR-SYN-VERSION-UNKNOWN-MAJOR`) in both `--strict` and `--lenient`.
  Migrate legacy packages via `aphe migrate` (see below).
- `manifest.dpkg_spec_version` renamed to `aphelion_spec_version`
  (top-level, optional, semver). The nested
  `extensions.dpkg_spec_version` that v0.3 `init_skeleton` wrote is
  also gone; v0.4 `init` emits the top-level field directly.
- `SUPPORTED_SPEC_VERSIONS` in `aphelion.initializer` narrows to
  `{"0.4.0"}`. Asking `init` for `"0.2.x"` / `"0.3.0"` now raises
  `UNSUPPORTED_SPEC_VERSION`; those packages belong to v0.3 and are
  fed through `aphe migrate` instead.

### Added

- `aphelion.migrate` — one-shot v0.3 → v0.4 transform plus directory
  and `.aphelion.tar` wrappers. Pure data transform (no IO) is exposed
  as `migrate_v03_to_v04(manifest) -> manifest`; wrappers
  `migrate_directory(src, dst)` and `migrate_archive(src, dst)` copy
  every non-manifest byte verbatim and rewrite only `manifest.json`.
- `aphe migrate <src> <dst> [--force]` CLI subcommand. Refuses to
  overwrite an existing destination unless `--force`.
- `schemas/aphelion-v0.4.json` — new aggregate `$ref` bundle under the
  `https://aphelion.spec/schemas/` namespace. Replaces the
  `https://dpkg.spec/...` URL that v0.3 artifacts used.
- `schemas/diff-v0.4.json` + `schemas/expected-normalized-v0.4.json` —
  v0.4-namespaced companions for the diff and sample contracts.
- `spec/migration-v0.3-to-v0.4.md` — normative one-shot migration
  contract and pre/post conditions.
- `tests/test_migrate.py` — 23 tests covering the transform,
  directory + archive wrappers (incl. size budgets, directory
  pass-through, atomic write, force overwrite), and the `aphe
  migrate` CLI path.
- Fixture `invalid-syntax/schema-version-legacy` — locks the expected
  `PX_E_3003` rejection of a `format_version: "1.1"` manifest under
  v0.4.

### Changed

- `SCHEMA_VERSION_MAX` `1.1 → 2.0`; `SPEC_VERSION` `0.3.0 → 0.4.0`;
  package `__version__` `0.3.0 → 0.4.0`.
- `schemas/manifest.schema.json`: `$id` migrated to
  `https://aphelion.spec/...`, title `"DPKG Manifest"` →
  `"Aphelion Manifest"`, `format_version` enum narrowed to
  `["2.0"]`, top-level property `dpkg_spec_version` removed in favour
  of `aphelion_spec_version`.
- `init_skeleton` now stamps `format_version: "2.0"` +
  `aphelion_spec_version: "0.4.0"` (was `1.1` / extensions nested).
- `aphelion.content_hash.EXCLUDED_KEYS`: `dpkg_spec_version` removed,
  `aphelion_spec_version` added. Reserved-prefix exclusion unchanged.
- `aphelion.diff` emits `diff_spec_version: "0.4.0"` and points at the
  new `schemas/diff-v0.4.json` artifact.
- `scripts/external_reader.py` accepts `format_version: "2.0"` only.
- Eight canonical samples regenerated against the v0.4 wire
  (`aphelion_spec_version` + `format_version: "2.0"` in every
  `manifest.json`, `expected-normalized.json` pinned to
  `expected_normalized_version: "0.4"`).

### Preserved deliberately

- `schemas/dpkg-v0.3.json` / `schemas/diff-v0.3.json` /
  `schemas/expected-normalized-v0.3.json` stay verbatim as historical
  wire artifacts referenced by v0.3 tags.
- `PX_E_*` error-code prefix — remains the Parallax-ecosystem
  taxonomy, unchanged across the v0.3 → v0.4 break.
- v0.2.x / v0.3.0 `CHANGELOG` entries stay historical (references to
  `dpkg_spec_version` in those entries describe what was true at the
  time of shipping and are not rewritten).

## [0.3.0] — 2026-04-23

### Renamed

- Package renamed from `dpkg` to `aphelion`; CLI command changed to `aphe`
  (shorter type for frequent invocation). Wire format field
  `dpkg_spec_version`, schema artifact filenames (`schemas/dpkg-v0.3.json`,
  `schemas/diff-v0.3.json`, `schemas/expected-normalized-v0.3.json`), and
  error-code prefix `PX_E_*` are preserved verbatim: those are v0.3
  wire/ecosystem contracts and will be re-spec'd in v0.4 when the format
  itself advances. Archive extension changed `.dpkg.tar` → `.aphelion.tar`.

### Added

- `format_version` 1.1 — the wire-schema bump accepted alongside 1.0.
  `manifest.schema.json` `format_version` is now `enum: ["1.0", "1.1"]`;
  the validator accepts both, packers emit 1.1 for new skeletons.
- `aphelion.lifecycle` — state-machine enforcement module (pure stdlib).
  Walks provenance per `claim_id` in canonical `(occurred_at_ms,
  event_id_lex)` order, raising `PX_E_5101`
  (`ERR-SEM-LIFECYCLE-ILLEGAL`) on illegal transitions and
  `PX_E_5102` (`REAFFIRM_MISSING_TARGET`) when a `reaffirm` lacks
  `target_claim_instance_id`. Wired into `validate_package` as the
  third pass so every validate call enforces semantic lifecycle.
- `target_claim_instance_id` enforcement (spec §5.5) —
  `aphelion.lifecycle` rejects `create` / `publish` that carry the field
  (→ `PX_E_5101`, neither has a prior instance to point at) and
  `reaffirm` / `revise` / `supersede` / `withdraw` that omit it
  (→ `PX_E_5102` for `reaffirm`, `PX_E_5101` for the other three).
  `aphelion.validator` additionally pattern-checks the field against
  UUID-v7 (`PX_E_4001`) at the schema layer.
- `aphelion diff <a> <b>` command + `aphelion.diff` module — layered diff
  (manifest / claim-set / per-claim evidence / provenance timeline).
  `--json` emits a structured payload validated against
  `schemas/diff-v0.3.json` (`diff_spec_version: "0.3.0"`); the
  human-text form carries the mandatory
  `"NOTE: Human-readable diff is informational only; the JSON form
  (--json) is the machine contract"` banner. Exit 0 iff the diff is
  empty.
- `aphelion validate --strict` / `--lenient` mutually-exclusive modes
  (default strict).
- `schemas/dpkg-v0.3.json` — aggregate JSON Schema that `$ref`s
  manifest / claim-frontmatter / provenance-event, giving an external
  consumer a single document to point a JSON Schema validator at.
- `schemas/diff-v0.3.json` — JSON Schema for the diff output shape.
- `schemas/expected-normalized-v0.3.json` — schema for the
  `expected-normalized.json` fixture companion format.
- `scripts/external_reader.py` — stdlib-only reference reader
  (~160 LOC) that classifies every sample under `samples/` without
  importing `aphelion` / `parallax` / `memory`. Proves the wire format
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
  pass-through in Aphelion. Excluded from content-hash computation.
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
  `PACKAGE_SINGLE_FILE_BYTES_LIMIT` exported by `aphelion.unpacker`.
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
- `aphelion.output.Writer` + `detect_color`: bound output policy (`json_mode`,
  `color`, stdout) threaded through every subcommand. Color is auto-off for
  non-tty streams and when `NO_COLOR` is set (per https://no-color.org).
- `aphelion --json`: global flag that switches success output on stdout to a
  single JSON line `{"ok": true, "command": ..., "summary": ..., ...}`
  suitable for shell pipelines. Errors stay as JSON lines on stderr whether
  or not `--json` is passed, preserving the v0.2.1 error contract.
- `aphelion --no-color`: force plain text even when stdout is a tty.
- `aphelion --version` dual display: now reports package + spec + schema
  (`aphelion 0.2.2 (spec 0.2.2, schema 1.0)`) so users never have to guess
  which number their validator cares about. Closes Top-5 risk #5.
- `SPEC_VERSION` constant in `aphelion.__init__` (tracked independently from
  `__version__` so a maintenance release can ship without bumping the
  on-disk format).
- `tests/test_cli_output.py`: 15 tests covering --json structure, ANSI
  stripping in non-tty / `NO_COLOR` / `--no-color`, Writer unit behavior,
  `--version` dual display, and a full 5-step JSON-mode pipeline smoke.
- README quickstart rewritten as a copy-pastable 5-minute walkthrough with
  expected output for every command.

### Changed

- `aphelion.initializer.SUPPORTED_SPEC_VERSIONS` accepts `0.2.2` in addition to
  `0.2.0` / `0.2.1`.
- `src/aphelion/cli.py` refactored to use `Writer` for success output; error
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

- `aphelion.error_codes`: canonical `ErrorCode` registry using the
  `PX_E_<CCNN>` scheme across six category bands (1NN TYPE, 2NN STRUCTURE,
  3NN VERSION, 4NN FORMAT, 5NN CONSISTENCY, 6NN SECURITY) plus a 9NN GENERIC
  fallback. Single source of truth for every machine-readable error code
  emitted by the package. See `spec/error-codes.md`.
- `aphelion.initializer` + `aphelion init` CLI subcommand: creates an Aphelion skeleton
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
- `aphelion.validator`: 99%, `aphelion.verifier`: 96%, `aphelion.initializer`: 98%,
  `aphelion.error_codes`: 98%, package total: 93%.

## [0.2.0] — 2026-04-21

### Added

- `aphelion.canonical_json`: deterministic JSON serializer (NFC at insert time,
  duplicate-key rejection, NaN/Infinity rejection, float rejection). Reproduces
  the spec worked example (`{"a":"café","b":2}\n`) to SHA-256
  `d2995dc401d3e4b85320775178dbf4cff5393f8ba3b6f63c489ea7acde97f682`.
- `aphelion.canonical_tar`: deterministic uncompressed POSIX ustar writer with
  fixed mtime/uid/gid/uname/gname, NFC-sorted member order, and rejection of
  symlink/hardlink/device/fifo members.
- `aphelion.errors`: exception hierarchy (`DpkgError`, `SchemaError`,
  `SecurityError`, `SemanticError`, `VerificationError`) with
  machine-readable codes and single-line JSON emission to stderr.
- `aphelion.validator`: hand-coded strict-subset validator for `manifest.json`
  and `provenance.jsonl` events (no `jsonschema` dependency).
- `aphelion.packer`: deterministic source-dir → `.aphelion.tar` packing with hash
  recomputation and re-canonicalization.
- `aphelion.unpacker`: safe streaming extract with budgets for file count,
  total bytes, per-file bytes, compression ratio, and path length. Rejects
  path traversal, absolute paths, Windows drive paths, backslashes,
  symlinks, hardlinks, devices, and fifos.
- `aphelion.verifier`: four-check semantic verification (hash, fileset, chain,
  refs).
- `aphelion.cli`: `argparse`-based CLI exposing `validate`, `pack`, `unpack`,
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
