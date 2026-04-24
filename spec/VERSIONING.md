# Aphelion Versioning Policy

**Version:** 0.4.0
**Status:** Normative
**Date:** 2026-04-24

## 1. Two independent version axes

Aphelion maintains two independent semver strings:

| Field | Location | What it tracks |
|---|---|---|
| `format_version` | `manifest.json` (required) | Wire-shape MAJOR.MINOR of the Aphelion on-tar layout. Pinned set of valid values per release line. |
| `aphelion_spec_version` | `manifest.json` (optional) | Human-facing Aphelion spec release label (e.g. `"0.3.0"`). |
| `exchange_profile_version` | `manifest.json` (optional) | Version of a specific adapter's exchange profile (e.g. Parallax mapping). Opaque to Aphelion validator. |

Rationale (from xcouncil 2026-04-21 Codex observation): adapter mapping
changes should not bump the Aphelion core. Separating the two axes lets
Parallax evolve `exchange_profile_version` without forcing an Aphelion spec
bump, and vice versa.

## 2. What counts as a semver change

### MAJOR (breaking)
- Removing a required field from any schema.
- Renaming a field in the canonical projection for `content_hash`.
- Changing canonical JSON whitespace, key ordering, or NFC rules.
- Changing the tar format (e.g. pax → ustar).
- Changing the hash algorithm.
- Any change that makes a previously-valid v$N$ package fail validation
  under v$N+1$ without `--lenient`.

### MINOR (additive, backwards-compatible)
- Adding a new optional field to manifest or frontmatter.
- Adding a new error code.
- Adding a new sample or test vector.
- Documenting previously-undefined behavior, provided the documented
  behavior matches existing implementations.

### PATCH (editorial)
- Typo fixes in any spec document.
- Clarifying wording that does not change normative requirements.
- Dependency-free test / tooling bug fixes.

## 3. `format_version` handling by the validator

- **Known MAJOR.MINOR** (currently `2.0` only): accept.
- **Known MAJOR, unknown MINOR** (e.g. `2.99`): emit a warning to
  stderr naming the unknown minor, continue validation in additive
  mode (unknown optional fields tolerated in `--lenient`, rejected in
  `--strict`).
- **Unknown MAJOR** (e.g. `3.0`, `1.x`): reject with
  `ERR-SYN-VERSION-UNKNOWN-MAJOR`, exit non-zero in any mode. v0.3
  packages (`format_version` 1.0 / 1.1) are rejected for the same
  reason; migrate them via `aphe migrate` (see
  `spec/migration-v0.3-to-v0.4.md`).

## 4. `aphelion_spec_version` and `exchange_profile_version`

Both fields are optional in `manifest.json`:

- If absent, the validator treats the package as conforming to the
  highest-known spec line matched by `format_version` alone.
- If present, the value MUST be a valid semver string (`X.Y.Z`).
  Anything else → `ERR-SYN-VERSION-NOT-SEMVER`.
- The validator does not use `exchange_profile_version` for any check;
  it is passed through unchanged and available to adapter code.

## 5. Three worked examples

1. **v0.4 wire seal: rename `dpkg_spec_version` → `aphelion_spec_version`
   and bump `format_version` 1.1 → 2.0.** This is MAJOR. v0.3 packages
   cannot be validated under v0.4 without the migration tool (`aphe
   migrate`). Rationale: the pre-rename field name leaked the legacy
   "DPKG" brand into the wire contract; v0.3 deliberately preserved it
   so v0.3 validators could keep reading older packages, and v0.4 is
   where the break lands. See `spec/migration-v0.3-to-v0.4.md`.
2. **Changing `canonical-serialization.md` Rule 1 whitespace from no
   spaces to single spaces after commas.** This is MAJOR. Every
   pre-existing package would produce different canonical bytes and
   fail hash verification. Bump `format_version` 2.x → 3.0 and
   `aphelion_spec_version` 0.y.z → 1.0.0.
3. **Fixing the typo "symantic" → "semantic" in `error-codes.md`.**
   This is PATCH. No schema or wire change. Bump only the patch digit
   in the release channel (`0.3.0` → `0.3.1`).

## 6. Release checklist

When bumping `aphelion_spec_version`:

- [ ] `pyproject.toml` version updated to match the semver tag.
- [ ] `CHANGELOG.md` has a section for the new version listing what
      changed.
- [ ] `manifest.schema.json` `format_version` enum includes the new
      minor if the wire shape changed.
- [ ] `tests/vectors/hash_vectors.json` re-checked to verify canonical
      form unchanged (MAJOR gate).
- [ ] Samples regenerated if schema fields changed.
