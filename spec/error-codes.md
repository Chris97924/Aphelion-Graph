# Aphelion Error Code Registry (v0.4.0 + v0.3-r1r4)

## Code-prefix conventions

The registry uses two prefix forms:

| Prefix | Meaning | Behavior |
|---|---|---|
| `PX_E_<CCNN>` | Error | Validator MUST abort processing and surface the error to the caller. The body band convention (`CC` = 1NN/2NN/.../6NN) is documented in the v0.2.1 historical legend below. |
| `PX_W_<CCNN>` | Warning (introduced v0.3-r1r4) | Validator MUST emit the signal but MUST NOT abort. Production deployments MUST surface the warning beyond logs (e.g. Prometheus counter) so silent occurrences are alertable. The first member is `PX_W_4151 / W_CLAIM_SUPERSEDES_DANGLING`. |

Both prefix forms share the same band numbering. A semantic alias (e.g. `E_CLAIM_KEY_ORDER`, `W_CLAIM_SUPERSEDES_DANGLING`) is preferred in spec prose; the `PX_*` form is preferred in validator output.

---

## v0.3-r1r4 additions (claim semantics — Chris-pinned 2026-05-09)

| PX code      | Semantic alias                              | Condition                                                                |
|--------------|---------------------------------------------|--------------------------------------------------------------------------|
| PX_E_4101    | E_CLAIM_CONFIDENCE_TYPE                     | `confidence` not numeric.                                                |
| PX_E_4102    | E_CLAIM_CONFIDENCE_RANGE                    | `confidence` outside `[0.000, 1.000]`.                                   |
| PX_E_4103    | E_CLAIM_CONFIDENCE_PRECISION                | `confidence` serialized with precision != 3dp on the wire.               |
| PX_E_4111    | E_CLAIM_VALIDTIME_TYPE                      | `valid_from` / `valid_until` not string.                                 |
| PX_E_4112    | E_CLAIM_VALIDTIME_FORMAT                    | `valid_from` / `valid_until` not exact 20-char ISO 8601 UTC `Z`.         |
| PX_E_4113    | E_CLAIM_VALIDTIME_ORDER                     | `valid_from > valid_until` when both present.                            |
| PX_E_4121    | E_CLAIM_POLARITY_TYPE                       | `polarity` not string.                                                   |
| PX_E_4122    | E_CLAIM_POLARITY_VALUE                      | `polarity` not in `{affirm, negate, unknown}`.                           |
| PX_E_4131    | E_CLAIM_SUPERSEDES_TYPE                     | `supersedes` not array<string>.                                          |
| PX_E_4132    | E_CLAIM_SUPERSEDES_SELF                     | `supersedes` includes the claim's own `claim_id`.                        |
| PX_E_4133    | E_CLAIM_SUPERSEDES_DUPLICATE                | `supersedes` array contains the same `claim_id` twice.                   |
| PX_E_4141    | E_CLAIM_RESERVED_FIELD                      | Reader-only derivation field (e.g. `conflict_class`) used in frontmatter. |
| PX_E_4143    | E_CLAIM_KEY_ORDER                           | Frontmatter keys not ASCII-codepoint ascending. Use `aphe canonicalize`. |
| PX_E_4144    | E_CLAIM_SUBJECT_REQUIRED_FOR_CONFLICT       | R4-trigger field present (`polarity` / `valid_*` / `supersedes` — see ADR-0002 §6 backward-compat note re `confidence`) without `subject`. |
| PX_W_4151    | W_CLAIM_SUPERSEDES_DANGLING                 | `supersedes` references a `claim_id` not present in loaded packages (warning, not error — D1.2 lenient resolution). MUST be exposed as Prometheus counter `aphelion_supersedes_dangling_total{package_id,target_id}` so deployments can alert on non-zero rate. |

> The `PX_W_*` prefix denotes a **warning** rather than an error — emitted to logs / observation channels but does not abort processing. v0.3 introduces this prefix for the cross-package `supersedes` lenient case. Production deployments MUST surface the warning via a Prometheus counter (NOT log-only) so silent typos are alertable.

> **Note on `PX_E_4142`**: an earlier draft of this addition included `PX_E_4142 / E_CLAIM_DUPLICATE_ID` for "two claim files in the same package share the same `claim_id`". Removed because `PX_E_4004 / DUPLICATE_CLAIM_ID` (manifest-side duplicate detection) already covers this — `claim-frontmatter.md` Rule 5 makes manifest authoritative on conflict, so manifest-side detection is sufficient and avoids registry collision.

See `spec/v0.3-claim-semantics.md` for normative semantics, `adr/0002-v0.3-claim-semantics-r1r4.md` for design rationale and xcouncil verdict trail.

---

## v0.3.0 additions (semantic aliases)

| PX code      | Semantic alias                     | Condition                                         |
|--------------|------------------------------------|---------------------------------------------------|
| PX_E_3003    | ERR-SYN-VERSION-UNKNOWN-MAJOR      | `manifest.format_version` has unknown MAJOR (incl. legacy 1.x under v0.4). |
| PX_E_3004    | ERR-SYN-VERSION-NOT-SEMVER         | `aphelion_spec_version` / `exchange_profile_version` not X.Y.Z. |
| PX_E_3005    | ERR-SYN-TIMESTAMP-NS               | Timestamp has sub-ms precision or non-`Z` offset. |
| PX_E_5101    | ERR-SEM-LIFECYCLE-ILLEGAL          | Illegal state transition per lifecycle matrix.    |
| PX_E_5102    | ERR-SEM-REAFFIRM-MISSING-TARGET    | `reaffirm` event lacks `target_claim_instance_id`. |
| PX_E_5103    | ERR-SEM-DUPLICATE-HASH-COLLISION   | Same `claim_id`, different `content_hash` across packages. |

See `spec/lifecycle-state-machine.md` and `spec/content-hash.md` for
normative detail. The semantic-alias form is preferred in spec prose;
the PX code form is preferred in validator output.

---

# Aphelion Error Code Registry (v0.2.1 — historical legend)

Every machine-readable error emitted by Aphelion carries a `code` field of the
form `PX_E_<CCNN>` where `CC` identifies one of six categories:

| Band  | Category       | Meaning                                                                 |
|-------|----------------|-------------------------------------------------------------------------|
| 1NN   | TYPE           | Wrong JSON type (e.g. `list` where `str` was required).                 |
| 2NN   | STRUCTURE      | Required/extra/empty/forbidden fields, I/O boundary issues.            |
| 3NN   | VERSION        | Format or spec version is unknown / unsupported.                       |
| 4NN   | FORMAT         | Pattern, enum, const, duplicate-value violations; JSON parse failure.  |
| 5NN   | CONSISTENCY    | Cross-reference failures (hash, fileset, chain, dangling reference).   |
| 6NN   | SECURITY       | Archive-extraction safety breach (traversal, bomb, bad member type…).   |

The canonical source of truth is [`src/aphelion/error_codes.py`][impl].
All raise sites import the `ErrorCode` enum — no string literals.

[impl]: ../src/aphelion/error_codes.py

## 1NN — TYPE

| Code       | Name            | Condition                                    |
|------------|-----------------|----------------------------------------------|
| PX_E_1001  | TYPE_MISMATCH   | Field has the wrong Python/JSON type.        |

## 2NN — STRUCTURE

| Code       | Name                       | Condition                                                              |
|------------|----------------------------|------------------------------------------------------------------------|
| PX_E_2001  | REQUIRED_FIELD_MISSING     | One or more required keys are absent.                                  |
| PX_E_2002  | EXTRA_FIELD                | An unknown / disallowed field is present.                              |
| PX_E_2003  | EMPTY_VALUE                | String field is empty where non-empty is required (license, producer). |
| PX_E_2004  | FORBIDDEN_FIELD            | Field is present where it must be absent (e.g. `create` + `prev_event_id`). |
| PX_E_2005  | MISSING_FILE               | Filesystem I/O: required input file not found.                         |
| PX_E_2006  | INIT_REFUSES_EXISTING      | `aphelion init` refuses — destination already holds a manifest.            |
| PX_E_2007  | INIT_MISSING_CONFIRMATION  | `--force` used without `--i-know-what-im-doing`.                       |

## 3NN — VERSION

| Code       | Name                        | Condition                                    |
|------------|-----------------------------|----------------------------------------------|
| PX_E_3001  | UNSUPPORTED_SCHEMA_VERSION  | `format_version` not understood by parser.   |
| PX_E_3002  | UNSUPPORTED_SPEC_VERSION    | `--spec-version` value is not in the supported set. |

## 4NN — FORMAT

| Code       | Name                  | Condition                                            |
|------------|-----------------------|------------------------------------------------------|
| PX_E_4001  | PATTERN_MISMATCH      | String fails regex (UUID v7, SHA-256, timestamp…).  |
| PX_E_4002  | ENUM_INVALID          | Value not in allowed enum (state, event_type…).     |
| PX_E_4003  | CONST_MISMATCH        | Field must equal a constant (e.g. `provenance.jsonl`). |
| PX_E_4004  | DUPLICATE_CLAIM_ID    | Two manifest entries share the same `claim_id`.      |
| PX_E_4005  | DUPLICATE_TAG         | Same tag appears twice on a claim entry.             |
| PX_E_4006  | PARSE_ERROR           | JSON parse failure.                                  |
| PX_E_4007  | DUPLICATE_JSON_KEY    | Object has repeated key (also NFC-collision).        |
| PX_E_4008  | FLOAT_FORBIDDEN       | Float value in canonical JSON.                       |
| PX_E_4009  | NAN_FORBIDDEN         | `NaN` / `Infinity` literal in canonical JSON.        |
| PX_E_4010  | UTF8_INVALID          | Input bytes are not valid UTF-8.                     |

## 5NN — CONSISTENCY

| Code       | Name                 | Condition                                                  |
|------------|----------------------|------------------------------------------------------------|
| PX_E_5001  | HASH_MISMATCH        | Manifest hash != actual claim-file bytes.                  |
| PX_E_5002  | FILESET_DIVERGENCE   | Archive file set != manifest.claims paths.                 |
| PX_E_5003  | CHAIN_BROKEN         | Provenance chain broken/forked/multi-create for a claim.   |
| PX_E_5004  | DANGLING_REFERENCE   | Event references `claim_id` not in manifest.               |

## 6NN — SECURITY

| Code       | Name                        | Condition                                             |
|------------|-----------------------------|-------------------------------------------------------|
| PX_E_6001  | PATH_TRAVERSAL              | `..` segment in member path / resolved path escapes dest. |
| PX_E_6002  | ABSOLUTE_PATH               | Member path is absolute.                              |
| PX_E_6003  | WINDOWS_DRIVE               | Member path has Windows drive prefix.                 |
| PX_E_6004  | WINDOWS_BACKSLASH           | Member path contains `\`.                             |
| PX_E_6005  | PATH_TOO_LONG               | Member path exceeds `max_path_length`.                |
| PX_E_6006  | EMPTY_MEMBER_NAME           | Member has empty name.                                |
| PX_E_6007  | DUPLICATE_MEMBER_PATH       | Two members normalise to same path.                   |
| PX_E_6008  | DISALLOWED_MEMBER_TYPE      | Symlink / hardlink / device / fifo rejected.          |
| PX_E_6009  | FILE_COUNT_EXCEEDED         | Archive exceeds `max_files` budget.                   |
| PX_E_6010  | FILE_BYTES_EXCEEDED         | Member declares size > `max_file_bytes`.              |
| PX_E_6011  | TOTAL_BYTES_EXCEEDED        | Aggregate size > `max_total_bytes`.                   |
| PX_E_6012  | COMPRESSION_RATIO_EXCEEDED  | Uncompressed bytes / archive size > ratio budget.     |
| PX_E_6013  | ARCHIVE_BOMB                | Stream overran a budget mid-extraction.               |

## 9NN — GENERIC

| Code       | Name    | Condition                                      |
|------------|---------|------------------------------------------------|
| PX_E_9001  | UNKNOWN | Uncategorised failure (last-resort fallback).  |

---

## v0.5 — Signer / Trust error codes

These codes are emitted by `signer.SignerVerificationError` (not `ErrorCode` enum) and
are used by the v0.5 signature verification path in `validator.validate_signatures()` and
`verifier.verify_package()`. See `spec/v0.5-signer-trust.md §6` for normative detail.

| Code                           | Condition                                                                                 |
|--------------------------------|-------------------------------------------------------------------------------------------|
| `E_SIGNATURE_MALFORMED`        | `signatures.jsonl` line fails §2.2 schema (non-UTF-8, missing fields, wrong types).      |
| `E_SIGNER_MISSING`             | Envelope references `signer_id` with no matching `signers/<signer_id>.json`.             |
| `E_SIGNER_MALFORMED`           | `signers/<signer_id>.json` exists but fails §2.3 schema.                                  |
| `E_SIGNER_FINGERPRINT_MISMATCH`| `key_fingerprint` in signer manifest does not recompute from `public_key_b64`.           |
| `E_SIGNATURE_HASH_MISMATCH`    | Envelope `package_canonical_hash` does not match recomputed value from current contents. |
| `E_SIGNER_ALGORITHM_UNKNOWN`   | `algorithm` field value is not in the §3.1 registry.                                     |
| `E_SIGNER_ALGORITHM_MISMATCH`  | Envelope `algorithm` does not match the signer manifest `algorithm`. Raised before verifier dispatch to close confused-deputy gap. |
| `E_SIGNATURE_INVALID`          | Signature bytes fail cryptographic verification against the public key.                   |
| `E_SIGNATURE_ORDER`            | Lines in `signatures.jsonl` violate §2.4 lex-ascending sort order.                       |
| `E_SIGNER_REQUIRED`            | Caller passed `--require-signed` but package has no `signatures.jsonl`.                  |
| `E_SIGNER_NOTARY_REQUIRED`     | Caller passed `--require-notary` but all attestations are `"verified-locally"` only.     |
| `E_SIGNER_ALGORITHM_UNAVAILABLE`| `cryptography` extra is not installed; `ed25519` cannot be used.                        |
