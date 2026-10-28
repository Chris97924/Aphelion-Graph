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
| PX_E_4011  | DUPLICATE_CLAIM_INSTANCE_ID | Two manifest entries, or two instance-emitting events, share a `claim_instance_id` (ERR-SEM-005, identity I-2). |
| PX_E_4012  | DUPLICATE_EVENT_ID    | Two provenance events share an `event_id` (ERR-SEM-006, identity I-3). |

## 5NN — CONSISTENCY

| Code       | Name                 | Condition                                                  |
|------------|----------------------|------------------------------------------------------------|
| PX_E_5001  | HASH_MISMATCH        | Manifest hash != actual claim-file bytes.                  |
| PX_E_5002  | FILESET_DIVERGENCE   | Archive file set != manifest.claims paths, or a claim's path is not `claims/<claim_id>.md` (two claims sharing one file). |
| PX_E_5003  | CHAIN_BROKEN         | Provenance chain broken/forked/multi-create for a claim.   |
| PX_E_5004  | DANGLING_REFERENCE   | Event references `claim_id` not in manifest, or a `claim_instance_id` the claim's provenance never established (a `target_claim_instance_id` that is not the instance in force, or a manifest entry's instance). |
| PX_E_5005  | MANIFEST_STATE_MISMATCH | Manifest terminal state disagrees with the claim's last provenance event (ERR-SEM-013). |

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
| PX_E_6008  | DISALLOWED_MEMBER_TYPE      | Symlink / hardlink / device / fifo / sparse member rejected, or a member after a pax header with a `GNU.sparse.*` key that `tarfile` can parse (any pax header before it: local or global, the first or a later one). The type is read from the member's own header: a regular-file header in the old form (typeflag NUL) whose name field ends in `/` is a directory when no pax or GNU long-name or long-link header comes before it and its size field is 0; it is rejected when one does, as Python releases read it as different types, and when its size field is not 0, as `tar` programs read it as a directory with or without that many bytes of data after it. A negative size (`PX_E_6010`) and then a pax header that a Python release stops reading the archive at (`tarfile.ReadError`) come first, then reading past the header allowance (`PX_E_6013`), then a pax header that releases only read differently (`tarfile.ReadError`), then this rejection. A value `tarfile` cannot parse makes it fail, which every reader reports as `tarfile.ReadError` (`PX_E_9001` at the command line), as it does on every Python release a pax header that releases read differently. Releases stop at one with a record that is not whole, and at one whose first `<digits> hdrcharset=<value>` line, found anywhere in its data, has a value that is not UTF-8. They only read differently one in which that line names `BINARY` and the header's first `hdrcharset` record does not, or the other way round; a global pax header with a `hdrcharset` record or line, so an archive whose global pax header carries one is refused, as is one whose global pax values are not UTF-8 (its writer then adds a global `hdrcharset`); and, for GNU sparse 0.0, an `offset` or `numbytes` value `int()` cannot read. Whether an archive is refused is the same on every supported Python release; the code can differ where a pax header that a release stops at is followed later in the same header blocks by a negative size (`tarfile.ReadError` on some releases, `PX_E_6010` on others), and on Python 3.10.0 to 3.10.6, where a GNU sparse 0.0 value of more than 4,300 digits is refused as sparse (this code). |
| PX_E_6009  | FILE_COUNT_EXCEEDED         | Archive exceeds `max_files` budget.                   |
| PX_E_6010  | FILE_BYTES_EXCEEDED         | Member declares size > `max_file_bytes`; or a negative size, in a member's header, in a pax or GNU long-name header before it or in a pax record, on every Python release (where a pax header that a release stops at comes before it in the same header blocks, some releases report `tarfile.ReadError` instead: see `PX_E_6008`); or a member after a pax header with a `size` key (any pax header before it: local or global, the first or a later one). A directory member's size, if not negative, is ignored; a negative size is refused for every member type. |
| PX_E_6011  | TOTAL_BYTES_EXCEEDED        | Aggregate size > `max_total_bytes`.                   |
| PX_E_6012  | COMPRESSION_RATIO_EXCEEDED  | Uncompressed bytes / archive size > ratio budget. Member data only: header bytes are bounded by the per-member allowance (`PX_E_6013`). |
| PX_E_6013  | ARCHIVE_BOMB                | Stream overran a budget mid-extraction; or reading the archive would go past what its checked member headers allow: a member's header blocks may take H bytes past the end of the member before it (4,096 at the default policy; more for a larger `max_path_length`, room for a pax header holding a path of that many four-byte UTF-8 characters and about 1 KiB of other records), the first member's 1,024 more for global pax headers in front of it, so a member with larger header records, such as an extended attribute of about 3 KB or more at the default policy, is refused (as `max_path_length` counts characters after NFC normalisation, a name stored decomposed, such as NFD, can need more than four bytes per counted character, and a member whose header blocks then take more than H is refused too); or it reads past the archive's end more than 8 times; or a member's header blocks do not lead, size by size, from where the member before it ends to its own header; or `tarfile` reports a member with another type or size than its own header gives; or the archive changed between `unpack`'s two passes; or decompressing an xz or LZMA-alone archive needs more decoder memory than the limit. |

## 9NN — GENERIC

| Code       | Name    | Condition                                      |
|------------|---------|------------------------------------------------|
| PX_E_9001  | UNKNOWN | Uncategorised failure (last-resort fallback).  |

---

## v0.5 — Signer / Trust error codes

These codes are emitted by `signer.SignerVerificationError` (not `ErrorCode` enum) and
are used by the v0.5 signature verification path in `validator.validate_signatures()` and
`verifier.verify_package()`, and by `aphe verify`, which reports them. The second
`E_SIGNER_REQUIRED` row is `aphe verify`'s alone. See `spec/v0.5-signer-trust.md §6` for
normative detail.

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
| `E_SIGNER_REQUIRED`            | A package file without signatures, given to `verify_package(require_signed=True)` or `verify_package(require_notary=True)` (which implies it), or to `aphe verify --require-signed` or `--require-notary`. |
| `E_SIGNER_REQUIRED`            | `aphe verify --require-signed` or `--require-notary` on a target that is not a file (a directory, such as an unpacked package, or a path that does not exist), on which no signature can be checked. `verify_package` itself raises the operating system's error for such a path. A regular file is always verified as a package file, so one that is not a package fails with the archive or package error instead (`PX_E_9001` for a file that is not a tar archive). |
| `E_SIGNER_NOTARY_REQUIRED`     | Caller passed `--require-notary` for a signed package file, and a signer's attestation is `"verified-locally"` only. |
| `E_SIGNER_ALGORITHM_UNAVAILABLE`| `cryptography` extra is not installed; `ed25519` cannot be used.                        |

## v0.6 — Notary attestation error codes (R7.2)

Emitted by `trust.SignerVerificationError` from
`trust.resolve_notary_attestation()`. See
`spec/v0.6-notary-attestation.md §4` for normative detail. The notary
attestation path also reuses `E_SIGNATURE_INVALID`, `E_SIGNER_ALGORITHM_UNKNOWN`,
`E_SIGNER_ALGORITHM_MISMATCH`, and `E_SIGNER_FINGERPRINT_MISMATCH` from v0.5
with their existing meanings.

| Code                       | Condition                                                                                                  |
|----------------------------|------------------------------------------------------------------------------------------------------------|
| `E_SIGNER_NOTARY_INVALID`  | A notary attestation envelope is structurally present but fails an identity/fingerprint binding check (signer_id, key_fingerprint, or notary_id mismatch). |
