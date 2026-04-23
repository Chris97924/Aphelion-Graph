# DPKG Validator Spec

**Version:** 1.0
**Status:** Normative
**Date:** 2026-04-21

> **v0.2.1 — Error code migration.** The `ERR-SYN-*` / `ERR-SCH-*` / `ERR-SEM-*`
> codes below are the original *conceptual* namespace. The machine-readable
> codes emitted at runtime now use the `PX_E_<CCNN>` scheme defined in
> [`error-codes.md`](error-codes.md) — that file is the single source of
> truth. This document is retained for the layer-ordering contract; the
> concrete code strings in the tables are being migrated.

A DPKG validator runs in three ordered layers. Each layer has a machine-readable error-code namespace. Validators MUST halt on the first `ERROR` in a layer before proceeding to the next (fail-fast per layer).

## Layers

| Layer | Namespace | Scope |
|---|---|---|
| 1. Syntax | `ERR-SYN-*` | Bytes, encoding, line endings, JSON/YAML/tar parseability. |
| 2. Schema | `ERR-SCH-*` | Field presence, types, enum values, format patterns. |
| 3. Semantic | `ERR-SEM-*` | Cross-file consistency, state-machine legality, hashes. |

### Layer 1 — Syntax

Operates on raw bytes. Uses canonical-serialization rules.

### Layer 2 — Schema

Runs against JSON Schema draft 2020-12 for each structured file:
- `schemas/manifest.schema.json`
- `schemas/claim-frontmatter.schema.json`
- `schemas/provenance-event.schema.json`

### Layer 3 — Semantic

Cross-references: event → claim, hash → body bytes, state-machine legality, mirror conflicts.

---

## Severity Levels

| Severity | Meaning | Layer behavior |
|---|---|---|
| `ERROR` | Package is non-conformant. Consumer MUST reject. | Halts the current layer. |
| `WARN` | Discouraged but legal. | Reported; layer continues. |
| `INFO` | Observational. | Reported; layer continues. |

---

## Migration Map: legacy → `PX_E_<CCNN>` (v0.2.1+)

The tables below retain the original `ERR-*` code strings for reference. At
runtime the implementation emits the `PX_E_<CCNN>` codes defined in
[`error-codes.md`](error-codes.md). Use this table when porting old tooling:

| Legacy code | Current `PX_E_*` | Registry name |
|---|---|---|
| `ERR-SYN-001` | `PX_E_4010` | `UTF8_INVALID` |
| `ERR-SYN-002` | (v0.3.0 — canonical NFC check, not yet emitted) | — |
| `ERR-SYN-008` | `PX_E_4006` | `PARSE_ERROR` |
| `ERR-SYN-009` | (implicit — canonical writer sorts; never emitted) | — |
| `ERR-SYN-010` | `PX_E_4009` | `NAN_FORBIDDEN` |
| `ERR-SCH-001` | `PX_E_2001` | `REQUIRED_FIELD_MISSING` |
| `ERR-SCH-002` | `PX_E_1001` | `TYPE_MISMATCH` |
| `ERR-SCH-003` | `PX_E_4002` | `ENUM_INVALID` |
| `ERR-SCH-004` | `PX_E_4001` | `PATTERN_MISMATCH` |
| `ERR-SCH-007` | `PX_E_2002` | `EXTRA_FIELD` |
| `ERR-SCH-008` | `PX_E_3001` | `UNSUPPORTED_SCHEMA_VERSION` |
| `ERR-SEM-001` | `PX_E_5001` | `HASH_MISMATCH` |
| `ERR-SEM-002` / `003` | `PX_E_5002` | `FILESET_DIVERGENCE` |
| `ERR-SEM-004` | `PX_E_4004` | `DUPLICATE_CLAIM_ID` |
| `ERR-SEM-007` | `PX_E_5004` | `DANGLING_REFERENCE` |
| `ERR-SEM-009` / `010` / `011` / `012` | `PX_E_5003` | `CHAIN_BROKEN` |
| `ERR-SEM-014` | `PX_E_2004` | `FORBIDDEN_FIELD` |
| `ERR-SEM-015` | `PX_E_2001` | `REQUIRED_FIELD_MISSING` |
| `ERR-SEC-*` (archive safety) | `PX_E_6001..6013` | see `error-codes.md` §6NN |

Entries marked *(v0.3.0)* or *(implicit)* are cases the current validator
either does not yet check or guarantees structurally so no runtime code is
emitted. The tables below are retained as the conceptual contract.

## Error Code Table (machine-readable)

| Code | Severity | Layer | Message Template |
|---|---|---|---|
| `ERR-SYN-001` | ERROR | Syntax | Invalid UTF-8 byte sequence at offset {offset} in {file} |
| `ERR-SYN-002` | ERROR | Syntax | Text not NFC-normalized in {file} |
| `ERR-SYN-003` | ERROR | Syntax | Unpaired surrogate in {file} |
| `ERR-SYN-004` | ERROR | Syntax | CRLF line ending in {file} at line {line} |
| `ERR-SYN-005` | ERROR | Syntax | Trailing whitespace in {file} at line {line} |
| `ERR-SYN-006` | ERROR | Syntax | Missing terminal LF in {file} |
| `ERR-SYN-007` | ERROR | Syntax | Extra trailing LF (empty last line) in {file} |
| `ERR-SYN-008` | ERROR | Syntax | JSON parse error in {file}: {parser_message} |
| `ERR-SYN-009` | ERROR | Syntax | JSON keys not sorted in {file} at path {json_pointer} |
| `ERR-SYN-010` | ERROR | Syntax | JSON contains forbidden value (NaN/Infinity) in {file} |
| `ERR-SYN-011` | ERROR | Syntax | YAML parse error in {file}: {parser_message} |
| `ERR-SYN-012` | ERROR | Syntax | YAML uses forbidden construct (flow mapping/comment/anchor/tag) in {file} |
| `ERR-SYN-013` | ERROR | Syntax | tar entry order violation at entry {n} ({path}) |
| `ERR-SYN-014` | ERROR | Syntax | tar entry mtime ≠ 0 at {path} |
| `ERR-SYN-015` | ERROR | Syntax | tar entry uid/gid ≠ 0 at {path} |
| `ERR-SYN-016` | ERROR | Syntax | tar entry mode not in {0644, 0755} at {path} |
| `ERR-SYN-017` | ERROR | Syntax | tar missing EOF zero blocks |
| `ERR-SYN-018` | ERROR | Syntax | Timestamp not UTC-Z form in {file} at path {pointer} |
| `ERR-SYN-019` | WARN  | Syntax | Pax extended header used where ustar would suffice at {path} |
| `ERR-SYN-020` | INFO  | Syntax | File size > 1 MiB in {path} (reproducibility still valid) |
| `ERR-SCH-001` | ERROR | Schema | Missing required field {field} in {file} |
| `ERR-SCH-002` | ERROR | Schema | Type mismatch at {json_pointer}: expected {expected}, got {actual} |
| `ERR-SCH-003` | ERROR | Schema | Value not in enum at {json_pointer}: {value} not in {allowed} |
| `ERR-SCH-004` | ERROR | Schema | Pattern mismatch at {json_pointer}: {value} does not match {pattern} |
| `ERR-SCH-005` | ERROR | Schema | Unknown format-namespace field {field} in {file} |
| `ERR-SCH-006` | WARN  | Schema | Application-defined field shadows reserved name at {pointer} |
| `ERR-SCH-007` | ERROR | Schema | Additional property forbidden at {pointer}: {field} |
| `ERR-SCH-008` | ERROR | Schema | `format_version` unsupported: {value} |
| `ERR-SCH-009` | ERROR | Schema | `license` not a valid SPDX identifier: {value} |
| `ERR-SCH-010` | INFO  | Schema | Optional field {field} omitted in {file} |
| `ERR-SEM-001` | ERROR | Semantic | claim hash mismatch at {path}: expected {expected}, got {actual} |
| `ERR-SEM-002` | ERROR | Semantic | manifest references missing claim file at {path} |
| `ERR-SEM-003` | ERROR | Semantic | claim file not referenced by manifest: {path} |
| `ERR-SEM-004` | ERROR | Semantic | duplicate `claim_id` in manifest: {id} |
| `ERR-SEM-005` | ERROR | Semantic | duplicate `claim_instance_id` in manifest: {id} |
| `ERR-SEM-006` | ERROR | Semantic | duplicate `event_id` in provenance.jsonl: {id} |
| `ERR-SEM-007` | ERROR | Semantic | provenance event references unknown `claim_id`: {id} |
| `ERR-SEM-008` | ERROR | Semantic | provenance events not in monotonic UUID-v7 timestamp order at line {line} |
| `ERR-SEM-009` | ERROR | Semantic | supersede event missing `superseded_by_claim_id` at line {line} |
| `ERR-SEM-010` | ERROR | Semantic | illegal state transition at line {line}: from {from} via {event} |
| `ERR-SEM-011` | ERROR | Semantic | supersede target claim_id does not exist: {id} |
| `ERR-SEM-012` | ERROR | Semantic | supersede chain contains a cycle involving {id} |
| `ERR-SEM-013` | ERROR | Semantic | manifest terminal state disagrees with provenance last event for {claim_id} |
| `ERR-SEM-014` | ERROR | Semantic | `claim_instance_id` on reaffirm/withdraw event (MUST be absent) at line {line} |
| `ERR-SEM-015` | ERROR | Semantic | `claim_instance_id` missing on create/revise/supersede event at line {line} |
| `ERR-SEM-016` | ERROR | Semantic | `created_at` later than `updated_at` in claim {claim_id} |
| `ERR-SEM-017` | ERROR | Semantic | package.dpkg.tar.gz sha256 mismatch: expected {expected}, got {actual} |
| `ERR-SEM-018` | ERROR | Semantic | signature invalid for declared `public_key` |
| `ERR-SEM-019` | WARN  | Semantic | package contains withdrawn claim with no `withdrawn_reason`: {claim_id} |
| `ERR-SEM-020` | ERROR | Semantic | manifest/frontmatter mirror conflict at field {field} for {claim_id} |

---

## Machine-Readable Output Shape

Validators MUST be able to emit a JSON report in this shape:

```json
{
  "package_path": "…/foo.dpkg.tar.gz",
  "format_version": "1.0",
  "layer_results": [
    {"layer": "syntax",   "passed": true,  "findings": []},
    {"layer": "schema",   "passed": false, "findings": [
      {"code": "ERR-SCH-001", "severity": "ERROR", "message": "Missing required field claim_id in manifest.json", "location": {"file": "manifest.json", "pointer": "/claims/0"}}
    ]},
    {"layer": "semantic", "passed": null,  "findings": []}
  ],
  "overall": "fail"
}
```

`overall` is `"pass"` iff every layer's `passed` is `true` (no `ERROR` in any layer). `WARN` and `INFO` findings do NOT fail a package.
